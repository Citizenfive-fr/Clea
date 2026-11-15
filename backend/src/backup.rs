//! Encrypted backups of the whole instance, in BACKUP_DIR.
//!
//! - Backup key: an HPKE key pair (like the recovery key). The public part is in the
//!   database, the private part is shown once to the owner. The server can make backups
//!   but cannot read them back.
//! - One backup = one file `clea-<date>-<id>.backup`, encrypted for the backup public key
//!   (HPKE: X25519 + HKDF-SHA256 + AES-256-GCM), and its fingerprint next to it in
//!   `<file>.sha256`, in the `sha256sum` format: a copy can be checked with `sha256sum -c`,
//!   without Cléa and without the key.
//! - Sessions are not backed up: after a restore, everyone logs in again.

use std::io::Write;
use std::path::Path;

use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{AssertSqlSafe, PgPool};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    error::AppError,
    keys::{self, from_hex, to_hex},
    recovery::{self, PrivateKey},
};

const DISPLAY_PREFIX: &str = "CLEA-BACKUP-KEY-";
const CHECKSUM_DOMAIN: &[u8] = b"clea/backup-checksum/v1\0";
const PUBLIC_PREFIX: &str = "b1:";
const HPKE_INFO: &[u8] = b"clea/backup/v1";
const FILE_MAGIC: &[u8] = b"CLEA-BACKUP\x01";
const PUBLIC_LEN: usize = 32;
/// File header: magic || backup id || public key used. It is bound to the content (AAD).
const HEADER_LEN: usize = 12 + 16 + PUBLIC_LEN;
const EXPORT_FORMAT: &str = "clea-export/1";
const FINGERPRINT_EXT: &str = ".sha256";

/// Tables saved, in restore order (parents first).
const TABLES: &[&str] = &[
    "organizations",
    "setup_state",
    "users",
    "invitations",
    "audit_logs",
    "news_favorites",
    "backup_settings",
];
/// Tables left out on purpose. Any other table makes the backup fail: a new migration
/// must say here whether its table is saved, so nothing is forgotten silently.
const SKIPPED: &[&str] = &["sessions", "_sqlx_migrations"];

// --- Backup key ---

/// A new backup key pair: the public part goes to the database, the secret to the owner.
pub struct NewBackupKey {
    pub public_key: String,
    pub secret_display: Zeroizing<String>,
}

pub fn generate_key() -> NewBackupKey {
    let (public_key, secret) = recovery::generate_pair();
    NewBackupKey {
        public_key: format!("{PUBLIC_PREFIX}{}", to_hex(&public_key)),
        secret_display: recovery::display_with(DISPLAY_PREFIX, CHECKSUM_DOMAIN, &secret),
    }
}

/// A backup secret typed back (wiped from memory when dropped).
pub struct BackupSecret(PrivateKey);

impl BackupSecret {
    pub fn parse(input: &str) -> Result<Self, AppError> {
        recovery::parse_displayed(input, DISPLAY_PREFIX, CHECKSUM_DOMAIN, bad_secret).map(Self)
    }

    pub fn public_key(&self) -> String {
        format!("{PUBLIC_PREFIX}{}", to_hex(&recovery::public_of(&self.0)))
    }
}

fn bad_secret(reason: &str) -> AppError {
    AppError::BadRequest(format!("Clé de sauvegarde mal recopiée ({reason})"))
}

fn public_key_bytes(public_key: &str) -> Result<Vec<u8>, String> {
    public_key
        .strip_prefix(PUBLIC_PREFIX)
        .and_then(from_hex)
        .filter(|b| b.len() == PUBLIC_LEN)
        .ok_or_else(|| "Clé publique de sauvegarde invalide".to_string())
}

// --- Backup files ---

fn encrypt_file(public_key: &str, id: Uuid, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = FILE_MAGIC.to_vec();
    out.extend_from_slice(id.as_bytes());
    out.extend_from_slice(&public_key_bytes(public_key)?);
    let sealed = recovery::seal(&out[FILE_MAGIC.len() + 16..], HPKE_INFO, &out, plaintext)
        .map_err(|_| "Chiffrement de la sauvegarde échoué".to_string())?;
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Public key a backup file was made for (`b1:` format), read from its header.
fn file_public_key(data: &[u8]) -> Option<String> {
    let header = data.get(..HEADER_LEN)?.strip_prefix(FILE_MAGIC)?;
    Some(format!("{PUBLIC_PREFIX}{}", to_hex(&header[16..])))
}

fn decrypt_file(secret: &BackupSecret, data: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let public_key = file_public_key(data).ok_or("Ce fichier n'est pas une sauvegarde Cléa.")?;
    if public_key != secret.public_key() {
        return Err(
            "Cette sauvegarde a été faite avec une autre clé de sauvegarde \
                    (une ancienne clé, remplacée depuis ?)."
                .into(),
        );
    }
    let (header, sealed) = data.split_at(HEADER_LEN);
    recovery::open(&secret.0, HPKE_INFO, header, sealed)
        .map(Zeroizing::new)
        .map_err(|_| "Déchiffrement impossible : le fichier est abîmé.".into())
}

/// Only names made by Cléa are accepted (no path, no `..`): `clea-<date>-<id>.backup`.
pub fn is_backup_file_name(name: &str) -> bool {
    name.starts_with("clea-")
        && name.ends_with(".backup")
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        && !name.contains("..")
}

/// Date of a backup, read from its name (`clea-20261114-103000-1a2b3c4d.backup`, UTC).
fn date_of(name: &str) -> Option<DateTime<Utc>> {
    let stamp = name.get(5..20)?;
    NaiveDateTime::parse_from_str(stamp, "%Y%m%d-%H%M%S")
        .ok()
        .map(|d| d.and_utc())
}

pub fn fingerprint_name(file: &str) -> String {
    format!("{file}{FINGERPRINT_EXT}")
}

fn sha256_hex(data: &[u8]) -> String {
    to_hex(&Sha256::digest(data))
}

/// Fingerprint file content, in the `sha256sum` format.
fn fingerprint_line(file: &str, data: &[u8]) -> String {
    format!("{}  {file}\n", sha256_hex(data))
}

/// Fingerprint written in a `.sha256` file (the first word of the line).
fn parse_fingerprint(content: &str) -> Option<String> {
    let hash = content.split_whitespace().next()?;
    (hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| hash.to_ascii_lowercase())
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match std::fs::read(path) {
        Ok(data) => Ok(Some(data)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("Lecture de {} impossible : {e}", path.display())),
    }
}

/// Writes a file in one step (temporary file, then rename), readable by its owner only.
fn write_atomic(path: &Path, data: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    let result = (|| -> std::io::Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        if let Some(dir) = path.parent() {
            std::fs::File::open(dir)?.sync_all()?;
        }
        Ok(())
    })();
    result.map_err(|e| {
        std::fs::remove_file(&tmp).ok();
        format!("Écriture de {} impossible : {e}", path.display())
    })
}

/// Fingerprint check of one backup.
#[derive(Debug, PartialEq)]
pub enum Fingerprint {
    Valid,
    Missing,
    Mismatch,
}

pub struct BackupFile {
    pub file: String,
    pub at: DateTime<Utc>,
    pub size: u64,
    pub fingerprint: Fingerprint,
}

/// Backups of the folder, oldest first, with their fingerprint checked.
pub fn list(dir: &Path) -> Result<Vec<BackupFile>, String> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("Lecture de {} impossible : {e}", dir.display())),
    };
    let mut backups = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let Some(file) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let Some(at) = date_of(&file).filter(|_| is_backup_file_name(&file)) else {
            continue;
        };
        let data = std::fs::read(entry.path()).map_err(|e| format!("Lecture de {file} : {e}"))?;
        let sha256 = sha256_hex(&data);
        let fingerprint = match read_optional(&dir.join(fingerprint_name(&file)))? {
            None => Fingerprint::Missing,
            Some(content) => match parse_fingerprint(&String::from_utf8_lossy(&content)) {
                Some(expected) if expected == sha256 => Fingerprint::Valid,
                _ => Fingerprint::Mismatch,
            },
        };
        backups.push(BackupFile {
            file,
            at,
            size: data.len() as u64,
            fingerprint,
        });
    }
    backups.sort_by(|a, b| a.at.cmp(&b.at).then_with(|| a.file.cmp(&b.file)));
    Ok(backups)
}

/// Problems to show: backups whose fingerprint is missing or no longer matches.
pub fn problems(backups: &[BackupFile]) -> Vec<String> {
    backups
        .iter()
        .filter_map(|b| match b.fingerprint {
            Fingerprint::Valid => None,
            Fingerprint::Missing => Some(format!("{} : fichier d'empreinte absent.", b.file)),
            Fingerprint::Mismatch => Some(format!(
                "{} : modifiée depuis sa création (l'empreinte ne correspond plus).",
                b.file
            )),
        })
        .collect()
}

/// Number of backups made for `public_key`: tells the owner whether an old backup key is
/// still needed.
pub fn backups_using_key(dir: &Path, public_key: &str) -> Result<usize, String> {
    let mut count = 0;
    for b in list(dir)? {
        let mut header = [0u8; HEADER_LEN];
        let mut file =
            std::fs::File::open(dir.join(&b.file)).map_err(|e| format!("{}: {e}", b.file))?;
        if std::io::Read::read_exact(&mut file, &mut header).is_ok()
            && file_public_key(&header).as_deref() == Some(public_key)
        {
            count += 1;
        }
    }
    Ok(count)
}

// --- Database export and import ---

/// Every table of the schema must be saved or skipped on purpose.
async fn check_tables(tx: &mut sqlx::PgConnection) -> Result<(), String> {
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT table_name::text FROM information_schema.tables
         WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'",
    )
    .fetch_all(tx)
    .await
    .map_err(db_error)?;
    let unknown: Vec<&String> = names
        .iter()
        .filter(|n| !TABLES.contains(&n.as_str()) && !SKIPPED.contains(&n.as_str()))
        .collect();
    if !unknown.is_empty() {
        return Err(format!(
            "Table(s) non prise(s) en charge par la sauvegarde : {unknown:?}. \
             Mets à jour TABLES ou SKIPPED dans backup.rs."
        ));
    }
    Ok(())
}

async fn migration_version(conn: &mut sqlx::PgConnection) -> Result<i64, String> {
    sqlx::query_scalar("SELECT COALESCE(MAX(version), 0) FROM _sqlx_migrations WHERE success")
        .fetch_one(conn)
        .await
        .map_err(db_error)
}

/// JSON export of the saved tables, read in the caller's transaction (one snapshot).
async fn export(conn: &mut sqlx::PgConnection) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut tables = serde_json::Map::new();
    for table in TABLES {
        // Safe: table names come from the TABLES constant, never from input
        let rows: String = sqlx::query_scalar(AssertSqlSafe(format!(
            "SELECT COALESCE(json_agg(t), '[]'::json)::text FROM {table} t"
        )))
        .fetch_one(&mut *conn)
        .await
        .map_err(db_error)?;
        let rows: Value = serde_json::from_str(&rows).map_err(|e| e.to_string())?;
        tables.insert(table.to_string(), rows);
    }
    let doc = serde_json::json!({
        "format": EXPORT_FORMAT,
        "migration": migration_version(conn).await?,
        "tables": tables,
    });
    serde_json::to_vec(&doc)
        .map(Zeroizing::new)
        .map_err(|e| e.to_string())
}

// --- Operations ---

pub struct Made {
    pub file: String,
    pub size: u64,
}

/// Makes a backup now: the encrypted file, then its fingerprint.
pub async fn run(db: &PgPool, dir: &Path) -> Result<Made, String> {
    let mut tx = db.begin().await.map_err(db_error)?;
    // One snapshot for the whole export
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    // Row lock: two backups never run at the same time (server and command line)
    let public_key: Option<String> =
        sqlx::query_scalar("SELECT public_key FROM backup_settings WHERE id = 1 FOR UPDATE")
            .fetch_one(&mut *tx)
            .await
            .map_err(db_error)?;
    let public_key = public_key.ok_or(
        "Sauvegardes pas encore activées : il faut d'abord créer la clé de sauvegarde \
         (page Sauvegardes).",
    )?;
    check_tables(&mut tx).await?;
    let plaintext = export(&mut tx).await?;

    let id = Uuid::new_v4();
    let data = encrypt_file(&public_key, id, &plaintext)?;
    let file = format!(
        "clea-{}-{}.backup",
        Utc::now().format("%Y%m%d-%H%M%S"),
        &id.simple().to_string()[..8]
    );
    std::fs::create_dir_all(dir).map_err(|e| format!("Dossier {} : {e}", dir.display()))?;
    write_atomic(&dir.join(&file), &data)?;
    write_atomic(
        &dir.join(fingerprint_name(&file)),
        fingerprint_line(&file, &data).as_bytes(),
    )?;

    sqlx::query("UPDATE backup_settings SET last_backup_at = now() WHERE id = 1")
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    tx.commit().await.map_err(db_error)?;
    Ok(Made {
        file,
        size: data.len() as u64,
    })
}

/// Deletes the backups older than the retention period, with their fingerprint.
pub async fn purge(db: &PgPool, dir: &Path) -> Result<usize, String> {
    let retention_days: i32 =
        sqlx::query_scalar("SELECT retention_days FROM backup_settings WHERE id = 1")
            .fetch_one(db)
            .await
            .map_err(db_error)?;
    let limit = Utc::now() - chrono::Duration::days(retention_days.into());
    delete_older_than(dir, limit)
}

fn delete_older_than(dir: &Path, limit: DateTime<Utc>) -> Result<usize, String> {
    let expired: Vec<BackupFile> = list(dir)?.into_iter().filter(|b| b.at < limit).collect();
    for b in &expired {
        for name in [b.file.clone(), fingerprint_name(&b.file)] {
            match std::fs::remove_file(dir.join(&name)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("Suppression de {name} impossible : {e}")),
            }
        }
    }
    Ok(expired.len())
}

/// Called every 15 minutes by the server: makes a backup when one is due, then deletes the
/// expired ones. Errors are logged, never shown to visitors.
pub async fn scheduled(db: &PgPool, dir: &Path) {
    type Row = (Option<String>, String, i32, i32, Option<i64>);
    let settings: Result<Row, sqlx::Error> = sqlx::query_as(
        "SELECT public_key, frequency, month_day, week_day,
                EXTRACT(EPOCH FROM last_backup_at)::bigint
         FROM backup_settings WHERE id = 1",
    )
    .fetch_one(db)
    .await;
    let (frequency, month_day, week_day, last) = match settings {
        Ok((Some(_), f, m, w, last)) => {
            (f, m, w, last.and_then(|s| DateTime::from_timestamp(s, 0)))
        }
        Ok(_) => return,
        Err(e) => {
            tracing::warn!("Sauvegardes : lecture des réglages impossible : {e}");
            return;
        }
    };
    if is_due(&frequency, month_day, week_day, last, Utc::now()) {
        match run(db, dir).await {
            Ok(m) => tracing::info!("Sauvegarde faite : {}", m.file),
            Err(e) => tracing::error!("Sauvegarde automatique échouée : {e}"),
        }
    }
    if let Err(e) = purge(db, dir).await {
        tracing::error!("Suppression des sauvegardes expirées échouée : {e}");
    }
}

/// Whether an automatic backup is due. Daily counts from the last backup; weekly and
/// monthly are due once the chosen day (00:00 UTC) has come and no backup was made since.
fn is_due(
    frequency: &str,
    month_day: i32,
    week_day: i32,
    last: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> bool {
    match frequency {
        "daily" => last.is_none_or(|at| now - at >= chrono::Duration::days(1)),
        "weekly" => {
            let due = last_week_day(now, week_day.clamp(1, 7) as u32);
            last.is_none_or(|at| at < due)
        }
        "monthly" => {
            let due = last_month_day(now, month_day.clamp(1, 28) as u32);
            last.is_none_or(|at| at < due)
        }
        _ => false,
    }
}

/// Most recent `day` of the week (1 = Monday) at 00:00 UTC, at or before `now`.
fn last_week_day(now: DateTime<Utc>, day: u32) -> DateTime<Utc> {
    use chrono::Datelike;
    let today = now.weekday().number_from_monday();
    let back = (today + 7 - day) % 7;
    let date = now.date_naive() - chrono::Duration::days(back.into());
    date.and_hms_opt(0, 0, 0)
        .expect("midnight always exists")
        .and_utc()
}

/// Most recent `day` of a month at 00:00 UTC, at or before `now`.
fn last_month_day(now: DateTime<Utc>, day: u32) -> DateTime<Utc> {
    use chrono::{Datelike, TimeZone};
    let (mut year, mut month) = (now.year(), now.month());
    if now.day() < day {
        (year, month) = if month == 1 {
            (year - 1, 12)
        } else {
            (year, month - 1)
        };
    }
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0)
        .single()
        .expect("days 1 to 28 exist in every month")
}

pub struct Restored {
    pub file: String,
    /// The `.sha256` file was next to the backup and matched
    pub fingerprint_checked: bool,
    /// The current master key opens the organization key of the backup
    pub master_key_opens: bool,
}

/// `clea restore`: checks the fingerprint, decrypts with the backup key, then imports into
/// an empty instance (the tables are created by the migrations, run before the command).
pub async fn restore(
    db: &PgPool,
    master_key: &str,
    backup_path: &Path,
    secret_input: &str,
) -> Result<Restored, String> {
    let file = backup_path
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| is_backup_file_name(n))
        .ok_or("Nom de fichier inattendu : il faut un fichier clea-….backup.")?
        .to_string();
    let data = std::fs::read(backup_path).map_err(|e| format!("Lecture de {file} : {e}"))?;
    let fingerprint_path = backup_path.with_file_name(fingerprint_name(&file));
    let fingerprint_checked = match read_optional(&fingerprint_path)? {
        None => false,
        Some(content) => {
            if parse_fingerprint(&String::from_utf8_lossy(&content)) != Some(sha256_hex(&data)) {
                return Err(
                    "Le fichier a été modifié depuis sa création (l'empreinte ne \
                            correspond plus) : restauration refusée."
                        .into(),
                );
            }
            true
        }
    };

    let secret = BackupSecret::parse(secret_input).map_err(message)?;
    let plaintext = decrypt_file(&secret, &data)?;
    let doc: Value = serde_json::from_slice(&plaintext).map_err(|_| "Contenu illisible.")?;
    if doc["format"] != EXPORT_FORMAT {
        return Err("Format de sauvegarde inconnu.".into());
    }
    // Cléa only starts if the master key opens the organization keys of the backup
    let master_key_opens = doc["tables"]["organizations"]
        .as_array()
        .is_some_and(|orgs| {
            orgs.iter().all(|o| {
                let id = o["id"].as_str().and_then(|s| Uuid::parse_str(s).ok());
                let locked = o["locked_key"].as_str();
                matches!((id, locked), (Some(id), Some(locked))
                    if keys::unlock_org_key(master_key, id, locked).is_ok())
            })
        });

    let mut tx = db.begin().await.map_err(db_error)?;
    let version = migration_version(&mut tx).await?;
    if doc["migration"].as_i64() != Some(version) {
        return Err(
            "Cette sauvegarde vient d'une autre version de Cléa : restaure-la avec \
                    la version qui l'a faite, puis mets à jour."
                .into(),
        );
    }
    let orgs: i64 = sqlx::query_scalar("SELECT count(*) FROM organizations")
        .fetch_one(&mut *tx)
        .await
        .map_err(db_error)?;
    if orgs > 0 {
        return Err(
            "La base n'est pas vide : la restauration se fait dans une base neuve, \
                    sans faire le setup."
                .into(),
        );
    }
    for table in TABLES.iter().rev() {
        sqlx::query(AssertSqlSafe(format!("DELETE FROM {table}")))
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
    }
    for table in TABLES {
        let rows = doc["tables"][*table].to_string();
        sqlx::query(AssertSqlSafe(format!(
            "INSERT INTO {table} SELECT * FROM json_populate_recordset(NULL::{table}, $1::json)"
        )))
        .bind(rows)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    }
    tx.commit().await.map_err(db_error)?;
    Ok(Restored {
        file,
        fingerprint_checked,
        master_key_opens,
    })
}

fn message(e: AppError) -> String {
    match e {
        AppError::BadRequest(m)
        | AppError::Unauthorized(m)
        | AppError::Forbidden(m)
        | AppError::Conflict(m)
        | AppError::NotFound(m)
        | AppError::TooManyRequests(m)
        | AppError::Internal(m) => m,
    }
}

fn db_error(e: sqlx::Error) -> String {
    format!("Erreur de base de données : {e}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("clea-test-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn backup_key_display_and_parse() {
        let new = generate_key();
        assert!(new.secret_display.starts_with("CLEA-BACKUP-KEY-"));
        assert!(new.public_key.starts_with("b1:"));
        let secret = BackupSecret::parse(&new.secret_display.to_lowercase()).unwrap();
        assert_eq!(secret.public_key(), new.public_key);
        // A recovery key is not a backup key
        let recovery = recovery::generate();
        assert!(BackupSecret::parse(&recovery.secret_display).is_err());
    }

    #[test]
    fn backup_file_opens_only_with_its_key_and_untouched() {
        let new = generate_key();
        let secret = BackupSecret::parse(&new.secret_display).unwrap();
        let data = encrypt_file(&new.public_key, Uuid::new_v4(), b"{\"a\":1}").unwrap();
        assert_eq!(file_public_key(&data).unwrap(), new.public_key);
        assert_eq!(&*decrypt_file(&secret, &data).unwrap(), b"{\"a\":1}");

        let other = BackupSecret::parse(&generate_key().secret_display).unwrap();
        assert!(decrypt_file(&other, &data).is_err());
        let mut tampered = data.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(decrypt_file(&secret, &tampered).is_err());
        // The header is bound to the content: changing the backup id breaks it
        let mut header_changed = data.clone();
        header_changed[FILE_MAGIC.len()] ^= 1;
        assert!(decrypt_file(&secret, &header_changed).is_err());
        assert!(decrypt_file(&secret, b"not a backup").is_err());
    }

    #[test]
    fn fingerprints_are_checked_like_sha256sum() {
        let dir = temp_dir("list");
        let name = "clea-20261114-100000-1a2b3c4d.backup";
        std::fs::write(dir.join(name), b"data").unwrap();
        let line = fingerprint_line(name, b"data");
        assert!(line.ends_with(&format!("  {name}\n")));
        std::fs::write(dir.join(fingerprint_name(name)), &line).unwrap();
        // Not backups: ignored
        std::fs::write(dir.join("notes.txt"), b"x").unwrap();
        std::fs::write(dir.join("clea-x.backup"), b"x").unwrap();

        let backups = list(&dir).unwrap();
        assert_eq!(backups.len(), 1);
        assert_eq!(backups[0].fingerprint, Fingerprint::Valid);
        assert_eq!(backups[0].at.to_rfc3339(), "2026-11-14T10:00:00+00:00");
        assert!(problems(&backups).is_empty());

        std::fs::write(dir.join(name), b"changed").unwrap();
        assert_eq!(list(&dir).unwrap()[0].fingerprint, Fingerprint::Mismatch);
        std::fs::remove_file(dir.join(fingerprint_name(name))).unwrap();
        let backups = list(&dir).unwrap();
        assert_eq!(backups[0].fingerprint, Fingerprint::Missing);
        assert_eq!(problems(&backups).len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn expired_backups_are_deleted_with_their_fingerprint() {
        let dir = temp_dir("purge");
        for name in [
            "clea-20260101-000000-00000001.backup",
            "clea-20261110-000000-00000002.backup",
        ] {
            std::fs::write(dir.join(name), b"data").unwrap();
            std::fs::write(
                dir.join(fingerprint_name(name)),
                fingerprint_line(name, b"data"),
            )
            .unwrap();
        }
        let limit = "2026-06-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        assert_eq!(delete_older_than(&dir, limit).unwrap(), 1);
        assert!(!dir.join("clea-20260101-000000-00000001.backup").exists());
        assert!(!dir
            .join("clea-20260101-000000-00000001.backup.sha256")
            .exists());
        assert!(dir.join("clea-20261110-000000-00000002.backup").exists());
        assert_eq!(delete_older_than(&dir, limit).unwrap(), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn schedule_is_due_at_the_right_time() {
        let t = |s: &str| s.parse::<DateTime<Utc>>().unwrap();
        // Monthly on the 15th
        let m15 = |last: Option<&str>, now| is_due("monthly", 15, 1, last.map(t), t(now));
        assert!(m15(None, "2026-11-14T10:00:00Z"));
        assert!(!m15(Some("2026-10-15T00:10:00Z"), "2026-11-14T23:59:00Z"));
        assert!(m15(Some("2026-10-15T00:10:00Z"), "2026-11-15T00:00:00Z"));
        assert!(!m15(Some("2026-11-15T00:10:00Z"), "2026-12-01T00:00:00Z"));
        // Chosen on the 20th: next one on the 15th of the next month, across the new year
        assert!(!m15(Some("2026-12-20T09:00:00Z"), "2027-01-14T09:00:00Z"));
        assert!(m15(Some("2026-12-20T09:00:00Z"), "2027-01-15T09:00:00Z"));
        assert_eq!(
            last_month_day(t("2027-01-10T00:00:00Z"), 15),
            t("2026-12-15T00:00:00Z")
        );
        // Weekly on Tuesday (2): 2026-11-17 is a Tuesday
        let tue = |last, now| is_due("weekly", 1, 2, Some(t(last)), t(now));
        assert!(!tue("2026-11-10T00:05:00Z", "2026-11-16T23:59:00Z"));
        assert!(tue("2026-11-10T00:05:00Z", "2026-11-17T00:00:00Z"));
        // A manual backup on Thursday does not move the next Tuesday
        assert!(tue("2026-11-12T15:00:00Z", "2026-11-17T00:00:00Z"));
        assert!(!tue("2026-11-17T00:05:00Z", "2026-11-23T12:00:00Z"));
        assert_eq!(
            last_week_day(t("2026-11-16T08:00:00Z"), 2),
            t("2026-11-10T00:00:00Z")
        );
        // Daily, manual
        let daily = |last, now| is_due("daily", 1, 1, Some(t(last)), t(now));
        assert!(!daily("2026-11-14T10:00:00Z", "2026-11-15T09:59:00Z"));
        assert!(daily("2026-11-14T10:00:00Z", "2026-11-15T10:00:00Z"));
        assert!(!is_due("manual", 1, 1, None, t("2026-11-14T10:00:00Z")));
    }

    #[test]
    fn only_backup_file_names_are_accepted() {
        assert!(is_backup_file_name("clea-20261114-100000-1a2b3c4d.backup"));
        assert!(!is_backup_file_name("../etc/passwd"));
        assert!(!is_backup_file_name("clea-../../x.backup"));
        assert!(!is_backup_file_name("clea-a/b.backup"));
        assert!(!is_backup_file_name(
            "clea-20261114-100000-1a2b3c4d.backup.sha256"
        ));
        assert!(!is_backup_file_name("clea-x.backup.tmp"));
    }

    #[test]
    fn tables_are_listed_once() {
        for t in TABLES {
            assert_eq!(TABLES.iter().filter(|x| x == &t).count(), 1);
            assert!(!SKIPPED.contains(t));
        }
    }
}
