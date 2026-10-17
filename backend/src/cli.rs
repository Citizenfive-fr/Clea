//! Admin commands, run from the command line by the host (never through the web interface).
//!
//! Keys are always read from a file or from standard input (`-`), never passed as arguments:
//! arguments are visible to other users in `ps` and are kept in the shell history.
//! Standard input is what works with Docker, where the container user cannot read a
//! host file restricted with `chmod 600`.

use sqlx::{PgPool, Row};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    config,
    error::AppError,
    keys,
    recovery::{self, RecoverySecret},
};

pub const USAGE: &str = "\
Utilisation :
  clea                          lance le serveur
  clea recover <fichier>        clé maîtresse perdue : rouvre la clé de l'organisation
                                avec la clé de secours rangée dans <fichier>, puis
                                l'enferme avec la nouvelle clé maîtresse
                                (APP_SECRET_KEY ou APP_KEY_FILE). Une nouvelle clé
                                de secours est créée et affichée une seule fois
  clea rotate-key <fichier>     change de clé maîtresse : la nouvelle clé est lue
                                dans <fichier>, l'actuelle dans APP_SECRET_KEY ou
                                APP_KEY_FILE
  clea new-recovery-key         clé de secours perdue : en crée une nouvelle avec la
                                clé maîtresse et l'affiche une seule fois. L'ancienne
                                ne marche plus
  clea help                     affiche cette aide

<fichier> peut être - pour lire la clé sur l'entrée standard (clea recover - < secours.txt).
Arrête Cléa avant de lancer recover ou rotate-key.";

pub enum Command {
    Serve,
    Help,
    Recover(String),
    RotateKey(String),
    NewRecoveryKey,
}

/// Parses the arguments after the program name. Unknown input gives the usage text as error.
pub fn parse(args: &[String]) -> Result<Command, String> {
    match args {
        [] => Ok(Command::Serve),
        [cmd] if matches!(cmd.as_str(), "help" | "--help" | "-h") => Ok(Command::Help),
        [cmd, file] if cmd == "recover" => Ok(Command::Recover(file.clone())),
        [cmd, file] if cmd == "rotate-key" => Ok(Command::RotateKey(file.clone())),
        [cmd] if cmd == "new-recovery-key" => Ok(Command::NewRecoveryKey),
        _ => Err(USAGE.into()),
    }
}

/// An organization with its new recovery key (shown once, never stored).
pub struct Renewed {
    pub name: String,
    pub new_recovery_key: Zeroizing<String>,
}

/// `clea recover`: reopens the organization key with the recovery key and locks it again
/// with the master key from the configuration (the new one).
///
/// The used recovery key is replaced by a new one: it sat in a file on the server, so it may
/// have leaked. The old recovery copy and public key are overwritten in the same transaction,
/// so the old key no longer opens anything in this database.
pub async fn recover(
    db: &PgPool,
    master_key: &str,
    secret_file: &str,
) -> Result<Vec<Renewed>, String> {
    let content = read_key_input(secret_file, "la clé de secours")?;
    let secret = RecoverySecret::parse(&content).map_err(message)?;

    let mut tx = db.begin().await.map_err(db_error)?;
    let rows = sqlx::query(
        "SELECT id, name, recovery_locked_key FROM organizations
         WHERE recovery_public_key = $1 FOR UPDATE",
    )
    .bind(secret.public_key())
    .fetch_all(&mut *tx)
    .await
    .map_err(db_error)?;
    if rows.is_empty() {
        return Err(
            "Aucune organisation ne correspond à cette clé de secours. \
                    Si elle a déjà servi à un clea recover, elle a été remplacée par une nouvelle."
                .into(),
        );
    }

    let mut recovered = Vec::new();
    for row in rows {
        let id: Uuid = row.get("id");
        let locked: Option<String> = row.get("recovery_locked_key");
        let locked = locked.ok_or("Organisation sans copie de secours de sa clé.")?;
        let key = recovery::unlock_with_recovery(&secret, id, &locked).map_err(message)?;
        let relocked = keys::lock_org_key(master_key, id, &key).map_err(message)?;
        let (new_recovery, recovery_locked) = renew_recovery(id, &key)?;
        sqlx::query(
            "UPDATE organizations
             SET locked_key = $1, recovery_locked_key = $2, recovery_public_key = $3,
                 recovery_created_at = now(), recovery_source = 'recover',
                 recovery_notice_pending = TRUE
             WHERE id = $4",
        )
        .bind(relocked)
        .bind(recovery_locked)
        .bind(&new_recovery.public_key)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        audit(&mut tx, id, "master_key.recovered").await?;
        recovered.push(Renewed {
            name: row.get("name"),
            new_recovery_key: new_recovery.secret_display,
        });
    }
    // Nothing is shown before the commit: a key displayed for a rolled-back change would be useless
    tx.commit().await.map_err(db_error)?;
    Ok(recovered)
}

/// `clea new-recovery-key`: replaces the recovery key of every organization, using the
/// master key to open the organization key. For a recovery key lost or never saved.
/// Whoever has the master key and the database can already open everything, so this
/// command gives no new power. It is not offered in the web interface on purpose:
/// a stolen password must not be enough to create a recovery key.
pub async fn new_recovery_key(db: &PgPool, master_key: &str) -> Result<Vec<Renewed>, String> {
    let mut tx = db.begin().await.map_err(db_error)?;
    let rows = sqlx::query("SELECT id, name, locked_key FROM organizations FOR UPDATE")
        .fetch_all(&mut *tx)
        .await
        .map_err(db_error)?;
    if rows.is_empty() {
        return Err("Aucune organisation en base : la clé de secours est créée au setup.".into());
    }

    let mut renewed = Vec::new();
    for row in rows {
        let id: Uuid = row.get("id");
        let locked: Option<String> = row.get("locked_key");
        let locked =
            locked.ok_or("Organisation sans clé de chiffrement (base d'une ancienne bêta).")?;
        let key = keys::unlock_org_key(master_key, id, &locked).map_err(|_| {
            "La clé maîtresse n'ouvre pas la clé de l'organisation : vérifie APP_SECRET_KEY \
             ou APP_KEY_FILE (si elle est perdue, utilise clea recover)."
                .to_string()
        })?;
        let (new_recovery, recovery_locked) = renew_recovery(id, &key)?;
        sqlx::query(
            "UPDATE organizations
             SET recovery_locked_key = $1, recovery_public_key = $2, recovery_created_at = now(),
                 recovery_source = 'new-recovery-key', recovery_notice_pending = TRUE
             WHERE id = $3",
        )
        .bind(recovery_locked)
        .bind(&new_recovery.public_key)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        audit(&mut tx, id, "recovery_key.recreated_by_host").await?;
        renewed.push(Renewed {
            name: row.get("name"),
            new_recovery_key: new_recovery.secret_display,
        });
    }
    // Same as recover: the new keys are shown only once they are saved
    tx.commit().await.map_err(db_error)?;
    Ok(renewed)
}

/// `clea rotate-key`: locks every organization key with a new master key, all or nothing.
/// The recovery copies do not depend on the master key and stay as they are.
pub async fn rotate_key(
    db: &PgPool,
    current_key: &str,
    new_key_file: &str,
) -> Result<usize, String> {
    let source = "la nouvelle clé";
    let content = read_key_input(new_key_file, source)?;
    let new_key = Zeroizing::new(config::check_master_key(
        content.trim().to_string(),
        source,
    )?);
    if new_key.as_str() == current_key {
        return Err("La nouvelle clé est identique à la clé actuelle.".into());
    }

    let mut tx = db.begin().await.map_err(db_error)?;
    let rows = sqlx::query("SELECT id, locked_key FROM organizations FOR UPDATE")
        .fetch_all(&mut *tx)
        .await
        .map_err(db_error)?;
    if rows.is_empty() {
        return Err(
            "Aucune organisation en base, rien à changer : mets directement la nouvelle \
                    clé dans APP_SECRET_KEY ou APP_KEY_FILE."
                .into(),
        );
    }

    for row in &rows {
        let id: Uuid = row.get("id");
        let locked: Option<String> = row.get("locked_key");
        let locked =
            locked.ok_or("Organisation sans clé de chiffrement (base d'une ancienne bêta).")?;
        let key = keys::unlock_org_key(current_key, id, &locked).map_err(|_| {
            "La clé maîtresse actuelle n'ouvre pas la clé de l'organisation : \
             vérifie APP_SECRET_KEY ou APP_KEY_FILE (si elle est perdue, utilise clea recover)."
                .to_string()
        })?;
        let relocked = keys::lock_org_key(&new_key, id, &key).map_err(message)?;
        sqlx::query("UPDATE organizations SET locked_key = $1 WHERE id = $2")
            .bind(relocked)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        audit(&mut tx, id, "master_key.rotated").await?;
    }
    tx.commit().await.map_err(db_error)?;
    Ok(rows.len())
}

/// Audit entry written in the same transaction as the change: no change without its trace.
/// No user: these commands are run by the host on the server, not through an account.
async fn audit(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: Uuid,
    action: &str,
) -> Result<(), String> {
    sqlx::query("INSERT INTO audit_logs (organization_id, action) VALUES ($1, $2)")
        .bind(org_id)
        .bind(action)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
    Ok(())
}

/// New recovery key pair, and the organization key locked for it.
fn renew_recovery(
    id: Uuid,
    key: &keys::OrgKey,
) -> Result<(recovery::NewRecoveryKey, String), String> {
    let new_recovery = recovery::generate();
    let locked = recovery::lock_for_recovery(&new_recovery.public_key, id, key).map_err(message)?;
    Ok((new_recovery, locked))
}

/// Reads a key from a file, or from standard input when `path` is `-`.
fn read_key_input(path: &str, what: &str) -> Result<Zeroizing<String>, String> {
    let mut content = Zeroizing::new(String::new());
    let result = if path == "-" {
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut content).map(|_| ())
    } else {
        std::fs::read_to_string(path).map(|s| *content = s)
    };
    result.map_err(|e| format!("Lecture de {what} impossible ({path}) : {e}"))?;
    Ok(content)
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

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_commands() {
        assert!(matches!(parse(&args(&[])), Ok(Command::Serve)));
        assert!(matches!(parse(&args(&["help"])), Ok(Command::Help)));
        assert!(matches!(
            parse(&args(&["new-recovery-key"])),
            Ok(Command::NewRecoveryKey)
        ));
        assert!(
            matches!(parse(&args(&["recover", "k.txt"])), Ok(Command::Recover(f)) if f == "k.txt")
        );
        assert!(
            matches!(parse(&args(&["rotate-key", "k.txt"])), Ok(Command::RotateKey(f)) if f == "k.txt")
        );
    }

    #[test]
    fn refuses_unknown_or_incomplete_commands() {
        assert!(parse(&args(&["recover"])).is_err());
        assert!(parse(&args(&["rotate-key"])).is_err());
        assert!(parse(&args(&["recover", "a", "b"])).is_err());
        assert!(parse(&args(&["serve"])).is_err());
        assert!(parse(&args(&["new-recovery-key", "k.txt"])).is_err());
    }
}
