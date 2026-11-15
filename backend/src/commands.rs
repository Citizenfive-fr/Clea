//! Host commands (`clea backup`, `clea recover`...), shared by the command line and the
//! console. Each one prints its result and returns an error message on failure.

use sqlx::{PgConnection, PgPool};
use std::path::{Path, PathBuf};

use crate::{backup, cli, config::Config, keys};

/// Advisory lock held by the running server ("CLEA" in ASCII).
const SERVER_LOCK: i64 = 0x434C_4541;

/// Taken by the server at startup and kept for its whole life (the connection is never
/// returned to the pool). The commands that must run with Cléa stopped check it.
pub async fn hold_server_lock(db: &PgPool) -> Option<PgConnection> {
    let mut conn = db.acquire().await.ok()?.detach();
    let taken: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(SERVER_LOCK)
        .fetch_one(&mut conn)
        .await
        .ok()?;
    if !taken {
        tracing::warn!("Une autre instance de Cléa semble déjà tourner sur cette base.");
    }
    Some(conn)
}

/// Whether a Cléa server is running on this database.
pub async fn server_running(db: &PgPool) -> Result<bool, String> {
    let mut conn = db.acquire().await.map_err(db_error)?;
    let free: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(SERVER_LOCK)
        .fetch_one(&mut *conn)
        .await
        .map_err(db_error)?;
    if free {
        sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(SERVER_LOCK)
            .execute(&mut *conn)
            .await
            .map_err(db_error)?;
    }
    Ok(!free)
}

/// recover, rotate-key and restore change keys or the whole base under the server's feet.
async fn ensure_server_stopped(db: &PgPool) -> Result<(), String> {
    if server_running(db).await? {
        return Err("Cléa tourne encore sur cette base : arrête-la d'abord \
                    (docker compose stop app), puis relance la commande."
            .into());
    }
    Ok(())
}

pub fn backup_dir(config: &Config) -> Result<PathBuf, String> {
    config
        .backup_dir
        .clone()
        .ok_or_else(|| "BACKUP_DIR n'est pas défini : indique le dossier des sauvegardes.".into())
}

pub async fn recover(db: &PgPool, config: &Config, file: &str) -> Result<(), String> {
    ensure_server_stopped(db).await?;
    let recovered = cli::recover(db, &config.master_key, file).await?;
    for org in &recovered {
        say(&format!(
            "Organisation « {} » : clé récupérée et enfermée avec la nouvelle clé maîtresse.",
            org.name
        ));
        print_new_recovery_key(&org.new_recovery_key);
    }
    let shred = if file == "-" {
        "shred -u <fichier>".to_string()
    } else {
        format!("shred -u {file}")
    };
    say(&format!(
        "Supprime maintenant le fichier de l'ancienne clé de secours ({shred}), \
         puis relance Cléa."
    ));
    if let Err(e) = keys::check_org_keys(db, &config.master_key).await {
        say(&format!(
            "Attention, une autre organisation ne s'ouvre pas avec cette clé maîtresse : {e}\n\
             Son propriétaire doit lancer clea recover avec sa propre clé de secours."
        ));
    }
    Ok(())
}

pub async fn rotate_key(db: &PgPool, config: &Config, file: &str) -> Result<(), String> {
    ensure_server_stopped(db).await?;
    let count = cli::rotate_key(db, &config.master_key, file).await?;
    say(&format!(
        "Clé maîtresse changée pour {count} organisation(s).\n\
         L'ancienne clé ne marche plus : mets la nouvelle dans APP_SECRET_KEY \
         ou APP_KEY_FILE, puis relance Cléa."
    ));
    Ok(())
}

pub async fn new_recovery_key(db: &PgPool, config: &Config) -> Result<(), String> {
    for org in &cli::new_recovery_key(db, &config.master_key).await? {
        say(&format!("Organisation « {} » :", org.name));
        print_new_recovery_key(&org.new_recovery_key);
    }
    Ok(())
}

pub async fn backup(db: &PgPool, config: &Config) -> Result<(), String> {
    let dir = backup_dir(config)?;
    let made = backup::run(db, &dir).await?;
    say(&format!(
        "Sauvegarde faite : {} ({} octets).",
        made.file, made.size
    ));
    match backup::purge(db, &dir).await {
        Ok(0) => {}
        Ok(n) => say(&format!("{n} sauvegarde(s) expirée(s) supprimée(s).")),
        Err(e) => say(&format!(
            "Suppression des sauvegardes expirées échouée : {e}"
        )),
    }
    Ok(())
}

pub fn backup_verify(config: &Config) -> Result<(), String> {
    let backups = backup::list(&backup_dir(config)?)?;
    let problems = backup::problems(&backups);
    if !problems.is_empty() {
        return Err(format!(
            "Problèmes trouvés :\n{}",
            problems
                .iter()
                .map(|p| format!("- {p}"))
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }
    say(&format!(
        "{} sauvegarde(s), toutes les empreintes sont bonnes.",
        backups.len()
    ));
    Ok(())
}

pub async fn restore(
    db: &PgPool,
    config: &Config,
    file: &Path,
    key_file: &str,
) -> Result<(), String> {
    ensure_server_stopped(db).await?;
    let secret = cli::read_key_input(key_file, "la clé de sauvegarde")?;
    let restored = backup::restore(db, &config.master_key, file, &secret).await?;
    say(&format!("Sauvegarde {} restaurée.", restored.file));
    if !restored.fingerprint_checked {
        say(
            "Attention : pas de fichier d'empreinte (.sha256) à côté de la sauvegarde. \
             Le déchiffrement a tout de même vérifié que le fichier n'était pas abîmé.",
        );
    }
    if !restored.master_key_opens {
        say(
            "Attention : la clé maîtresse actuelle n'ouvre pas la clé de l'organisation de \
             cette sauvegarde, Cléa refusera de démarrer. Remets l'ancienne clé maîtresse, \
             ou si elle est perdue, lance clea recover avec la clé de secours.",
        );
    }
    say(
        "Les sessions ne sont pas sauvegardées : tout le monde devra se reconnecter. \
         Relance Cléa.",
    );
    Ok(())
}

/// Shows a new recovery key once, with what to do with it.
fn print_new_recovery_key(key: &str) {
    say(&format!(
        "\nL'ancienne clé de secours ne marche plus. Voici la nouvelle, affichée une seule \
         fois. Garde-la hors de ce serveur, imprimée et rangée dans un \
         endroit sûr. Ne la transmets à personne :\n\n{key}\n"
    ));
}

/// Latest stable release on the forge (no pre-release, no draft).
const RELEASES_API: &str = "https://git.citizenfive.fr/api/v1/repos/Citizenfive-fr/Clea/releases\
                            ?draft=false&pre-release=false&limit=1";
const RELEASES_PAGE: &str = "https://git.citizenfive.fr/Citizenfive-fr/Clea/releases";

/// `clea update-check`: asks the forge for the latest stable version, only when the host
/// runs it (never in the background). Nothing is downloaded or installed.
/// As anonymous as a request can be: no version (compared here), no User-Agent, no cookie.
/// The forge still sees the IP: HTTPS_PROXY is honoured to go through a proxy.
pub async fn update_check() -> Result<(), String> {
    let current = env!("CARGO_PKG_VERSION");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    let releases: serde_json::Value = client
        .get(RELEASES_API)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|_| "Impossible de joindre la forge (git.citizenfive.fr) : réessaie plus tard.")?
        .bytes()
        .await
        .ok()
        .and_then(|body| serde_json::from_slice(&body).ok())
        .ok_or("Réponse de la forge illisible.")?;

    // The tag comes from the network: only a plain version number is accepted and shown
    let Some(tag) = releases[0]["tag_name"].as_str() else {
        say(&format!(
            "Aucune version stable publiée pour l'instant. Tu as la version {current}."
        ));
        return Ok(());
    };
    let latest = parse_version(tag).ok_or("Numéro de version inattendu sur la forge.")?;
    match parse_version(current) {
        Some(mine) if mine >= latest => say(&format!("Tu es à jour (version {current}).")),
        _ => say(&format!(
            "Nouvelle version stable : {}.{}.{} (tu as {current}).\n\
             Notes de version : {RELEASES_PAGE}/tag/v{}.{}.{}\n\
             Pour mettre à jour : docker compose pull, puis docker compose up -d.\n\
             Vérifie d'abord la signature de l'image (cosign verify, voir le wiki).",
            latest.0, latest.1, latest.2, latest.0, latest.1, latest.2
        )),
    }
    Ok(())
}

/// `v1.2.3` or `1.2.3` -> (1, 2, 3). Pre-releases (`1.2.3-beta`) are refused.
fn parse_version(text: &str) -> Option<(u64, u64, u64)> {
    let mut parts = text.strip_prefix('v').unwrap_or(text).split('.');
    let mut next = || parts.next()?.parse::<u64>().ok();
    let version = (next()?, next()?, next()?);
    parts.next().is_none().then_some(version)
}

/// Prints a message with the margin of the console, line by line.
fn say(text: &str) {
    for line in text.lines() {
        if line.is_empty() {
            println!();
        } else {
            println!("  {line}");
        }
    }
}

fn db_error(e: sqlx::Error) -> String {
    format!("Erreur de base de données : {e}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_compared_as_numbers() {
        assert_eq!(parse_version("v0.10.2"), Some((0, 10, 2)));
        assert_eq!(parse_version("1.2.3"), Some((1, 2, 3)));
        assert!(parse_version("v0.10.0") > parse_version("v0.9.9"));
        assert_eq!(parse_version("v1.0.0-beta"), None);
        assert_eq!(parse_version("v1.0"), None);
        assert_eq!(parse_version("v1.0.0.1"), None);
        assert_eq!(parse_version("\x1b[31mv1.0.0"), None);
    }
}
