use std::env;

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    /// Master key chosen by the host (APP_KEY_FILE, or APP_SECRET_KEY). Never stored in the database.
    pub master_key: String,
    pub session_duration_hours: i64,
    pub invitation_duration_hours: i64,
    pub secure_cookies: bool,
    /// Read the client IP from X-Forwarded-For (only behind our own reverse proxy)
    pub trust_proxy: bool,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let master_key = resolve_master_key(
            env::var("APP_KEY_FILE").ok().as_deref(),
            env::var("APP_SECRET_KEY").ok().as_deref(),
        )?;
        Ok(Self {
            database_url: require("DATABASE_URL")?,
            master_key,
            session_duration_hours: optional_i64("SESSION_DURATION_HOURS", 24),
            invitation_duration_hours: optional_i64("INVITATION_DURATION_HOURS", 72),
            secure_cookies: std::env::var("SECURE_COOKIES").as_deref() == Ok("true"),
            trust_proxy: std::env::var("TRUST_PROXY").as_deref() == Ok("true"),
        })
    }
}

/// 64 hex characters = 256 random bits, what `openssl rand -hex 64` (128 chars) easily exceeds
const MASTER_KEY_MIN_HEX: usize = 64;

/// APP_KEY_FILE (a file holding the key, e.g. a Docker secret) wins over APP_SECRET_KEY.
/// Errors never include the key itself.
fn resolve_master_key(file: Option<&str>, env_key: Option<&str>) -> Result<String, String> {
    match (file, env_key) {
        (Some(path), _) => read_master_key_file(path, "APP_KEY_FILE"),
        (None, Some(key)) => check_master_key(key.to_string(), "APP_SECRET_KEY"),
        (None, None) => {
            Err("Clé maîtresse manquante : définir APP_SECRET_KEY ou APP_KEY_FILE".into())
        }
    }
}

/// Reads a master key from a file (surrounding spaces and line breaks ignored) and checks it.
pub fn read_master_key_file(path: &str, source: &str) -> Result<String, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Lecture de {source} impossible ({path}) : {e}"))?;
    check_master_key(content.trim().to_string(), source)
}

pub fn check_master_key(key: String, source: &str) -> Result<String, String> {
    // Hex only: a random key, not a passphrase (HKDF is fast, a weak phrase could be guessed)
    if key.len() < MASTER_KEY_MIN_HEX || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "Clé maîtresse invalide dans {source} : il faut au moins {MASTER_KEY_MIN_HEX} \
             caractères hexadécimaux (générer avec : openssl rand -hex 64)"
        ));
    }
    Ok(key)
}

fn require(key: &str) -> Result<String, String> {
    env::var(key).map_err(|_| format!("Variable d'environnement manquante : {key}"))
}

fn optional_i64(key: &str, default: i64) -> i64 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn temp_file(name: &str, content: &str) -> String {
        let path = std::env::temp_dir().join(format!("clea-test-{}-{name}", std::process::id()));
        std::fs::write(&path, content).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn reads_the_environment_key() {
        assert_eq!(resolve_master_key(None, Some(KEY)).unwrap(), KEY);
    }

    #[test]
    fn file_wins_over_environment_and_is_trimmed() {
        let path = temp_file("trim", &format!("{KEY}\n"));
        let other = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        assert_eq!(resolve_master_key(Some(&path), Some(other)).unwrap(), KEY);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn refuses_missing_short_or_unreadable_keys_without_leaking_them() {
        assert!(resolve_master_key(None, None).is_err());
        let err = resolve_master_key(None, Some("short-secret")).unwrap_err();
        assert!(err.contains("64") && !err.contains("short-secret"));
        // Long enough but not hex: a passphrase is refused
        let phrase = "correct horse battery staple correct horse battery staple 1234";
        assert!(resolve_master_key(None, Some(phrase)).is_err());
        let path = temp_file("short", "tiny\n");
        assert!(resolve_master_key(Some(&path), None).is_err());
        std::fs::remove_file(path).ok();
        assert!(resolve_master_key(Some("/nonexistent/clea-key"), None).is_err());
    }
}
