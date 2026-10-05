use std::env;

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    #[allow(dead_code)]
    pub app_secret_key: String,
    pub session_duration_hours: i64,
    pub invitation_duration_hours: i64,
    pub secure_cookies: bool,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Ok(Self {
            database_url: require("DATABASE_URL")?,
            app_secret_key: require("APP_SECRET_KEY")?,
            session_duration_hours: optional_i64("SESSION_DURATION_HOURS", 24),
            invitation_duration_hours: optional_i64("INVITATION_DURATION_HOURS", 72),
            secure_cookies: std::env::var("SECURE_COOKIES").as_deref() == Ok("true"),
        })
    }
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
