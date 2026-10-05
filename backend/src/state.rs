use crate::config::Config;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use uuid::Uuid;

type Pending2faStore = Arc<Mutex<HashMap<String, (Uuid, Instant, u8)>>>;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Arc<Config>,
    /// (attempt_count, window_start) keyed by email — resets after 15 min
    pub login_attempts: Arc<Mutex<HashMap<String, (u8, Instant)>>>,
    /// (user_id, created_at, attempt_count) keyed by hashed pending token — expires after 5 min
    pub pending_2fa: Pending2faStore,
}

impl AppState {
    pub fn new(db: PgPool, config: Config) -> Self {
        Self {
            db,
            config: Arc::new(config),
            login_attempts: Arc::new(Mutex::new(HashMap::new())),
            pending_2fa: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}
