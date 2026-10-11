use crate::{config::Config, password, ratelimit::RateLimiter, routes::news::NewsItem};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use uuid::Uuid;

const FIFTEEN_MIN: Duration = Duration::from_secs(900);
const MAX_BAN: Duration = Duration::from_secs(24 * 3600);

type NewsCache = Arc<Mutex<HashMap<String, (Instant, Vec<NewsItem>)>>>;
type Pending2faStore = Arc<Mutex<HashMap<String, (Uuid, Instant, u8)>>>;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Arc<Config>,
    /// Failed logins per client IP (all emails): temporary ban, longer on each repeat
    pub login_ip_limiter: Arc<RateLimiter>,
    /// Failed logins per email, higher threshold: backstop against attacks spread over many IPs
    pub login_email_limiter: Arc<RateLimiter>,
    /// Failed 2FA codes per user (5 per 15 min), escalating bans
    pub totp_user_limiter: Arc<RateLimiter>,
    /// Failed password re-checks of a logged-in user (password change, 2FA disable)
    pub reauth_limiter: Arc<RateLimiter>,
    /// Outbound HTTP client (RSS feeds only)
    pub http: reqwest::Client,
    /// Last fetched items per feed source (name -> fetch time, items), see routes/news.rs
    pub news_cache: NewsCache,
    /// Bounds concurrent Argon2 operations (memory and CPU heavy)
    pub hash_permits: Arc<Semaphore>,
    /// Valid hash of a random password, checked when the user does not exist (login timing)
    pub dummy_hash: Arc<String>,
    /// (user_id, created_at, attempt_count) keyed by hashed pending token — expires after 5 min
    pub pending_2fa: Pending2faStore,
}

impl AppState {
    pub fn new(db: PgPool, config: Config) -> Self {
        let permits = std::thread::available_parallelism().map_or(2, |n| n.get());
        let dummy_hash = password::hash_sync(&Uuid::new_v4().to_string())
            .expect("Argon2 dummy hash generation failed");
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::limited(3))
                .user_agent("Clea/0.1 RGPD compliance tool")
                .build()
                .expect("HTTP client creation failed"),
            news_cache: Arc::new(Mutex::new(HashMap::new())),
            hash_permits: Arc::new(Semaphore::new(permits)),
            dummy_hash: Arc::new(dummy_hash),
            db,
            config: Arc::new(config),
            login_ip_limiter: Arc::new(RateLimiter::new(20, FIFTEEN_MIN, FIFTEEN_MIN, MAX_BAN)),
            reauth_limiter: Arc::new(RateLimiter::new(5, FIFTEEN_MIN, FIFTEEN_MIN, MAX_BAN)),
            totp_user_limiter: Arc::new(RateLimiter::new(5, FIFTEEN_MIN, FIFTEEN_MIN, MAX_BAN)),
            login_email_limiter: Arc::new(RateLimiter::new(50, FIFTEEN_MIN, FIFTEEN_MIN, MAX_BAN)),
            pending_2fa: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}
