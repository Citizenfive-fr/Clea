use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    Json,
};
use rand::{rng, Rng};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;
use std::net::SocketAddr;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::{
    audit, crypto,
    error::AppError,
    password,
    ratelimit::{ban_error, client_key},
    routes::auth::create_session,
    session::{hash_token, random_token, AuthSession},
    state::AppState,
};

/// POST /api/auth/2fa/setup
/// Generates a TOTP secret, saves it (not yet enabled), returns QR + secret for the UI.
pub async fn setup(
    session: AuthSession,
    State(state): State<AppState>,
) -> Result<Json<Value>, AppError> {
    let mut raw = [0u8; 20];
    rng().fill_bytes(&mut raw);

    let secret_b32 = match totp_rs::Secret::Raw(raw.to_vec()).to_encoded() {
        totp_rs::Secret::Encoded(s) => s,
        _ => return Err(AppError::Internal("TOTP encoding failed".into())),
    };

    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        raw.to_vec(),
        Some("Cléa".to_string()),
        session.email.clone(),
    )
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let url = totp.get_url();
    let qr = totp
        .get_qr_base64()
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let stored_secret = crypto::encrypt(
        &state.config.app_secret_key,
        session.user_id.as_bytes(),
        &secret_b32,
    )?;

    // Never replace the secret of an account whose 2FA is already active:
    // the user must disable it first (which requires the password).
    let updated = sqlx::query(
        "UPDATE users SET totp_secret = $1, totp_last_step = NULL
         WHERE id = $2 AND totp_enabled = FALSE",
    )
    .bind(&stored_secret)
    .bind(session.user_id)
    .execute(&state.db)
    .await?
    .rows_affected();
    if updated == 0 {
        return Err(AppError::Conflict(
            "Le 2FA est déjà activé. Désactive-le d'abord avec ton mot de passe.".into(),
        ));
    }

    Ok(Json(json!({ "secret": secret_b32, "qr": qr, "url": url })))
}

#[derive(Deserialize)]
pub struct ConfirmPayload {
    pub code: String,
}

/// POST /api/auth/2fa/confirm
/// Verifies a TOTP code and activates 2FA for the user.
pub async fn confirm(
    session: AuthSession,
    State(state): State<AppState>,
    Json(payload): Json<ConfirmPayload>,
) -> Result<StatusCode, AppError> {
    let row = sqlx::query("SELECT totp_secret FROM users WHERE id = $1")
        .bind(session.user_id)
        .fetch_one(&state.db)
        .await?;

    let secret_b32: Option<String> = row.try_get("totp_secret").ok().flatten();
    let secret_b32 = secret_b32.ok_or_else(|| AppError::BadRequest("2FA non initialisé".into()))?;
    let secret_b32 = crypto::decrypt(
        &state.config.app_secret_key,
        session.user_id.as_bytes(),
        &secret_b32,
    )?;

    let step = matching_step(&secret_b32, &session.email, &payload.code)?
        .ok_or_else(|| AppError::Unauthorized("Code incorrect".into()))?;

    // Store the step so this same code cannot be reused at the next login
    sqlx::query("UPDATE users SET totp_enabled = TRUE, totp_last_step = $2 WHERE id = $1")
        .bind(session.user_id)
        .bind(step)
        .execute(&state.db)
        .await?;

    audit::log(
        &state.db,
        Some(session.org_id),
        Some(session.user_id),
        "auth.2fa_enabled",
        None,
        None,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct DisablePayload {
    pub password: String,
}

/// POST /api/auth/2fa/disable
/// Requires current password. Clears secret and disables 2FA.
pub async fn disable(
    session: AuthSession,
    State(state): State<AppState>,
    Json(payload): Json<DisablePayload>,
) -> Result<StatusCode, AppError> {
    let limit_key = session.user_id.to_string();
    state.reauth_limiter.check(&limit_key).map_err(ban_error)?;

    let row = sqlx::query("SELECT password_hash FROM users WHERE id = $1")
        .bind(session.user_id)
        .fetch_one(&state.db)
        .await?;

    let hash: String = row.get("password_hash");
    if !password::verify(&state, payload.password.clone(), Some(hash)).await? {
        state.reauth_limiter.record_failure(&limit_key);
        return Err(AppError::Unauthorized("Mot de passe incorrect".into()));
    }

    sqlx::query(
        "UPDATE users SET totp_enabled = FALSE, totp_secret = NULL, totp_last_step = NULL
         WHERE id = $1",
    )
    .bind(session.user_id)
    .execute(&state.db)
    .await?;

    audit::log(
        &state.db,
        Some(session.org_id),
        Some(session.user_id),
        "auth.2fa_disabled",
        None,
        None,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct VerifyPayload {
    pub pending_token: String,
    pub code: String,
}

/// POST /api/auth/2fa/verify
/// Second step of login: validates TOTP code against a pending token, then creates a session.
pub async fn verify(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req_headers: HeaderMap,
    Json(payload): Json<VerifyPayload>,
) -> Result<Response, AppError> {
    // Same IP limiter as the login: failed codes here count towards the IP ban
    let ip_key = client_key(&req_headers, peer, state.config.trust_proxy);
    state.login_ip_limiter.check(&ip_key).map_err(ban_error)?;

    let token_hash = hash_token(&payload.pending_token);

    let user_id = {
        let mut pending = state.pending_2fa.lock().unwrap();
        match pending.get_mut(&token_hash) {
            None => {
                drop(pending);
                state.login_ip_limiter.record_failure(&ip_key);
                return Err(AppError::Unauthorized("Token expiré ou invalide".into()));
            }
            Some((_, created, _)) if created.elapsed() >= std::time::Duration::from_secs(300) => {
                pending.remove(&token_hash);
                return Err(AppError::Unauthorized("Token expiré".into()));
            }
            Some((_, _, attempts)) if *attempts >= 5 => {
                pending.remove(&token_hash);
                return Err(AppError::TooManyRequests("Trop de tentatives.".into()));
            }
            Some((uid, _, attempts)) => {
                *attempts += 1;
                *uid
            }
        }
    };

    let row = sqlx::query(
        "SELECT email, organization_id, role, totp_secret
         FROM users WHERE id = $1 AND is_active = TRUE",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::Unauthorized("Utilisateur introuvable".into()))?;

    let email: String = row.get("email");
    let org_id: Uuid = row.get("organization_id");
    let role: String = row.get("role");
    let secret_b32: Option<String> = row.try_get("totp_secret").ok().flatten();
    let secret_b32 = secret_b32.ok_or_else(|| AppError::Internal("2FA secret manquant".into()))?;
    let secret_b32 = crypto::decrypt(
        &state.config.app_secret_key,
        user_id.as_bytes(),
        &secret_b32,
    )?;

    // Per-user ban: applies across logins and pending tokens, and grows on repeat
    let user_key = user_id.to_string();
    state
        .totp_user_limiter
        .check(&user_key)
        .map_err(ban_error)?;

    let Some(step) = matching_step(&secret_b32, &email, &payload.code)? else {
        state.totp_user_limiter.record_failure(&user_key);
        state.login_ip_limiter.record_failure(&ip_key);
        return Err(AppError::Unauthorized("Code 2FA incorrect".into()));
    };

    // Atomic anti-replay: only accept a step newer than the last one used
    let accepted = sqlx::query(
        "UPDATE users SET totp_last_step = $2
         WHERE id = $1 AND (totp_last_step IS NULL OR totp_last_step < $2)",
    )
    .bind(user_id)
    .bind(step)
    .execute(&state.db)
    .await?
    .rows_affected();
    if accepted == 0 {
        return Err(AppError::Unauthorized("Code 2FA déjà utilisé".into()));
    }

    // Consume the pending token — one-time use
    state.pending_2fa.lock().unwrap().remove(&token_hash);
    state.totp_user_limiter.clear_failures(&user_key);

    create_session(&state, user_id, org_id, role, "auth.login_2fa").await
}

/// Stores a pending 2FA token in memory. Returns the plaintext token to send to the client.
pub fn create_pending_token(state: &AppState, user_id: Uuid) -> String {
    let token = random_token();
    let token_hash = hash_token(&token);
    state
        .pending_2fa
        .lock()
        .unwrap()
        .insert(token_hash, (user_id, Instant::now(), 0u8));
    token
}

/// Returns the time step (30 s units) matching the code, tolerating ±1 step of clock skew.
/// The step is returned so callers can reject replays of an already used code.
fn matching_step(secret_b32: &str, email: &str, code: &str) -> Result<Option<i64>, AppError> {
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(None);
    }

    let secret_bytes = totp_rs::Secret::Encoded(secret_b32.to_string())
        .to_bytes()
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some("Cléa".to_string()),
        email.to_string(),
    )
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .as_secs() as i64;
    let current_step = now / 30;

    // Check every candidate (no early exit) to keep timing independent of the match
    let mut found = None;
    for step in (current_step - 1)..=(current_step + 1) {
        let expected = totp.generate((step * 30) as u64);
        if constant_time_eq(expected.as_bytes(), code.as_bytes()) {
            found = Some(step);
        }
    }
    Ok(found)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
