use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    extract::State,
    http::{header::SET_COOKIE, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use rand::{rng, RngCore};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;
use std::time::Instant;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    audit,
    error::AppError,
    session::{hash_token, AuthSession},
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

    sqlx::query("UPDATE users SET totp_secret = $1 WHERE id = $2")
        .bind(&secret_b32)
        .bind(session.user_id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

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
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let secret_b32: Option<String> = row.try_get("totp_secret").ok().flatten();
    let secret_b32 = secret_b32.ok_or_else(|| AppError::BadRequest("2FA non initialisé".into()))?;

    if !verify_totp_code(&secret_b32, &session.email, &payload.code)? {
        return Err(AppError::Unauthorized("Code incorrect".into()));
    }

    sqlx::query("UPDATE users SET totp_enabled = TRUE WHERE id = $1")
        .bind(session.user_id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

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
    let row = sqlx::query("SELECT password_hash FROM users WHERE id = $1")
        .bind(session.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let hash: String = row.get("password_hash");
    if !verify_argon2(&payload.password, &hash) {
        return Err(AppError::Unauthorized("Mot de passe incorrect".into()));
    }

    sqlx::query("UPDATE users SET totp_enabled = FALSE, totp_secret = NULL WHERE id = $1")
        .bind(session.user_id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

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
    Json(payload): Json<VerifyPayload>,
) -> Result<Response, AppError> {
    let token_hash = hash_token(&payload.pending_token);

    let user_id = {
        let mut pending = state.pending_2fa.lock().unwrap();
        match pending.get_mut(&token_hash) {
            None => return Err(AppError::Unauthorized("Token expiré ou invalide".into())),
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
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .ok_or_else(|| AppError::Unauthorized("Utilisateur introuvable".into()))?;

    let email: String = row.get("email");
    let org_id: Uuid = row.get("organization_id");
    let role: String = row.get("role");
    let secret_b32: Option<String> = row.try_get("totp_secret").ok().flatten();
    let secret_b32 = secret_b32.ok_or_else(|| AppError::Internal("2FA secret manquant".into()))?;

    if !verify_totp_code(&secret_b32, &email, &payload.code)? {
        return Err(AppError::Unauthorized("Code 2FA incorrect".into()));
    }

    // Consume the pending token — one-time use
    state.pending_2fa.lock().unwrap().remove(&token_hash);

    let mut bytes = [0u8; 32];
    rng().fill_bytes(&mut bytes);
    let session_token: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let session_token_hash = hash_token(&session_token);

    let expires_at =
        OffsetDateTime::now_utc() + time::Duration::hours(state.config.session_duration_hours);

    sqlx::query(
        "INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(&session_token_hash)
    .bind(expires_at)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    audit::log(
        &state.db,
        Some(org_id),
        Some(user_id),
        "auth.login_2fa",
        None,
        None,
    )
    .await;

    let max_age = state.config.session_duration_hours * 3600;
    let secure = if state.config.secure_cookies {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "session={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
        session_token, max_age, secure
    );
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, cookie.parse().unwrap());

    Ok((
        StatusCode::OK,
        headers,
        Json(json!({ "user_id": user_id, "org_id": org_id, "role": role })),
    )
        .into_response())
}

/// Stores a pending 2FA token in memory. Returns the plaintext token to send to the client.
pub fn create_pending_token(state: &AppState, user_id: Uuid) -> String {
    let mut raw = [0u8; 32];
    rng().fill_bytes(&mut raw);
    let token: String = raw.iter().map(|b| format!("{:02x}", b)).collect();
    let token_hash = hash_token(&token);
    state
        .pending_2fa
        .lock()
        .unwrap()
        .insert(token_hash, (user_id, Instant::now(), 0u8));
    token
}

fn verify_totp_code(secret_b32: &str, email: &str, code: &str) -> Result<bool, AppError> {
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

    totp.check_current(code)
        .map_err(|e| AppError::Internal(e.to_string()))
}

fn verify_argon2(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .ok()
        .map(|h| {
            Argon2::default()
                .verify_password(password.as_bytes(), &h)
                .is_ok()
        })
        .unwrap_or(false)
}
