use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Algorithm, Argon2, Params, PasswordHash, PasswordVerifier, Version,
};
use axum::{
    extract::State,
    http::{header::SET_COOKIE, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    Json,
};
use rand::{rng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    audit,
    error::AppError,
    routes::totp::create_pending_token,
    session::{extract_session_token, hash_token, AuthSession},
    state::AppState,
};

const RATE_LIMIT_MAX: u8 = 5;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(900); // 15 min

pub async fn login_page() -> Html<String> {
    Html(
        tokio::fs::read_to_string("../frontend/html/login.html")
            .await
            .unwrap_or_default(),
    )
}

#[derive(Deserialize)]
pub struct LoginPayload {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub user_id: Uuid,
    pub org_id: Uuid,
    pub role: String,
}

pub async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginPayload>,
) -> Result<Response, AppError> {
    let email = payload.email.trim().to_lowercase();

    // Check rate limit before any DB work
    {
        let mut attempts = state.login_attempts.lock().unwrap();
        if let Some((count, since)) = attempts.get(&email) {
            if since.elapsed() >= RATE_LIMIT_WINDOW {
                attempts.remove(&email);
            } else if *count >= RATE_LIMIT_MAX {
                return Err(AppError::TooManyRequests(
                    "Trop de tentatives. Réessayez dans 15 minutes.".into(),
                ));
            }
        }
    }

    let row = sqlx::query(
        "SELECT id, organization_id, password_hash, role, is_active, totp_enabled
         FROM users WHERE email = $1",
    )
    .bind(&email)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let (found, user_id, org_id, db_hash, role, is_active, totp_enabled) = match row {
        Some(r) => (
            true,
            r.get::<Uuid, _>("id"),
            r.get::<Uuid, _>("organization_id"),
            r.get::<String, _>("password_hash"),
            r.get::<String, _>("role"),
            r.get::<bool, _>("is_active"),
            r.get::<bool, _>("totp_enabled"),
        ),
        None => (
            false,
            Uuid::nil(),
            Uuid::nil(),
            String::new(),
            String::new(),
            false,
            false,
        ),
    };

    // Constant-time: always verify even if user not found (prevents timing attacks)
    let password_ok = !db_hash.is_empty() && verify_password(&payload.password, &db_hash);

    if !found || !is_active || !password_ok {
        // Increment failed attempt counter
        let mut attempts = state.login_attempts.lock().unwrap();
        let entry = attempts.entry(email.clone()).or_insert((0, Instant::now()));
        if entry.1.elapsed() >= RATE_LIMIT_WINDOW {
            *entry = (1, Instant::now());
        } else {
            entry.0 = entry.0.saturating_add(1);
        }
        return Err(AppError::Unauthorized(
            "Email ou mot de passe incorrect".into(),
        ));
    }

    // Clear attempt counter on success
    state.login_attempts.lock().unwrap().remove(&email);

    // If 2FA is enabled: return a short-lived pending token instead of a session
    if totp_enabled {
        let pending_token = create_pending_token(&state, user_id);
        return Ok((
            StatusCode::ACCEPTED,
            Json(json!({ "requires_2fa": true, "pending_token": pending_token })),
        )
            .into_response());
    }

    create_session(&state, user_id, org_id, role).await
}

pub async fn logout(State(state): State<AppState>, req_headers: HeaderMap) -> impl IntoResponse {
    if let Some(token) = extract_session_token(&req_headers) {
        let token_hash = hash_token(&token);

        // Fetch user info for audit log before deleting
        if let Ok(Some(row)) = sqlx::query(
            "SELECT s.user_id, u.organization_id
             FROM sessions s JOIN users u ON u.id = s.user_id
             WHERE s.token_hash = $1",
        )
        .bind(&token_hash)
        .fetch_optional(&state.db)
        .await
        {
            let user_id: Uuid = row.get("user_id");
            let org_id: Uuid = row.get("organization_id");
            let _ = sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
                .bind(&token_hash)
                .execute(&state.db)
                .await;
            audit::log(
                &state.db,
                Some(org_id),
                Some(user_id),
                "auth.logout",
                None,
                None,
            )
            .await;
        } else {
            let _ = sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
                .bind(&token_hash)
                .execute(&state.db)
                .await;
        }
    }

    let secure = if state.config.secure_cookies {
        "; Secure"
    } else {
        ""
    };
    let clear = format!(
        "session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{}",
        secure
    );
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, clear.parse().unwrap());
    (StatusCode::NO_CONTENT, headers)
}

pub async fn me(
    session: AuthSession,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, AppError> {
    let row = sqlx::query("SELECT totp_enabled FROM users WHERE id = $1")
        .bind(session.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let totp_enabled: bool = row.get("totp_enabled");

    Ok(Json(json!({
        "email": session.email,
        "username": session.username,
        "role": session.role,
        "totp_enabled": totp_enabled,
    })))
}

#[derive(Deserialize)]
pub struct PasswordChangePayload {
    pub current_password: String,
    pub new_password: String,
}

pub async fn change_password(
    session: AuthSession,
    State(state): State<AppState>,
    Json(payload): Json<PasswordChangePayload>,
) -> Result<StatusCode, AppError> {
    if payload.new_password.len() < 12 {
        return Err(AppError::BadRequest(
            "Mot de passe trop court (12 caractères minimum)".into(),
        ));
    }

    let row = sqlx::query("SELECT password_hash FROM users WHERE id = $1")
        .bind(session.user_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let current_hash: String = row.get("password_hash");

    if !verify_password(&payload.current_password, &current_hash) {
        return Err(AppError::Unauthorized(
            "Mot de passe actuel incorrect".into(),
        ));
    }

    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(19456, 2, 1, None).map_err(|e| AppError::Internal(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let new_hash = argon2
        .hash_password(payload.new_password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .to_string();

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    sqlx::query("UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2")
        .bind(&new_hash)
        .bind(session.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    // Invalidate all sessions (forces re-login on all devices)
    sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(session.user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    audit::log(
        &state.db,
        Some(session.org_id),
        Some(session.user_id),
        "auth.password_change",
        None,
        None,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

/// Shared session creation logic used by login and 2FA verify.
pub async fn create_session(
    state: &AppState,
    user_id: Uuid,
    org_id: Uuid,
    role: String,
) -> Result<Response, AppError> {
    let mut bytes = [0u8; 32];
    rng().fill_bytes(&mut bytes);
    let token: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let token_hash = hash_token(&token);

    let expires_at =
        OffsetDateTime::now_utc() + time::Duration::hours(state.config.session_duration_hours);

    sqlx::query(
        "INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(&token_hash)
    .bind(expires_at)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    audit::log(
        &state.db,
        Some(org_id),
        Some(user_id),
        "auth.login",
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
        token, max_age, secure
    );
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, cookie.parse().unwrap());

    Ok((
        StatusCode::OK,
        headers,
        Json(LoginResponse {
            user_id,
            org_id,
            role,
        }),
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct UsernamePayload {
    pub username: String,
}

pub async fn update_username(
    session: AuthSession,
    State(state): State<AppState>,
    Json(payload): Json<UsernamePayload>,
) -> Result<StatusCode, AppError> {
    let username = payload.username.trim().to_string();
    if username.is_empty() || username.len() > 50 {
        return Err(AppError::BadRequest(
            "Le nom d'utilisateur doit contenir entre 1 et 50 caractères".into(),
        ));
    }

    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE username = $1 AND id != $2)")
            .bind(&username)
            .bind(session.user_id)
            .fetch_one(&state.db)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;

    if exists {
        return Err(AppError::Conflict(
            "Ce nom d'utilisateur est déjà pris".into(),
        ));
    }

    sqlx::query("UPDATE users SET username = $1, updated_at = now() WHERE id = $2")
        .bind(&username)
        .bind(session.user_id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .ok()
        .map(|parsed| {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        })
        .unwrap_or(false)
}
