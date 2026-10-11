use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;
use std::net::SocketAddr;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    audit,
    error::AppError,
    password,
    ratelimit::{ban_error, client_key},
    routes::totp::create_pending_token,
    session::{cookie_headers, extract_session_token, hash_token, random_token, AuthSession},
    state::AppState,
    validation,
};

pub async fn login_page() -> Response {
    crate::routes::app::html_page("login.html", false).await
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
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<LoginPayload>,
) -> Result<Response, AppError> {
    let email = payload.email.trim().to_lowercase();
    let ip_key = client_key(&headers, peer, state.config.trust_proxy);

    // Check rate limits before any DB work
    let banned = state
        .login_ip_limiter
        .check(&ip_key)
        .and(state.login_email_limiter.check(&email));
    if let Err(remaining) = banned {
        return Err(ban_error(remaining));
    }

    let row = sqlx::query(
        "SELECT id, organization_id, password_hash, role, is_active, totp_enabled
         FROM users WHERE email = $1",
    )
    .bind(&email)
    .fetch_optional(&state.db)
    .await?;

    let (found, user_id, org_id, db_hash, role, is_active, totp_enabled) = match row {
        Some(r) => (
            true,
            r.get::<Uuid, _>("id"),
            r.get::<Uuid, _>("organization_id"),
            Some(r.get::<String, _>("password_hash")),
            r.get::<String, _>("role"),
            r.get::<bool, _>("is_active"),
            r.get::<bool, _>("totp_enabled"),
        ),
        None => (
            false,
            Uuid::nil(),
            Uuid::nil(),
            None,
            String::new(),
            false,
            false,
        ),
    };

    // Unknown user: verified against a dummy hash, so timing does not reveal accounts
    let password_ok = password::verify(&state, payload.password.clone(), db_hash).await?;

    if !found || !is_active || !password_ok {
        state.login_ip_limiter.record_failure(&ip_key);
        state.login_email_limiter.record_failure(&email);
        return Err(AppError::Unauthorized(
            "Email ou mot de passe incorrect".into(),
        ));
    }

    // Clear the email counter on success. The IP counter is kept on purpose:
    // otherwise an attacker owning one valid account could reset it at will.
    state.login_email_limiter.clear_failures(&email);

    // If 2FA is enabled: return a short-lived pending token instead of a session
    if totp_enabled {
        let pending_token = create_pending_token(&state, user_id);
        return Ok((
            StatusCode::ACCEPTED,
            Json(json!({ "requires_2fa": true, "pending_token": pending_token })),
        )
            .into_response());
    }

    create_session(&state, user_id, org_id, role, "auth.login").await
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

    let headers = cookie_headers(state.config.secure_cookies, "", 0);
    (StatusCode::NO_CONTENT, headers)
}

pub async fn me(
    session: AuthSession,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, AppError> {
    let row = sqlx::query("SELECT totp_enabled FROM users WHERE id = $1")
        .bind(session.user_id)
        .fetch_one(&state.db)
        .await?;

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
    validation::password(&payload.new_password)?;
    let limit_key = session.user_id.to_string();
    state.reauth_limiter.check(&limit_key).map_err(ban_error)?;

    let row = sqlx::query("SELECT password_hash FROM users WHERE id = $1")
        .bind(session.user_id)
        .fetch_one(&state.db)
        .await?;

    let current_hash: String = row.get("password_hash");

    if !password::verify(&state, payload.current_password.clone(), Some(current_hash)).await? {
        state.reauth_limiter.record_failure(&limit_key);
        return Err(AppError::Unauthorized(
            "Mot de passe actuel incorrect".into(),
        ));
    }

    let new_hash = password::hash(&state, payload.new_password.clone()).await?;

    let mut tx = state.db.begin().await?;

    sqlx::query("UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2")
        .bind(&new_hash)
        .bind(session.user_id)
        .execute(&mut *tx)
        .await?;

    // Invalidate all sessions (forces re-login on all devices)
    sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(session.user_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

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
    audit_action: &str,
) -> Result<Response, AppError> {
    let token = random_token();
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
    .await?;

    audit::log(
        &state.db,
        Some(org_id),
        Some(user_id),
        audit_action,
        None,
        None,
    )
    .await;

    let headers = cookie_headers(
        state.config.secure_cookies,
        &token,
        state.config.session_duration_hours * 3600,
    );

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
    let username = validation::username(&payload.username)?;

    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE username = $1 AND id != $2)")
            .bind(&username)
            .bind(session.user_id)
            .fetch_one(&state.db)
            .await?;

    if exists {
        return Err(AppError::Conflict(
            "Ce nom d'utilisateur est déjà pris".into(),
        ));
    }

    sqlx::query("UPDATE users SET username = $1, updated_at = now() WHERE id = $2")
        .bind(&username)
        .bind(session.user_id)
        .execute(&state.db)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}
