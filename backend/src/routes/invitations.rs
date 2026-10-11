use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Algorithm, Argon2, Params, Version,
};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use rand::{rng, RngCore};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    audit,
    error::AppError,
    session::{hash_token, AuthSession},
    state::AppState,
};

#[derive(Deserialize)]
pub struct CheckQuery {
    pub token: String,
}

pub async fn check(
    State(state): State<AppState>,
    Query(q): Query<CheckQuery>,
) -> Result<StatusCode, AppError> {
    let token_hash = hash_token(&q.token);
    let valid: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM invitations WHERE token_hash = $1 AND expires_at > now() AND accepted_at IS NULL)",
    )
    .bind(&token_hash)
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    if valid {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::BadRequest(
            "Invitation invalide ou expirée".into(),
        ))
    }
}

#[derive(Deserialize)]
pub struct InvitePayload {
    pub email: String,
    pub role: String,
    pub username: String,
}

#[derive(Serialize)]
pub struct InviteResponse {
    pub token: String,
}

pub async fn create(
    session: AuthSession,
    State(state): State<AppState>,
    Json(payload): Json<InvitePayload>,
) -> Result<Json<InviteResponse>, AppError> {
    if session.role == "member" {
        return Err(AppError::Unauthorized("Accès refusé".into()));
    }
    if !["admin", "member"].contains(&payload.role.as_str()) {
        return Err(AppError::BadRequest("Rôle invalide".into()));
    }
    if !payload.email.contains('@') {
        return Err(AppError::BadRequest("Email invalide".into()));
    }
    let username = payload.username.trim().to_string();
    if username.is_empty() || username.len() > 50 {
        return Err(AppError::BadRequest("Nom d'utilisateur invalide".into()));
    }
    // Check username not already taken
    let username_taken: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)")
            .bind(&username)
            .fetch_one(&state.db)
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?;
    if username_taken {
        return Err(AppError::Conflict(
            "Ce nom d'utilisateur est déjà pris".into(),
        ));
    }

    // Check user doesn't already exist
    let exists = sqlx::query("SELECT 1 FROM users WHERE email = $1")
        .bind(payload.email.trim().to_lowercase().as_str())
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    if exists.is_some() {
        return Err(AppError::Conflict("Cet email est déjà utilisé".into()));
    }

    let mut bytes = [0u8; 32];
    rng().fill_bytes(&mut bytes);
    let token: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let token_hash = hash_token(&token);

    let expires_at =
        OffsetDateTime::now_utc() + time::Duration::hours(state.config.invitation_duration_hours);

    sqlx::query(
        "INSERT INTO invitations (id, organization_id, invited_by, email, role, token_hash, expires_at, username)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(Uuid::new_v4())
    .bind(session.org_id)
    .bind(session.user_id)
    .bind(payload.email.trim().to_lowercase())
    .bind(&payload.role)
    .bind(&token_hash)
    .bind(expires_at)
    .bind(&username)
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    audit::log(
        &state.db,
        Some(session.org_id),
        Some(session.user_id),
        "invitation.create",
        Some("invitation"),
        None,
    )
    .await;

    Ok(Json(InviteResponse { token }))
}

#[derive(Deserialize)]
pub struct AcceptPayload {
    pub token: String,
    pub password: String,
}

pub async fn accept(
    State(state): State<AppState>,
    Json(payload): Json<AcceptPayload>,
) -> Result<StatusCode, AppError> {
    if payload.password.len() < 12 {
        return Err(AppError::BadRequest(
            "Mot de passe trop court (12 caractères minimum)".into(),
        ));
    }

    let token_hash = hash_token(&payload.token);

    let row = sqlx::query(
        "SELECT id, organization_id, email, role, username FROM invitations
         WHERE token_hash = $1
           AND expires_at > now()
           AND accepted_at IS NULL",
    )
    .bind(&token_hash)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .ok_or_else(|| AppError::BadRequest("Invitation invalide ou expirée".into()))?;

    let inv_id: Uuid = row.get("id");
    let org_id: Uuid = row.get("organization_id");
    let email: String = row.get("email");
    let role: String = row.get("role");
    let username: Option<String> = row.get("username");

    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(19456, 2, 1, None).map_err(|e| AppError::Internal(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let password_hash = argon2
        .hash_password(payload.password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .to_string();

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    sqlx::query(
        "INSERT INTO users (id, organization_id, email, password_hash, role, is_active, username)
         VALUES ($1, $2, $3, $4, $5, TRUE, $6)",
    )
    .bind(Uuid::new_v4())
    .bind(org_id)
    .bind(&email)
    .bind(&password_hash)
    .bind(&role)
    .bind(username.as_deref())
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    sqlx::query("UPDATE invitations SET accepted_at = now() WHERE id = $1")
        .bind(inv_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    audit::log(
        &state.db,
        Some(org_id),
        None,
        "invitation.accept",
        Some("user"),
        None,
    )
    .await;

    Ok(StatusCode::CREATED)
}
