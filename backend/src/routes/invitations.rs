use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    audit,
    error::AppError,
    password,
    session::{hash_token, random_token, AuthSession},
    state::AppState,
    validation,
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
    .await?;

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
        return Err(AppError::Forbidden("Accès refusé".into()));
    }
    if !["admin", "member"].contains(&payload.role.as_str()) {
        return Err(AppError::BadRequest("Rôle invalide".into()));
    }
    // Least privilege: only the owner can create admins
    if payload.role == "admin" && session.role != "owner" {
        return Err(AppError::Forbidden(
            "Seul le propriétaire peut inviter un admin".into(),
        ));
    }
    let email = validation::email(&payload.email)?;
    let username = validation::username(&payload.username)?;
    // Check username not already taken
    let username_taken: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)")
            .bind(&username)
            .fetch_one(&state.db)
            .await?;
    if username_taken {
        return Err(AppError::Conflict(
            "Ce nom d'utilisateur est déjà pris".into(),
        ));
    }

    // Check user doesn't already exist
    let exists = sqlx::query("SELECT 1 FROM users WHERE email = $1")
        .bind(&email)
        .fetch_optional(&state.db)
        .await?;
    if exists.is_some() {
        return Err(AppError::Conflict("Cet email est déjà utilisé".into()));
    }

    let token = random_token();
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
    .bind(&email)
    .bind(&payload.role)
    .bind(&token_hash)
    .bind(expires_at)
    .bind(&username)
    .execute(&state.db)
    .await?;

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
    validation::password(&payload.password)?;

    let token_hash = hash_token(&payload.token);

    let row = sqlx::query(
        "SELECT id, organization_id, email, role, username FROM invitations
         WHERE token_hash = $1
           AND expires_at > now()
           AND accepted_at IS NULL",
    )
    .bind(&token_hash)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::BadRequest("Invitation invalide ou expirée".into()))?;

    let inv_id: Uuid = row.get("id");
    let org_id: Uuid = row.get("organization_id");
    let email: String = row.get("email");
    let role: String = row.get("role");
    let username: Option<String> = row.get("username");

    let password_hash = password::hash(&state, payload.password.clone()).await?;

    let mut tx = state.db.begin().await?;

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
    .await?;

    sqlx::query("UPDATE invitations SET accepted_at = now() WHERE id = $1")
        .bind(inv_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

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
