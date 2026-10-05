use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Serialize;
use sqlx::Row;
use uuid::Uuid;

use crate::{audit, error::AppError, session::AuthSession, state::AppState};

#[derive(Serialize)]
pub struct UserEntry {
    pub id: Uuid,
    pub email: String,
    pub role: String,
    pub is_active: bool,
}

pub async fn list(
    session: AuthSession,
    State(state): State<AppState>,
) -> Result<Json<Vec<UserEntry>>, AppError> {
    if session.role == "member" {
        return Err(AppError::Unauthorized("Accès refusé".into()));
    }

    let rows = sqlx::query(
        "SELECT id, email, role, is_active FROM users
         WHERE organization_id = $1 ORDER BY created_at",
    )
    .bind(session.org_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(
        rows.iter()
            .map(|r| UserEntry {
                id: r.get("id"),
                email: r.get("email"),
                role: r.get("role"),
                is_active: r.get("is_active"),
            })
            .collect(),
    ))
}

pub async fn delete(
    session: AuthSession,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    if session.role == "member" {
        return Err(AppError::Unauthorized("Accès refusé".into()));
    }
    if session.user_id == user_id {
        return Err(AppError::BadRequest(
            "Impossible de supprimer votre propre compte".into(),
        ));
    }

    let row = sqlx::query("SELECT role FROM users WHERE id = $1 AND organization_id = $2")
        .bind(user_id)
        .bind(session.org_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Utilisateur introuvable".into()))?;

    let target_role: String = row.get("role");

    // Admin can only delete members
    if session.role == "admin" && target_role != "member" {
        return Err(AppError::Unauthorized(
            "Un admin ne peut supprimer que des membres".into(),
        ));
    }

    sqlx::query("DELETE FROM users WHERE id = $1 AND organization_id = $2")
        .bind(user_id)
        .bind(session.org_id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    audit::log(
        &state.db,
        Some(session.org_id),
        Some(session.user_id),
        "user.delete",
        Some("user"),
        Some(user_id),
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn logout_sessions(
    session: AuthSession,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    if session.user_id == user_id {
        return Err(AppError::BadRequest(
            "Utilisez /api/auth/logout pour vous déconnecter vous-même".into(),
        ));
    }

    let row = sqlx::query("SELECT role FROM users WHERE id = $1 AND organization_id = $2")
        .bind(user_id)
        .bind(session.org_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Utilisateur introuvable".into()))?;

    let target_role: String = row.get("role");

    match session.role.as_str() {
        "owner" => {}
        "admin" if target_role == "member" => {}
        _ => return Err(AppError::Unauthorized("Accès refusé".into())),
    }

    sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(user_id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    audit::log(
        &state.db,
        Some(session.org_id),
        Some(session.user_id),
        "user.logout_sessions",
        Some("user"),
        Some(user_id),
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}
