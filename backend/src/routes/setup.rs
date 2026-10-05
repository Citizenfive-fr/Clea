use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Algorithm, Argon2, Params, Version,
};
use axum::{extract::State, http::StatusCode, response::Html, Json};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::{error::AppError, state::AppState};

pub async fn page() -> Html<String> {
    Html(
        tokio::fs::read_to_string("../frontend/html/setup.html")
            .await
            .unwrap_or_default(),
    )
}

#[derive(Serialize)]
pub struct SetupStatus {
    pub completed: bool,
}

pub async fn status(State(state): State<AppState>) -> Result<Json<SetupStatus>, AppError> {
    let row = sqlx::query("SELECT completed FROM setup_state WHERE id = 1")
        .fetch_one(&state.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(SetupStatus {
        completed: row.get("completed"),
    }))
}

#[derive(Deserialize)]
pub struct SetupPayload {
    pub org_name: String,
    pub username: String,
    pub email: String,
    pub password: String,
}

pub async fn complete(
    State(state): State<AppState>,
    Json(payload): Json<SetupPayload>,
) -> Result<StatusCode, AppError> {
    let row = sqlx::query("SELECT completed FROM setup_state WHERE id = 1")
        .fetch_one(&state.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    if row.get::<bool, _>("completed") {
        return Err(AppError::Conflict("Setup déjà effectué".into()));
    }

    if payload.org_name.trim().is_empty() {
        return Err(AppError::BadRequest("Nom d'organisation requis".into()));
    }
    let username = payload.username.trim().to_string();
    if username.is_empty() || username.len() > 50 {
        return Err(AppError::BadRequest("Nom d'utilisateur invalide".into()));
    }
    if !is_valid_email(&payload.email) {
        return Err(AppError::BadRequest("Email invalide".into()));
    }
    if payload.password.len() < 12 {
        return Err(AppError::BadRequest(
            "Mot de passe trop court (12 caractères minimum)".into(),
        ));
    }

    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(19456, 2, 1, None).map_err(|e| AppError::Internal(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let password_hash = argon2
        .hash_password(payload.password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .to_string();

    let org_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let slug = slugify(&payload.org_name);
    let email = payload.email.trim().to_lowercase();

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    sqlx::query("INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $3)")
        .bind(org_id)
        .bind(payload.org_name.trim())
        .bind(slug)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    sqlx::query(
        "INSERT INTO users (id, organization_id, email, password_hash, role, is_active, username)
         VALUES ($1, $2, $3, $4, 'owner', TRUE, $5)",
    )
    .bind(user_id)
    .bind(org_id)
    .bind(email)
    .bind(password_hash)
    .bind(username)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    sqlx::query("UPDATE setup_state SET completed = TRUE, completed_at = now() WHERE id = 1")
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(StatusCode::CREATED)
}

fn is_valid_email(email: &str) -> bool {
    let parts: Vec<&str> = email.splitn(2, '@').collect();
    parts.len() == 2 && !parts[0].is_empty() && parts[1].contains('.')
}

fn slugify(name: &str) -> String {
    let raw: String = name
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    raw.split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}
