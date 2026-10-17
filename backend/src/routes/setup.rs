use axum::{extract::State, http::StatusCode, response::Response, Json};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::{error::AppError, keys, password, recovery, state::AppState, validation};

pub async fn page() -> Response {
    crate::routes::app::html_page("setup.html", false).await
}

#[derive(Serialize)]
pub struct SetupStatus {
    pub completed: bool,
}

pub async fn status(State(state): State<AppState>) -> Result<Json<SetupStatus>, AppError> {
    let row = sqlx::query("SELECT completed FROM setup_state WHERE id = 1")
        .fetch_one(&state.db)
        .await?;

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
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    let row = sqlx::query("SELECT completed FROM setup_state WHERE id = 1")
        .fetch_one(&state.db)
        .await?;

    if row.get::<bool, _>("completed") {
        return Err(AppError::Conflict("Setup déjà effectué".into()));
    }

    if payload.org_name.trim().is_empty() {
        return Err(AppError::BadRequest("Nom d'organisation requis".into()));
    }
    let username = validation::username(&payload.username)?;
    let email = validation::email(&payload.email)?;
    validation::password(&payload.password)?;

    let password_hash = password::hash(&state, payload.password.clone()).await?;

    let org_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let slug = Some(slugify(&payload.org_name))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "organisation".to_string());

    let mut tx = state.db.begin().await?;

    // Each organization gets its own data key, stored locked by the master key
    let org_key = keys::OrgKey::generate();
    let locked_key = keys::lock_org_key(&state.config.master_key, org_id, &org_key)?;
    // Recovery key pair: the organization key is also locked for its public part,
    // the secret part is returned once to the owner and never stored
    let recovery_key = recovery::generate();
    let recovery_locked_key =
        recovery::lock_for_recovery(&recovery_key.public_key, org_id, &org_key)?;

    sqlx::query(
        "INSERT INTO organizations
            (id, name, slug, locked_key, recovery_locked_key, recovery_public_key,
             recovery_created_at, recovery_source)
         VALUES ($1, $2, $3, $4, $5, $6, now(), 'setup')",
    )
    .bind(org_id)
    .bind(payload.org_name.trim())
    .bind(slug)
    .bind(&locked_key)
    .bind(&recovery_locked_key)
    .bind(&recovery_key.public_key)
    .execute(&mut *tx)
    .await?;

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
    .await?;

    // Atomic claim: only one concurrent request can flip `completed` from FALSE to TRUE
    let claimed = sqlx::query(
        "UPDATE setup_state SET completed = TRUE, completed_at = now()
         WHERE id = 1 AND completed = FALSE",
    )
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if claimed == 0 {
        return Err(AppError::Conflict("Setup déjà effectué".into()));
    }

    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "recovery_key": recovery_key.secret_display.as_str() })),
    ))
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
