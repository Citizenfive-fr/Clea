//! Recovery key in Mon profil (owner only): status, check, replacement.
//!
//! Replacing the key requires the current recovery key on top of the password: a stolen
//! password alone must never be enough to get a recovery key. A lost key is recreated
//! by the host with `clea new-recovery-key`, which needs the master key.

use axum::{extract::State, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;

use crate::{
    error::AppError,
    password,
    ratelimit::ban_error,
    recovery::{self, RecoverySecret},
    session::AuthSession,
    state::AppState,
};

fn require_owner(session: &AuthSession) -> Result<(), AppError> {
    if session.role != "owner" {
        return Err(AppError::Forbidden(
            "Réservé au propriétaire de l'organisation".into(),
        ));
    }
    Ok(())
}

/// GET /api/recovery-key
pub async fn status(
    session: AuthSession,
    State(state): State<AppState>,
) -> Result<Json<Value>, AppError> {
    require_owner(&session)?;
    let row = sqlx::query(
        "SELECT to_char(recovery_created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')
                AS created_at,
                recovery_source AS source,
                recovery_notice_pending AS notice
         FROM organizations WHERE id = $1",
    )
    .bind(session.org_id)
    .fetch_one(&state.db)
    .await?;
    let created_at: Option<String> = row.get("created_at");
    let source: Option<String> = row.get("source");
    let notice: bool = row.get("notice");
    Ok(Json(
        json!({ "created_at": created_at, "source": source, "notice": notice }),
    ))
}

#[derive(Deserialize)]
pub struct VerifyPayload {
    pub recovery_key: String,
}

/// POST /api/recovery-key/verify
/// Says whether the key typed is the current one. Changes nothing.
pub async fn verify(
    session: AuthSession,
    State(state): State<AppState>,
    Json(payload): Json<VerifyPayload>,
) -> Result<Json<Value>, AppError> {
    require_owner(&session)?;
    let limit_key = session.user_id.to_string();
    state.reauth_limiter.check(&limit_key).map_err(ban_error)?;

    let secret = RecoverySecret::parse(&payload.recovery_key)?;
    let valid = secret.public_key() == current_public_key(&state, session.org_id).await?;
    if valid {
        state.reauth_limiter.clear_failures(&limit_key);
        // The owner holds the current key: the warning about a recreated key is no longer needed
        clear_notice(&state, session.org_id).await?;
    } else {
        state.reauth_limiter.record_failure(&limit_key);
    }
    Ok(Json(json!({ "valid": valid })))
}

#[derive(Deserialize)]
pub struct ReplacePayload {
    pub recovery_key: String,
    pub password: String,
}

/// POST /api/recovery-key/replace
/// Needs the password and the current recovery key. Returns the new key, shown once.
pub async fn replace(
    session: AuthSession,
    State(state): State<AppState>,
    Json(payload): Json<ReplacePayload>,
) -> Result<Json<Value>, AppError> {
    require_owner(&session)?;
    let limit_key = session.user_id.to_string();
    state.reauth_limiter.check(&limit_key).map_err(ban_error)?;

    let hash: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
        .bind(session.user_id)
        .fetch_one(&state.db)
        .await?;
    if !password::verify(&state, payload.password.clone(), Some(hash)).await? {
        state.reauth_limiter.record_failure(&limit_key);
        return Err(AppError::Unauthorized("Mot de passe incorrect".into()));
    }

    let secret = RecoverySecret::parse(&payload.recovery_key)?;

    let mut tx = state.db.begin().await?;
    let row = sqlx::query(
        "SELECT recovery_public_key, recovery_locked_key FROM organizations
         WHERE id = $1 FOR UPDATE",
    )
    .bind(session.org_id)
    .fetch_one(&mut *tx)
    .await?;
    let public_key: Option<String> = row.get("recovery_public_key");
    let locked: Option<String> = row.get("recovery_locked_key");
    let (Some(public_key), Some(locked)) = (public_key, locked) else {
        return Err(AppError::Internal(
            "Organisation sans clé de secours".into(),
        ));
    };
    if secret.public_key() != public_key {
        state.reauth_limiter.record_failure(&limit_key);
        return Err(wrong_key());
    }

    let org_key = recovery::unlock_with_recovery(&secret, session.org_id, &locked)?;
    let new_recovery = recovery::generate();
    let new_locked =
        recovery::lock_for_recovery(&new_recovery.public_key, session.org_id, &org_key)?;
    sqlx::query(
        "UPDATE organizations
         SET recovery_locked_key = $1, recovery_public_key = $2, recovery_created_at = now(),
             recovery_source = 'profile', recovery_notice_pending = FALSE
         WHERE id = $3",
    )
    .bind(&new_locked)
    .bind(&new_recovery.public_key)
    .bind(session.org_id)
    .execute(&mut *tx)
    .await?;
    // Same transaction as the change: no replacement without its trace
    sqlx::query("INSERT INTO audit_logs (organization_id, user_id, action) VALUES ($1, $2, $3)")
        .bind(session.org_id)
        .bind(session.user_id)
        .bind("recovery_key.replaced")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    state.reauth_limiter.clear_failures(&limit_key);

    Ok(Json(
        json!({ "recovery_key": new_recovery.secret_display.as_str() }),
    ))
}

/// POST /api/recovery-key/notice/dismiss
/// The owner closes the warning (Mon profil box or notification).
pub async fn dismiss_notice(
    session: AuthSession,
    State(state): State<AppState>,
) -> Result<axum::http::StatusCode, AppError> {
    require_owner(&session)?;
    clear_notice(&state, session.org_id).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

async fn clear_notice(state: &AppState, org_id: uuid::Uuid) -> Result<(), AppError> {
    sqlx::query("UPDATE organizations SET recovery_notice_pending = FALSE WHERE id = $1")
        .bind(org_id)
        .execute(&state.db)
        .await?;
    Ok(())
}

async fn current_public_key(state: &AppState, org_id: uuid::Uuid) -> Result<String, AppError> {
    let key: Option<String> =
        sqlx::query_scalar("SELECT recovery_public_key FROM organizations WHERE id = $1")
            .bind(org_id)
            .fetch_one(&state.db)
            .await?;
    key.ok_or_else(|| AppError::Internal("Organisation sans clé de secours".into()))
}

fn wrong_key() -> AppError {
    AppError::Unauthorized(
        "Cette clé de secours n'est pas celle de ton organisation. \
         Si elle est perdue, la personne qui gère ou maintient le serveur peut en créer une nouvelle (clea new-recovery-key)."
            .into(),
    )
}
