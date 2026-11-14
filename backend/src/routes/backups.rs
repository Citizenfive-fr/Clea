//! Sauvegardes page.
//!
//! Owner: creates or replaces the backup key, sets frequency and retention, downloads files.
//! Admin: sees the state and can start a backup. Member: nothing.
//! Restoring is only possible from the command line (`clea restore`), on purpose.

use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;
use uuid::Uuid;

use crate::{
    audit, backup, error::AppError, password, ratelimit::ban_error, session::AuthSession,
    state::AppState,
};

const FREQUENCIES: &[&str] = &["daily", "weekly", "monthly", "manual"];

fn require_manager(session: &AuthSession) -> Result<(), AppError> {
    if session.role == "member" {
        return Err(AppError::Forbidden("Accès refusé".into()));
    }
    Ok(())
}

fn require_owner(session: &AuthSession) -> Result<(), AppError> {
    if session.role != "owner" {
        return Err(AppError::Forbidden(
            "Réservé au propriétaire de l'organisation".into(),
        ));
    }
    Ok(())
}

fn backup_dir(state: &AppState) -> Result<&std::path::Path, AppError> {
    state.config.backup_dir.as_deref().ok_or_else(|| {
        AppError::BadRequest(
            "Les sauvegardes ne sont pas configurées sur ce serveur (BACKUP_DIR).".into(),
        )
    })
}

/// The backups belong to the organization that created the backup key.
async fn check_organization(state: &AppState, session: &AuthSession) -> Result<(), AppError> {
    let org: Option<Uuid> =
        sqlx::query_scalar("SELECT organization_id FROM backup_settings WHERE id = 1")
            .fetch_one(&state.db)
            .await?;
    match org {
        Some(id) if id != session.org_id => Err(AppError::Forbidden("Accès refusé".into())),
        _ => Ok(()),
    }
}

/// Logs the detail on the server and gives a plain message to the user.
fn failed(what: &str, detail: String) -> AppError {
    tracing::error!("{what} : {detail}");
    AppError::Conflict(format!(
        "{what}. Le détail est dans les journaux du serveur."
    ))
}

/// GET /api/backups
pub async fn status(
    session: AuthSession,
    State(state): State<AppState>,
) -> Result<Json<Value>, AppError> {
    require_manager(&session)?;
    check_organization(&state, &session).await?;
    let row = sqlx::query(
        "SELECT public_key IS NOT NULL AS enabled, frequency, retention_days, month_day, week_day,
                to_char(key_created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')
                AS key_created_at
         FROM backup_settings WHERE id = 1",
    )
    .fetch_one(&state.db)
    .await?;
    let enabled: bool = row.get("enabled");

    let mut body = json!({
        "configured": state.config.backup_dir.is_some(),
        "enabled": enabled,
        "can_manage": session.role == "owner",
        "frequency": row.get::<String, _>("frequency"),
        "retention_days": row.get::<i32, _>("retention_days"),
        "month_day": row.get::<i32, _>("month_day"),
        "week_day": row.get::<i32, _>("week_day"),
        "key_created_at": row.get::<Option<String>, _>("key_created_at"),
        "backups": [],
        "problems": [],
    });

    if let Some(dir) = state.config.backup_dir.as_deref() {
        let backups =
            backup::list(dir).map_err(|e| failed("Lecture des sauvegardes impossible", e))?;
        body["problems"] = json!(backup::problems(&backups));
        body["backups"] = json!(backups
            .iter()
            .rev()
            .map(|b| json!({
                "file": b.file,
                "at": b.at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                "size": b.size,
                "fingerprint_ok": b.fingerprint == backup::Fingerprint::Valid,
            }))
            .collect::<Vec<_>>());
    }
    Ok(Json(body))
}

#[derive(Deserialize)]
pub struct KeyPayload {
    pub password: String,
}

/// POST /api/backups/key
/// Creates (or replaces) the backup key. Needs the password. The key is shown once.
pub async fn create_key(
    session: AuthSession,
    State(state): State<AppState>,
    Json(payload): Json<KeyPayload>,
) -> Result<Json<Value>, AppError> {
    require_owner(&session)?;
    backup_dir(&state)?;
    check_organization(&state, &session).await?;
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
    state.reauth_limiter.clear_failures(&limit_key);

    let new_key = backup::generate_key();
    let mut tx = state.db.begin().await?;
    let replaced: bool = sqlx::query_scalar(
        "SELECT public_key IS NOT NULL FROM backup_settings WHERE id = 1 FOR UPDATE",
    )
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE backup_settings
         SET public_key = $1, organization_id = $2, key_created_at = now()
         WHERE id = 1",
    )
    .bind(&new_key.public_key)
    .bind(session.org_id)
    .execute(&mut *tx)
    .await?;
    // Same transaction as the change: no new key without its trace
    sqlx::query("INSERT INTO audit_logs (organization_id, user_id, action) VALUES ($1, $2, $3)")
        .bind(session.org_id)
        .bind(session.user_id)
        .bind(if replaced {
            "backup_key.replaced"
        } else {
            "backup_key.created"
        })
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(Json(
        json!({ "backup_key": new_key.secret_display.as_str() }),
    ))
}

#[derive(Deserialize)]
pub struct VerifyKeyPayload {
    pub backup_key: String,
}

/// POST /api/backups/key/verify
/// Says whether the key typed is the current backup key, an older one still needed by some
/// backups, or neither. Changes nothing.
pub async fn verify_key(
    session: AuthSession,
    State(state): State<AppState>,
    Json(payload): Json<VerifyKeyPayload>,
) -> Result<Json<Value>, AppError> {
    require_owner(&session)?;
    let dir = backup_dir(&state)?;
    check_organization(&state, &session).await?;
    let limit_key = session.user_id.to_string();
    state.reauth_limiter.check(&limit_key).map_err(ban_error)?;

    let typed = backup::BackupSecret::parse(&payload.backup_key)?.public_key();
    let current: Option<String> =
        sqlx::query_scalar("SELECT public_key FROM backup_settings WHERE id = 1")
            .fetch_one(&state.db)
            .await?;
    let used_by = backup::backups_using_key(dir, &typed)
        .map_err(|e| failed("Lecture des sauvegardes impossible", e))?;
    let status = if current.as_deref() == Some(typed.as_str()) {
        "current"
    } else if used_by > 0 {
        "old"
    } else {
        "unknown"
    };
    if status == "unknown" {
        state.reauth_limiter.record_failure(&limit_key);
    } else {
        state.reauth_limiter.clear_failures(&limit_key);
    }
    Ok(Json(json!({ "status": status, "backups": used_by })))
}

#[derive(Deserialize)]
pub struct SettingsPayload {
    pub frequency: String,
    pub retention_days: i32,
    pub month_day: i32,
    pub week_day: i32,
}

/// PUT /api/backups/settings
pub async fn update_settings(
    session: AuthSession,
    State(state): State<AppState>,
    Json(payload): Json<SettingsPayload>,
) -> Result<StatusCode, AppError> {
    require_owner(&session)?;
    check_organization(&state, &session).await?;
    if !FREQUENCIES.contains(&payload.frequency.as_str()) {
        return Err(AppError::BadRequest("Fréquence inconnue".into()));
    }
    if !(1..=3650).contains(&payload.retention_days) {
        return Err(AppError::BadRequest(
            "La durée de conservation va de 1 à 3650 jours".into(),
        ));
    }
    if !(1..=28).contains(&payload.month_day) {
        return Err(AppError::BadRequest("Le jour du mois va de 1 à 28".into()));
    }
    if !(1..=7).contains(&payload.week_day) {
        return Err(AppError::BadRequest("Jour de la semaine inconnu".into()));
    }
    sqlx::query(
        "UPDATE backup_settings
         SET frequency = $1, retention_days = $2, month_day = $3, week_day = $4
         WHERE id = 1",
    )
    .bind(&payload.frequency)
    .bind(payload.retention_days)
    .bind(payload.month_day)
    .bind(payload.week_day)
    .execute(&state.db)
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/backups/run
/// Makes a backup now, then deletes the expired ones.
pub async fn run(
    session: AuthSession,
    State(state): State<AppState>,
) -> Result<Json<Value>, AppError> {
    require_manager(&session)?;
    let dir = backup_dir(&state)?;
    check_organization(&state, &session).await?;
    let enabled: bool =
        sqlx::query_scalar("SELECT public_key IS NOT NULL FROM backup_settings WHERE id = 1")
            .fetch_one(&state.db)
            .await?;
    if !enabled {
        return Err(AppError::BadRequest(
            "Les sauvegardes ne sont pas encore activées : le propriétaire doit d'abord \
             créer la clé de sauvegarde."
                .into(),
        ));
    }

    // At most one manual backup per minute
    let recent: bool = sqlx::query_scalar(
        "SELECT COALESCE(last_backup_at > now() - interval '1 minute', FALSE)
         FROM backup_settings WHERE id = 1",
    )
    .fetch_one(&state.db)
    .await?;
    if recent {
        return Err(AppError::TooManyRequests(
            "Une sauvegarde vient d'être faite. Réessaie dans une minute.".into(),
        ));
    }

    let made = backup::run(&state.db, dir)
        .await
        .map_err(|e| failed("La sauvegarde a échoué", e))?;
    if let Err(e) = backup::purge(&state.db, dir).await {
        tracing::error!("Suppression des sauvegardes expirées échouée : {e}");
    }
    audit::log(
        &state.db,
        Some(session.org_id),
        Some(session.user_id),
        "backup.run_manual",
        None,
        None,
    )
    .await;
    Ok(Json(json!({ "file": made.file })))
}

/// GET /api/backups/files/{name}
/// Downloads a backup or its fingerprint file (owner only). The backup stays encrypted:
/// reading it needs the backup key, which is never on the server.
pub async fn download(
    session: AuthSession,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Response, AppError> {
    require_owner(&session)?;
    let dir = backup_dir(&state)?;
    check_organization(&state, &session).await?;

    // Only an existing backup, or its fingerprint: never another file of the folder
    let backup_name = name.strip_suffix(".sha256").unwrap_or(&name);
    let exists = backup::is_backup_file_name(backup_name)
        && backup::list(dir)
            .map_err(|e| failed("Lecture des sauvegardes impossible", e))?
            .iter()
            .any(|b| b.file == backup_name);
    if !exists {
        return Err(AppError::NotFound("Sauvegarde introuvable".into()));
    }
    let data = std::fs::read(dir.join(&name))
        .map_err(|_| AppError::NotFound("Fichier introuvable".into()))?;

    if name == backup_name {
        audit::log(
            &state.db,
            Some(session.org_id),
            Some(session.user_id),
            "backup.downloaded",
            None,
            None,
        )
        .await;
    }

    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        data,
    )
        .into_response())
}
