use axum::{
    extract::{FromRef, FromRequestParts},
    http::{header::COOKIE, request::Parts},
};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use crate::{error::AppError, state::AppState};

pub struct AuthSession {
    pub user_id: Uuid,
    pub org_id: Uuid,
    pub email: String,
    pub role: String,
    pub username: Option<String>,
}

impl<S> FromRequestParts<S> for AuthSession
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = AppState::from_ref(state);

        let token = extract_session_token(&parts.headers)
            .ok_or_else(|| AppError::Unauthorized("Non authentifié".into()))?;

        let token_hash = hash_token(&token);

        let row = sqlx::query(
            "SELECT s.user_id, u.organization_id, u.email, u.role, u.username
             FROM sessions s
             JOIN users u ON u.id = s.user_id
             WHERE s.token_hash = $1
               AND s.expires_at > now()
               AND u.is_active = TRUE",
        )
        .bind(&token_hash)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or_else(|| AppError::Unauthorized("Session invalide ou expirée".into()))?;

        Ok(AuthSession {
            user_id: row.get("user_id"),
            org_id: row.get("organization_id"),
            email: row.get("email"),
            role: row.get("role"),
            username: row.get("username"),
        })
    }
}

pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn extract_session_token(headers: &axum::http::HeaderMap) -> Option<String> {
    let cookie_header = headers.get(COOKIE)?.to_str().ok()?;
    cookie_header.split(';').find_map(|kv| {
        let kv = kv.trim();
        kv.strip_prefix("session=").map(|v| v.to_string())
    })
}
