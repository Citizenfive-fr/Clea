//! Single place for password hashing and verification (Argon2id).
//!
//! Argon2 is CPU and memory heavy (about 19 MiB per hash), so it runs on the blocking
//! thread pool, and a semaphore bounds how many run at once (see `AppState`).

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Algorithm, Argon2, Params, PasswordHash, PasswordVerifier, Version,
};

use crate::{error::AppError, state::AppState};

// OWASP minimum for Argon2id: 19 MiB, 2 iterations, 1 lane
const MEMORY_KIB: u32 = 19456;
const ITERATIONS: u32 = 2;
const LANES: u32 = 1;

fn internal(e: impl ToString) -> AppError {
    AppError::Internal(e.to_string())
}

pub fn hash_sync(password: &str) -> Result<String, AppError> {
    let params = Params::new(MEMORY_KIB, ITERATIONS, LANES, None).map_err(internal)?;
    let salt = SaltString::generate(&mut OsRng);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(internal)
}

fn verify_sync(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash).ok().is_some_and(|parsed| {
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    })
}

pub async fn hash(state: &AppState, password: String) -> Result<String, AppError> {
    let _permit = state.hash_permits.acquire().await.map_err(internal)?;
    tokio::task::spawn_blocking(move || hash_sync(&password))
        .await
        .map_err(internal)?
}

/// Verifies a password. With `hash = None` (unknown user) it checks against a dummy hash,
/// so the response time does not reveal whether an account exists. Always false in that case.
pub async fn verify(
    state: &AppState,
    password: String,
    hash: Option<String>,
) -> Result<bool, AppError> {
    let known = hash.is_some();
    let hash = hash.unwrap_or_else(|| state.dummy_hash.to_string());
    let _permit = state.hash_permits.acquire().await.map_err(internal)?;
    let ok = tokio::task::spawn_blocking(move || verify_sync(&password, &hash))
        .await
        .map_err(internal)?;
    Ok(ok && known)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_then_verify() {
        let h = hash_sync("un mot de passe solide").unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(verify_sync("un mot de passe solide", &h));
        assert!(!verify_sync("autre", &h));
        assert!(!verify_sync("x", "not-a-hash"));
    }
}
