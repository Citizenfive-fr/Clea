//! Field-level encryption for sensitive database values (AES-256-GCM).
//!
//! Stored format: `v1:` + hex(nonce[12] || ciphertext+tag).
//! The key is derived from APP_SECRET_KEY. The additional authenticated data (AAD)
//! binds a value to its owner, so a ciphertext copied to another row fails to decrypt.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use rand::{rng, Rng};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::error::AppError;

const PREFIX: &str = "v1:";
const NONCE_LEN: usize = 12;

fn cipher(app_secret: &str) -> Result<Aes256Gcm, AppError> {
    // APP_SECRET_KEY is high entropy (see .env.example), so a domain-separated SHA-256 is enough
    let mut hasher = Sha256::new();
    hasher.update(b"clea/field-encryption/v1\0");
    hasher.update(app_secret.as_bytes());
    Aes256Gcm::new_from_slice(&hasher.finalize())
        .map_err(|e| AppError::Internal(format!("Clé de chiffrement invalide : {e}")))
}

pub fn encrypt(app_secret: &str, aad: &[u8], plaintext: &str) -> Result<String, AppError> {
    let cipher = cipher(app_secret)?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng().fill_bytes(&mut nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext.as_bytes(),
                aad,
            },
        )
        .map_err(|_| AppError::Internal("Chiffrement échoué".into()))?;

    let mut out = nonce_bytes.to_vec();
    out.extend_from_slice(&ciphertext);
    Ok(format!("{PREFIX}{}", to_hex(&out)))
}

pub fn decrypt(app_secret: &str, aad: &[u8], stored: &str) -> Result<String, AppError> {
    let hex = stored
        .strip_prefix(PREFIX)
        .ok_or_else(|| AppError::Internal("Valeur non chiffrée".into()))?;
    let data =
        from_hex(hex).ok_or_else(|| AppError::Internal("Valeur chiffrée invalide".into()))?;
    if data.len() <= NONCE_LEN {
        return Err(AppError::Internal("Valeur chiffrée invalide".into()));
    }
    let (nonce, ciphertext) = data.split_at(NONCE_LEN);

    let plaintext = cipher(app_secret)?
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| {
            AppError::Internal("Déchiffrement échoué (APP_SECRET_KEY modifiée ?)".into())
        })?;

    String::from_utf8(plaintext)
        .map_err(|_| AppError::Internal("Valeur déchiffrée invalide".into()))
}

/// One-time migration: encrypts TOTP secrets stored in plaintext by earlier versions.
pub async fn encrypt_legacy_totp_secrets(db: &PgPool, app_secret: &str) -> Result<u64, AppError> {
    let rows = sqlx::query(
        "SELECT id, totp_secret FROM users
         WHERE totp_secret IS NOT NULL AND totp_secret NOT LIKE 'v1:%'",
    )
    .fetch_all(db)
    .await?;

    for row in &rows {
        let id: Uuid = row.get("id");
        let plain: String = row.get("totp_secret");
        let encrypted = encrypt(app_secret, id.as_bytes(), &plain)?;
        sqlx::query("UPDATE users SET totp_secret = $1 WHERE id = $2")
            .bind(encrypted)
            .bind(id)
            .execute(db)
            .await?;
    }
    Ok(rows.len() as u64)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn roundtrip() {
        let enc = encrypt(KEY, b"user-1", "JBSWY3DPEHPK3PXP").unwrap();
        assert!(enc.starts_with("v1:"));
        assert_eq!(decrypt(KEY, b"user-1", &enc).unwrap(), "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn rejects_wrong_owner_wrong_key_and_tampering() {
        let enc = encrypt(KEY, b"user-1", "secret").unwrap();
        assert!(decrypt(KEY, b"user-2", &enc).is_err());
        assert!(decrypt("another-key-another-key-another-key", b"user-1", &enc).is_err());
        let mut tampered = enc.clone();
        tampered.pop();
        tampered.push(if enc.ends_with('0') { '1' } else { '0' });
        assert!(decrypt(KEY, b"user-1", &tampered).is_err());
        assert!(decrypt(KEY, b"user-1", "plaintext").is_err());
    }
}
