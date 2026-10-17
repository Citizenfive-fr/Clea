//! Key hierarchy: master key (chosen by the host) -> organization key -> data.
//!
//! - The master key never touches the database. It only locks the organization keys.
//! - Each organization has its own random 256-bit key, stored locked (`k1:` format).
//!   It is the key that encrypts the data (`v2:` format).
//! - The organization id is bound as associated data: a locked key or a value copied
//!   to another organization fails to open.
//!
//! Formats: `k1:` / `v2:` + hex(nonce[12] || ciphertext+tag), AES-256-GCM.
//! Keys come from the OS random source and are wiped from memory when dropped.

use aes_gcm::{
    aead::{rand_core::RngCore, Aead, AeadCore, KeyInit, OsRng, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{error::AppError, state::AppState};
use sqlx::{PgPool, Row};

const LOCKED_KEY_PREFIX: &str = "k1:";
const VALUE_PREFIX: &str = "v2:";
const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

/// An opened organization key. No Debug/Display on purpose, so it cannot end up in logs.
#[derive(Clone)]
pub struct OrgKey(Zeroizing<[u8; KEY_LEN]>);

impl OrgKey {
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        fill_random(bytes.as_mut());
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Rebuilds a key from its raw bytes (after unlocking it with the master or recovery key).
    pub fn from_key_bytes(bytes: &[u8]) -> Result<Self, AppError> {
        if bytes.len() != KEY_LEN {
            return Err(internal("Clé de l'organisation invalide"));
        }
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    /// Encrypts a value for this organization (`aad` binds it to its row, e.g. a user id).
    pub fn encrypt(&self, aad: &[u8], plaintext: &str) -> Result<String, AppError> {
        seal(&self.0, VALUE_PREFIX, aad, plaintext.as_bytes())
    }

    pub fn decrypt(&self, aad: &[u8], stored: &str) -> Result<String, AppError> {
        let bytes = Zeroizing::new(open(&self.0, VALUE_PREFIX, aad, stored)?);
        String::from_utf8(bytes.to_vec()).map_err(|_| internal("Valeur déchiffrée invalide"))
    }
}

/// Locks an organization key with the master key, for storage in the database.
pub fn lock_org_key(master_key: &str, org_id: Uuid, key: &OrgKey) -> Result<String, AppError> {
    seal(
        &master_cipher_key(master_key),
        LOCKED_KEY_PREFIX,
        org_id.as_bytes(),
        key.as_bytes(),
    )
}

/// Opens an organization key stored in the database.
pub fn unlock_org_key(master_key: &str, org_id: Uuid, locked: &str) -> Result<OrgKey, AppError> {
    let bytes = open(
        &master_cipher_key(master_key),
        LOCKED_KEY_PREFIX,
        org_id.as_bytes(),
        locked,
    )
    .map_err(|_| {
        internal("Ouverture de la clé de l'organisation impossible (clé maîtresse modifiée ?)")
    })?;
    OrgKey::from_key_bytes(&Zeroizing::new(bytes))
}

/// Returns the opened key of an organization, from the in-memory cache or the database.
pub async fn org_key(state: &AppState, org_id: Uuid) -> Result<OrgKey, AppError> {
    if let Some(key) = state
        .org_keys
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(&org_id)
    {
        return Ok(key.clone());
    }

    let locked: Option<String> =
        sqlx::query_scalar("SELECT locked_key FROM organizations WHERE id = $1")
            .bind(org_id)
            .fetch_optional(&state.db)
            .await?
            .flatten();
    let locked = locked.ok_or_else(|| internal("Organisation sans clé de chiffrement"))?;
    let key = unlock_org_key(&state.config.master_key, org_id, &locked)?;

    state
        .org_keys
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(org_id, key.clone());
    Ok(key)
}

/// Startup check: every organization must have a key, and the master key must open it.
/// Catches a changed master key or a database from an older beta before any request.
pub async fn check_org_keys(db: &PgPool, master_key: &str) -> Result<(), String> {
    let rows = sqlx::query("SELECT id, locked_key, recovery_locked_key FROM organizations")
        .fetch_all(db)
        .await
        .map_err(|e| format!("Lecture des organisations impossible : {e}"))?;

    for row in rows {
        let id: Uuid = row.get("id");
        let locked: Option<String> = row.get("locked_key");
        let has_recovery = row
            .get::<Option<String>, _>("recovery_locked_key")
            .is_some();
        let Some(locked) = locked else {
            return Err("Base créée avec une version précédente de Cléa (bêta) : \
                 l'organisation n'a pas de clé de chiffrement. Repars d'une base neuve."
                .into());
        };
        if !has_recovery {
            return Err("Base créée avec une version précédente de Cléa (bêta) : \
                 l'organisation n'a pas de clé de secours. Repars d'une base neuve."
                .into());
        }
        unlock_org_key(master_key, id, &locked).map_err(|_| {
            "La clé maîtresse ne permet pas d'ouvrir la clé de l'organisation : \
             APP_SECRET_KEY ou APP_KEY_FILE a changé ?"
                .to_string()
        })?;
    }
    Ok(())
}

/// Derives the AES key that locks organization keys from the master key, with HKDF-SHA256
/// (RFC 5869). The master key must be random (64+ hex characters, checked in config.rs).
fn master_cipher_key(master_key: &str) -> Zeroizing<[u8; KEY_LEN]> {
    let hkdf = Hkdf::<Sha256>::new(Some(b"clea/master-key"), master_key.as_bytes());
    let mut okm = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(b"clea/organization-key-wrapping/v1", okm.as_mut())
        .expect("32 bytes is always a valid HKDF-SHA256 output length");
    okm
}

/// Fills a buffer from the operating system's random source (for keys and secrets).
pub fn fill_random(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
}

fn seal(
    key: &[u8; KEY_LEN],
    prefix: &str,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<String, AppError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| internal("Clé invalide"))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| internal("Chiffrement échoué"))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ciphertext);
    Ok(format!("{prefix}{}", to_hex(&out)))
}

fn open(key: &[u8; KEY_LEN], prefix: &str, aad: &[u8], stored: &str) -> Result<Vec<u8>, AppError> {
    let hex = stored
        .strip_prefix(prefix)
        .ok_or_else(|| internal("Format chiffré inattendu"))?;
    let data = from_hex(hex).ok_or_else(|| internal("Valeur chiffrée invalide"))?;
    if data.len() <= NONCE_LEN {
        return Err(internal("Valeur chiffrée invalide"));
    }
    let (nonce, ciphertext) = data.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| internal("Clé invalide"))?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| internal("Déchiffrement échoué"))
}

pub(crate) fn internal(msg: &str) -> AppError {
    AppError::Internal(msg.into())
}

pub(crate) fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn from_hex(s: &str) -> Option<Vec<u8>> {
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

    const MASTER: &str = "0123456789abcdef0123456789abcdef";
    const OTHER_MASTER: &str = "another-master-key-another-master-key";

    #[test]
    fn org_key_lock_and_unlock() {
        let org = Uuid::new_v4();
        let key = OrgKey::generate();
        let locked = lock_org_key(MASTER, org, &key).unwrap();
        assert!(locked.starts_with("k1:"));
        let opened = unlock_org_key(MASTER, org, &locked).unwrap();
        assert_eq!(opened.as_bytes(), key.as_bytes());
    }

    #[test]
    fn locked_key_needs_the_right_master_key_and_organization() {
        let org = Uuid::new_v4();
        let locked = lock_org_key(MASTER, org, &OrgKey::generate()).unwrap();
        assert!(unlock_org_key(OTHER_MASTER, org, &locked).is_err());
        assert!(unlock_org_key(MASTER, Uuid::new_v4(), &locked).is_err());
    }

    #[test]
    fn data_roundtrip_and_isolation_between_organizations() {
        let key_a = OrgKey::generate();
        let key_b = OrgKey::generate();
        let enc = key_a
            .encrypt(b"user-1", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")
            .unwrap();
        assert!(enc.starts_with("v2:"));
        assert_eq!(
            key_a.decrypt(b"user-1", &enc).unwrap(),
            "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
        );
        assert!(key_b.decrypt(b"user-1", &enc).is_err());
        assert!(key_a.decrypt(b"user-2", &enc).is_err());
    }

    #[test]
    fn rejects_tampering_and_wrong_formats() {
        let key = OrgKey::generate();
        let enc = key.encrypt(b"x", "secret").unwrap();
        let mut tampered = enc.clone();
        let last = tampered.pop().unwrap();
        tampered.push(if last == '0' { '1' } else { '0' });
        assert!(key.decrypt(b"x", &tampered).is_err());
        assert!(key.decrypt(b"x", "plaintext").is_err());
        assert!(key.decrypt(b"x", "v1:00").is_err());
        // A locked key is not a value, and the other way round
        let locked = lock_org_key(MASTER, Uuid::nil(), &key).unwrap();
        assert!(key.decrypt(b"x", &locked).is_err());
    }

    #[test]
    fn each_encryption_uses_a_fresh_nonce() {
        let key = OrgKey::generate();
        assert_ne!(
            key.encrypt(b"x", "same").unwrap(),
            key.encrypt(b"x", "same").unwrap()
        );
    }
}
