//! Recovery key: lets the owner reopen the organization key if the master key is lost.
//!
//! A key pair is generated at setup. The organization key is also locked for the public key
//! (HPKE, RFC 9180: X25519 + HKDF-SHA256 + AES-256-GCM). The private key is shown once to the
//! owner and never stored.
//!
//! Stored formats: public key `p1:` + hex, locked key `r1:` + hex(encapsulated key || ciphertext).
//! Displayed format: `CLEA-RECOVERY-KEY-` + 16 groups of 4 hex characters + 1 checksum group.

use hpke::{
    aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem as KemTrait,
    OpModeR, OpModeS, Serializable,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    error::AppError,
    keys::{from_hex, internal, to_hex, OrgKey, KEY_LEN},
};

type Kem = X25519HkdfSha256;
type PrivateKey = <Kem as KemTrait>::PrivateKey;
type PublicKey = <Kem as KemTrait>::PublicKey;
type EncappedKey = <Kem as KemTrait>::EncappedKey;

const INFO: &[u8] = b"clea/recovery/v1";
const PUBLIC_PREFIX: &str = "p1:";
const LOCKED_PREFIX: &str = "r1:";
const DISPLAY_PREFIX: &str = "CLEA-RECOVERY-KEY-";
const ENCAPPED_LEN: usize = 32;
const CHECKSUM_HEX: usize = 4;

/// A new recovery key pair: the public part goes to the database, the secret to the owner.
pub struct NewRecoveryKey {
    pub public_key: String,
    pub secret_display: Zeroizing<String>,
}

/// A recovery secret typed back by the owner (wiped from memory when dropped).
pub struct RecoverySecret(PrivateKey);

pub fn generate() -> NewRecoveryKey {
    let (private_key, public_key) = Kem::gen_keypair();
    let secret = Zeroizing::new(private_key.to_bytes().to_vec());
    NewRecoveryKey {
        public_key: format!("{PUBLIC_PREFIX}{}", to_hex(&public_key.to_bytes())),
        secret_display: display(&secret),
    }
}

impl RecoverySecret {
    /// Parses the displayed form. Tolerates upper/lower case, spaces and line breaks.
    pub fn parse(input: &str) -> Result<Self, AppError> {
        let compact: Zeroizing<String> = Zeroizing::new(
            input
                .chars()
                .filter(|c| !c.is_whitespace() && *c != '-')
                .collect::<String>()
                .to_ascii_lowercase(),
        );
        let prefix = DISPLAY_PREFIX.replace('-', "").to_ascii_lowercase();
        let body = compact
            .strip_prefix(&prefix)
            .ok_or_else(|| bad_secret("elle doit commencer par CLEA-RECOVERY-KEY-"))?;
        if body.len() != KEY_LEN * 2 + CHECKSUM_HEX {
            return Err(bad_secret("longueur incorrecte"));
        }
        let (key_hex, checksum) = body.split_at(KEY_LEN * 2);
        let bytes =
            Zeroizing::new(from_hex(key_hex).ok_or_else(|| bad_secret("caractère invalide"))?);
        if checksum != checksum_of(&bytes) {
            return Err(bad_secret("contrôle invalide"));
        }
        let private_key = PrivateKey::from_bytes(&bytes).map_err(|_| bad_secret("clé invalide"))?;
        Ok(Self(private_key))
    }

    /// Public key matching this secret, in the stored `p1:` format.
    pub fn public_key(&self) -> String {
        format!(
            "{PUBLIC_PREFIX}{}",
            to_hex(&Kem::sk_to_pk(&self.0).to_bytes())
        )
    }
}

/// Locks an organization key for the recovery public key (bound to the organization id).
pub fn lock_for_recovery(public_key: &str, org_id: Uuid, key: &OrgKey) -> Result<String, AppError> {
    let hex = public_key
        .strip_prefix(PUBLIC_PREFIX)
        .ok_or_else(|| internal("Clé publique de secours invalide"))?;
    let bytes = from_hex(hex).ok_or_else(|| internal("Clé publique de secours invalide"))?;
    let public_key =
        PublicKey::from_bytes(&bytes).map_err(|_| internal("Clé publique de secours invalide"))?;
    let (encapped, ciphertext) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, Kem>(
        &OpModeS::Base,
        &public_key,
        INFO,
        key.as_bytes(),
        org_id.as_bytes(),
    )
    .map_err(|_| internal("Chiffrement pour la clé de secours échoué"))?;
    let mut out = encapped.to_bytes().to_vec();
    out.extend_from_slice(&ciphertext);
    Ok(format!("{LOCKED_PREFIX}{}", to_hex(&out)))
}

/// Reopens an organization key with the recovery secret.
pub fn unlock_with_recovery(
    secret: &RecoverySecret,
    org_id: Uuid,
    locked: &str,
) -> Result<OrgKey, AppError> {
    let hex = locked
        .strip_prefix(LOCKED_PREFIX)
        .ok_or_else(|| internal("Format de clé de secours inattendu"))?;
    let data = from_hex(hex).ok_or_else(|| internal("Clé enfermée invalide"))?;
    if data.len() <= ENCAPPED_LEN {
        return Err(internal("Clé enfermée invalide"));
    }
    let (encapped, ciphertext) = data.split_at(ENCAPPED_LEN);
    let encapped =
        EncappedKey::from_bytes(encapped).map_err(|_| internal("Clé enfermée invalide"))?;
    let bytes = Zeroizing::new(
        hpke::single_shot_open::<AesGcm256, HkdfSha256, Kem>(
            &OpModeR::Base,
            &secret.0,
            &encapped,
            INFO,
            ciphertext,
            org_id.as_bytes(),
        )
        .map_err(|_| internal("Cette clé de secours n'ouvre pas la clé de l'organisation"))?,
    );
    OrgKey::from_key_bytes(&bytes)
}

fn display(secret: &[u8]) -> Zeroizing<String> {
    let hex = Zeroizing::new(to_hex(secret));
    let mut out = Zeroizing::new(String::from(DISPLAY_PREFIX));
    for (i, chunk) in hex.as_bytes().chunks(4).enumerate() {
        if i > 0 {
            out.push('-');
        }
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
    }
    out.push('-');
    out.push_str(&checksum_of(secret));
    out
}

/// Short checksum to detect a badly copied key (not a security feature).
fn checksum_of(secret: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"clea/recovery-checksum/v1\0");
    hasher.update(secret);
    to_hex(&hasher.finalize()[..CHECKSUM_HEX / 2])
}

fn bad_secret(reason: &str) -> AppError {
    AppError::BadRequest(format!("Clé de secours mal recopiée ({reason})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displayed_format_is_readable() {
        let new = generate();
        let s = new.secret_display.as_str();
        assert!(s.starts_with("CLEA-RECOVERY-KEY-"));
        let groups: Vec<&str> = s["CLEA-RECOVERY-KEY-".len()..].split('-').collect();
        assert_eq!(groups.len(), 17);
        assert!(groups.iter().all(|g| g.len() == 4));
        assert!(new.public_key.starts_with("p1:"));
    }

    #[test]
    fn lock_then_recover_the_organization_key() {
        let org = Uuid::new_v4();
        let key = OrgKey::generate();
        let new = generate();
        let locked = lock_for_recovery(&new.public_key, org, &key).unwrap();
        assert!(locked.starts_with("r1:"));
        let secret = RecoverySecret::parse(&new.secret_display).unwrap();
        assert_eq!(secret.public_key(), new.public_key);
        let opened = unlock_with_recovery(&secret, org, &locked).unwrap();
        assert_eq!(opened.as_bytes(), key.as_bytes());
    }

    #[test]
    fn parsing_tolerates_case_spaces_and_line_breaks() {
        let new = generate();
        let messy = new
            .secret_display
            .to_lowercase()
            .replace('-', " ")
            .replacen(' ', "\n", 3);
        assert!(RecoverySecret::parse(&messy).is_ok());
    }

    #[test]
    fn a_badly_copied_key_is_detected() {
        let new = generate();
        let s = new.secret_display.to_string();
        // Change one character of the key part
        let pos = "CLEA-RECOVERY-KEY-".len() + 1;
        let c = s.as_bytes()[pos] as char;
        let swapped = if c == '0' { '1' } else { '0' };
        let mut bad = s.clone();
        bad.replace_range(pos..pos + 1, &swapped.to_string());
        let err = RecoverySecret::parse(&bad).err().expect("must be refused");
        assert!(matches!(err, AppError::BadRequest(m) if m.contains("mal recopiée")));
        assert!(RecoverySecret::parse("CLEA-RECOVERY-KEY-1234").is_err());
        assert!(RecoverySecret::parse("n'importe quoi").is_err());
    }

    #[test]
    fn wrong_secret_or_organization_cannot_recover() {
        let org = Uuid::new_v4();
        let new = generate();
        let locked = lock_for_recovery(&new.public_key, org, &OrgKey::generate()).unwrap();
        let other = RecoverySecret::parse(&generate().secret_display).unwrap();
        assert!(unlock_with_recovery(&other, org, &locked).is_err());
        let right = RecoverySecret::parse(&new.secret_display).unwrap();
        assert!(unlock_with_recovery(&right, Uuid::new_v4(), &locked).is_err());
    }
}
