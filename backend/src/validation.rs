//! Input validation shared by the routes (lengths are counted in characters, not bytes).

use crate::error::AppError;

const PASSWORD_MIN: usize = 12;
// Upper bound: Argon2 cost does not grow with length, but huge inputs are pointless
const PASSWORD_MAX: usize = 128;
const USERNAME_MAX: usize = 50;
const EMAIL_MAX: usize = 254;

pub fn password(password: &str) -> Result<(), AppError> {
    let len = password.chars().count();
    if len < PASSWORD_MIN {
        return Err(AppError::BadRequest(format!(
            "Mot de passe trop court ({PASSWORD_MIN} caractères minimum)"
        )));
    }
    if len > PASSWORD_MAX {
        return Err(AppError::BadRequest(format!(
            "Mot de passe trop long ({PASSWORD_MAX} caractères maximum)"
        )));
    }
    Ok(())
}

/// Returns the trimmed username.
pub fn username(raw: &str) -> Result<String, AppError> {
    let username = raw.trim();
    let len = username.chars().count();
    if len == 0 || len > USERNAME_MAX || username.chars().any(char::is_control) {
        return Err(AppError::BadRequest(format!(
            "Le nom d'utilisateur doit contenir entre 1 et {USERNAME_MAX} caractères"
        )));
    }
    Ok(username.to_string())
}

/// Returns the trimmed, lowercased email.
pub fn email(raw: &str) -> Result<String, AppError> {
    let email = raw.trim().to_lowercase();
    let valid = email.len() <= EMAIL_MAX
        && !email
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "<>\"\\(),;:[]".contains(c))
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty()
                && !domain.contains('@')
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
        });
    if valid {
        Ok(email)
    } else {
        Err(AppError::BadRequest("Email invalide".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_rules() {
        assert_eq!(email("  Jean@Example.FR ").unwrap(), "jean@example.fr");
        assert!(email("o'brien@example.ie").is_ok());
        for bad in [
            "",
            "a@b",
            "@x.fr",
            "a@@x.fr",
            "a b@x.fr",
            "a@.fr",
            "a@x.",
            "a@x\n.fr",
            "<a>@x.fr",
            "a\"b@x.fr",
        ] {
            assert!(email(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn password_and_username_rules() {
        assert!(password("short").is_err());
        assert!(password(&"é".repeat(12)).is_ok());
        assert!(password(&"a".repeat(129)).is_err());
        assert_eq!(username("  Léa ").unwrap(), "Léa");
        assert!(username("   ").is_err());
        assert!(username(&"a".repeat(51)).is_err());
        assert!(username("a\u{0}b").is_err());
    }
}
