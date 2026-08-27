//! Users: local password accounts and OIDC-linked accounts.
//!
//! Deliberately minimal — a username, an optional password, an optional
//! OIDC subject, and an admin flag. No names, no email, no groups. Silo's
//! authorization decisions are made against *tokens*, and a user is only
//! ever the thing that mints them, so anything richer would be carried
//! around without being read.
//!
//! Passwords use argon2id with per-password random salts (encoded in the
//! PHC string, which is what `password_hash` stores). Unlike tokens —
//! which are 256-bit random values, see [`crate::tokens`] — passwords are
//! human-chosen and low-entropy, so the memory-hard KDF is doing real work
//! here.

use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::Argon2;
use sqlx::FromRow;
use uuid::Uuid;

use crate::{DateTime, Db};

#[derive(Debug, Clone, FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    #[sqlx(default)]
    pub password_hash: Option<String>,
    pub oidc_subject: Option<String>,
    pub is_admin: bool,
    pub disabled: bool,
    pub created_at: DateTime,
    pub last_login_at: Option<DateTime>,
}

impl User {
    /// True when this account can only sign in through the identity
    /// provider.
    pub fn is_oidc_only(&self) -> bool {
        self.password_hash.is_none()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    #[error("invalid username or password")]
    InvalidCredentials,
    #[error("this account is disabled")]
    Disabled,
    #[error("this account has no password set; sign in through your identity provider")]
    NoPassword,
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

const COLUMNS: &str =
    "id, username, password_hash, oidc_subject, is_admin, disabled, created_at, last_login_at";

impl Db {
    pub async fn create_user(
        &self,
        username: &str,
        password: Option<&str>,
        is_admin: bool,
    ) -> anyhow::Result<User> {
        let username = normalize_username(username)?;
        let password_hash = password.map(hash_password).transpose()?;

        let user: User = sqlx::query_as(&format!(
            "INSERT INTO users (id, username, password_hash, is_admin) \
             VALUES ($1, $2, $3, $4) RETURNING {COLUMNS}"
        ))
        .bind(Uuid::new_v4())
        .bind(&username)
        .bind(password_hash)
        .bind(is_admin)
        .fetch_one(self.pool())
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                anyhow::anyhow!("user `{username}` already exists")
            }
            _ => e.into(),
        })?;
        Ok(user)
    }

    pub async fn find_user_by_username(&self, username: &str) -> anyhow::Result<Option<User>> {
        Ok(
            sqlx::query_as(&format!("SELECT {COLUMNS} FROM users WHERE username = $1"))
                .bind(username.trim().to_lowercase())
                .fetch_optional(self.pool())
                .await?,
        )
    }

    pub async fn find_user_by_id(&self, id: Uuid) -> anyhow::Result<Option<User>> {
        Ok(
            sqlx::query_as(&format!("SELECT {COLUMNS} FROM users WHERE id = $1"))
                .bind(id)
                .fetch_optional(self.pool())
                .await?,
        )
    }

    pub async fn list_users(&self) -> anyhow::Result<Vec<User>> {
        Ok(
            sqlx::query_as(&format!("SELECT {COLUMNS} FROM users ORDER BY username"))
                .fetch_all(self.pool())
                .await?,
        )
    }

    /// Verifies a username/password pair and stamps `last_login_at`.
    pub async fn authenticate_password(
        &self,
        username: &str,
        password: &str,
    ) -> Result<User, LoginError> {
        let user = self
            .find_user_by_username(username)
            .await
            .map_err(|_| LoginError::InvalidCredentials)?
            .ok_or(LoginError::InvalidCredentials)?;

        if user.disabled {
            return Err(LoginError::Disabled);
        }
        let hash = user
            .password_hash
            .as_deref()
            .ok_or(LoginError::NoPassword)?;
        if !verify_password(hash, password) {
            return Err(LoginError::InvalidCredentials);
        }

        let _ = sqlx::query("UPDATE users SET last_login_at = now() WHERE id = $1")
            .bind(user.id)
            .execute(self.pool())
            .await;
        Ok(user)
    }

    /// Finds or provisions the local account for an OIDC identity.
    ///
    /// Matching is by `sub` first — the only claim an issuer guarantees is
    /// stable — and falls back to username so an existing local account
    /// gets *linked* rather than shadowed by a duplicate when its owner
    /// first signs in through the IdP.
    pub async fn upsert_oidc_user(
        &self,
        subject: &str,
        username: &str,
        admin_on_create: bool,
    ) -> anyhow::Result<User> {
        let username = normalize_username(username)?;

        if let Some(user) = sqlx::query_as::<_, User>(&format!(
            "SELECT {COLUMNS} FROM users WHERE oidc_subject = $1"
        ))
        .bind(subject)
        .fetch_optional(self.pool())
        .await?
        {
            if user.disabled {
                anyhow::bail!("account `{}` is disabled", user.username);
            }
            let _ = sqlx::query("UPDATE users SET last_login_at = now() WHERE id = $1")
                .bind(user.id)
                .execute(self.pool())
                .await;
            return Ok(user);
        }

        let user: User = sqlx::query_as(&format!(
            "INSERT INTO users (id, username, oidc_subject, is_admin, last_login_at) \
             VALUES ($1, $2, $3, $4, now()) \
             ON CONFLICT (username) DO UPDATE \
                SET oidc_subject = EXCLUDED.oidc_subject, last_login_at = now() \
             RETURNING {COLUMNS}"
        ))
        .bind(Uuid::new_v4())
        .bind(&username)
        .bind(subject)
        .bind(admin_on_create)
        .fetch_one(self.pool())
        .await?;

        if user.disabled {
            anyhow::bail!("account `{}` is disabled", user.username);
        }
        Ok(user)
    }

    pub async fn set_password(&self, id: Uuid, password: &str) -> anyhow::Result<()> {
        sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1")
            .bind(id)
            .bind(hash_password(password)?)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    pub async fn set_user_disabled(&self, username: &str, disabled: bool) -> anyhow::Result<bool> {
        let result = sqlx::query("UPDATE users SET disabled = $2 WHERE username = $1")
            .bind(username.trim().to_lowercase())
            .bind(disabled)
            .execute(self.pool())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_user(&self, username: &str) -> anyhow::Result<bool> {
        let result = sqlx::query("DELETE FROM users WHERE username = $1")
            .bind(username.trim().to_lowercase())
            .execute(self.pool())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn has_any_user(&self) -> anyhow::Result<bool> {
        let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM users")
            .fetch_one(self.pool())
            .await?;
        Ok(count > 0)
    }
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    if password.len() < 8 {
        anyhow::bail!("password must be at least 8 characters");
    }
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("failed to hash password: {e}"))
}

pub fn verify_password(phc: &str, password: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Usernames are lowercased so `Alice` and `alice` can't become two
/// accounts, and restricted to characters that survive being pasted into
/// a config file or a URL unescaped.
pub fn normalize_username(username: &str) -> anyhow::Result<String> {
    let username = username.trim().to_lowercase();
    if username.is_empty() || username.len() > 64 {
        anyhow::bail!("username must be between 1 and 64 characters");
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@'))
    {
        anyhow::bail!("username may only contain letters, digits, and the characters - _ . @");
    }
    Ok(username)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_verify_against_the_original_password() {
        let phc = hash_password("correct horse battery").unwrap();
        assert!(verify_password(&phc, "correct horse battery"));
        assert!(!verify_password(&phc, "wrong horse battery"));
    }

    #[test]
    fn hashes_are_argon2id_and_salted_per_password() {
        let a = hash_password("same password").unwrap();
        let b = hash_password("same password").unwrap();
        assert!(a.starts_with("$argon2id$"), "got {a}");
        assert_ne!(a, b, "each hash must carry its own random salt");
    }

    #[test]
    fn short_passwords_are_rejected() {
        assert!(hash_password("short").is_err());
        assert!(hash_password("longenough").is_ok());
    }

    #[test]
    fn garbage_hash_strings_never_verify() {
        assert!(!verify_password("not-a-phc-string", "anything"));
        assert!(!verify_password("", ""));
    }

    #[test]
    fn usernames_are_normalized_to_lowercase() {
        assert_eq!(normalize_username("  Alice  ").unwrap(), "alice");
        assert_eq!(
            normalize_username("bob@example.com").unwrap(),
            "bob@example.com"
        );
    }

    #[test]
    fn invalid_usernames_are_rejected() {
        assert!(normalize_username("").is_err());
        assert!(normalize_username("has space").is_err());
        assert!(normalize_username("slash/es").is_err());
        assert!(normalize_username(&"x".repeat(65)).is_err());
    }

    #[test]
    fn oidc_only_users_have_no_password() {
        let user = User {
            id: Uuid::nil(),
            username: "u".into(),
            password_hash: None,
            oidc_subject: Some("sub".into()),
            is_admin: false,
            disabled: false,
            created_at: chrono::Utc::now(),
            last_login_at: None,
        };
        assert!(user.is_oidc_only());
    }
}
