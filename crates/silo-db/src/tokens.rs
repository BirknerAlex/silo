//! API and session tokens.
//!
//! ## Why tokens aren't password-hashed
//!
//! Passwords get argon2id here (see [`crate::users`]) because humans pick
//! low-entropy secrets and a memory-hard KDF is the only thing standing
//! between a leaked hash and a working credential.
//!
//! Tokens are different: Silo generates them, they carry 256 bits of
//! entropy from the OS CSPRNG, and they are presented on *every* request.
//! Brute-forcing a 256-bit random value is not a threat any KDF makes
//! meaningfully harder, while argon2's cost would land on the hot path of
//! every `dnf makecache`. So tokens use SHA-256 over
//! `salt || secret || pepper`:
//!
//! - **per-token random salt**, stored alongside the hash, so identical
//!   secrets across installs don't produce identical hashes and no
//!   precomputed table is reusable;
//! - **optional server-side pepper** from config (never in the database),
//!   so a database dump on its own — a backup leak, a read-only SQL
//!   injection — doesn't yield usable credentials;
//! - **constant-time comparison**, so verification doesn't leak the hash
//!   through timing.
//!
//! The wire format is `silo_<prefix>_<secret>`. The prefix is a public
//! lookup handle, which means verification is a single indexed lookup
//! instead of a scan-and-compare over every token row.

use std::fmt;
use std::str::FromStr;

use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{DateTime, Db};

const TOKEN_PREFIX: &str = "silo_";
const PREFIX_BYTES: usize = 6;
const SECRET_BYTES: usize = 32;
const SALT_BYTES: usize = 16;

/// How stale `last_used_at` is allowed to get. Without this, every single
/// package download would trigger a write to the tokens table.
const LAST_USED_REFRESH: chrono::Duration = chrono::Duration::minutes(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    /// Download packages and read indexes.
    Read,
    /// Everything `Read` can do, plus publishing.
    Write,
    /// Everything `Write` can do, plus managing tokens, users, and
    /// reading the audit log.
    Admin,
}

impl Permission {
    pub fn as_str(&self) -> &'static str {
        match self {
            Permission::Read => "read",
            Permission::Write => "write",
            Permission::Admin => "admin",
        }
    }

    /// Permissions are a total order, so "does this token satisfy the
    /// requirement" is just a comparison.
    pub fn satisfies(&self, required: Permission) -> bool {
        *self >= required
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Permission {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "read" | "ro" => Ok(Permission::Read),
            "write" | "rw" | "read-write" | "readwrite" => Ok(Permission::Write),
            "admin" => Ok(Permission::Admin),
            other => anyhow::bail!("unknown permission `{other}` (expected read, write, or admin)"),
        }
    }
}

/// Which repos a token may act on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scope {
    /// Every repo, including ones created after the token was issued.
    All,
    /// Exactly the listed repos. A single-repo token is just the
    /// one-element case — there's no separate variant for it, because
    /// nothing downstream would treat it differently.
    Repos(Vec<String>),
}

impl Scope {
    pub fn covers(&self, repo: &str) -> bool {
        match self {
            Scope::All => true,
            Scope::Repos(repos) => repos.iter().any(|r| r == repo),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Scope::All => "*".to_string(),
            Scope::Repos(repos) if repos.is_empty() => "(none)".to_string(),
            Scope::Repos(repos) => repos.join(","),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenKind {
    /// Long-lived, created explicitly by an admin or by the bootstrap path.
    Api,
    /// Short-lived, issued by `silo login` and tied to a user.
    Session,
}

impl TokenKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenKind::Api => "api",
            TokenKind::Session => "session",
        }
    }
}

/// A token row, minus the secret (which is unrecoverable by design).
#[derive(Debug, Clone)]
pub struct Token {
    pub id: Uuid,
    pub name: String,
    pub prefix: String,
    pub permission: Permission,
    pub kind: TokenKind,
    pub scope: Scope,
    pub user_id: Option<Uuid>,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime,
    pub expires_at: Option<DateTime>,
    pub last_used_at: Option<DateTime>,
    pub revoked_at: Option<DateTime>,
}

impl Token {
    pub fn is_active(&self, now: DateTime) -> bool {
        self.revoked_at.is_none() && self.expires_at.map(|e| e > now).unwrap_or(true)
    }

    /// The single authorization question the rest of the codebase asks.
    pub fn allows(&self, repo: &str, required: Permission) -> bool {
        self.permission.satisfies(required) && self.scope.covers(repo)
    }
}

/// What to create. `expires_at: None` means "never expires".
#[derive(Debug, Clone)]
pub struct NewToken {
    pub name: String,
    pub permission: Permission,
    pub kind: TokenKind,
    pub scope: Scope,
    pub user_id: Option<Uuid>,
    pub created_by: Option<Uuid>,
    pub expires_at: Option<DateTime>,
}

/// A freshly created token. `secret` is the only time the full token
/// string exists anywhere — it is not recoverable afterwards.
#[derive(Debug, Clone)]
pub struct IssuedToken {
    pub token: Token,
    pub secret: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("malformed token")]
    Malformed,
    #[error("unknown token")]
    Unknown,
    #[error("token has been revoked")]
    Revoked,
    #[error("token expired at {0}")]
    Expired(DateTime),
    #[error("the account this token belongs to is disabled")]
    UserDisabled,
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

#[derive(FromRow)]
struct TokenRow {
    id: Uuid,
    name: String,
    prefix: String,
    salt: Vec<u8>,
    secret_hash: Vec<u8>,
    permission: String,
    kind: String,
    scope_all: bool,
    repos: Vec<String>,
    user_id: Option<Uuid>,
    created_by: Option<Uuid>,
    created_at: DateTime,
    expires_at: Option<DateTime>,
    last_used_at: Option<DateTime>,
    revoked_at: Option<DateTime>,
}

impl TokenRow {
    fn into_token(self) -> Token {
        Token {
            id: self.id,
            name: self.name,
            prefix: self.prefix,
            // Unknown strings can only come from hand-edited rows; falling
            // back to the least privileged value is the safe reading.
            permission: self.permission.parse().unwrap_or(Permission::Read),
            kind: if self.kind == "session" {
                TokenKind::Session
            } else {
                TokenKind::Api
            },
            scope: if self.scope_all {
                Scope::All
            } else {
                Scope::Repos(self.repos)
            },
            user_id: self.user_id,
            created_by: self.created_by,
            created_at: self.created_at,
            expires_at: self.expires_at,
            last_used_at: self.last_used_at,
            revoked_at: self.revoked_at,
        }
    }
}

const SELECT_COLUMNS: &str = "id, name, prefix, salt, secret_hash, permission, kind, scope_all, \
                              repos, user_id, created_by, created_at, expires_at, last_used_at, \
                              revoked_at";

impl Db {
    pub async fn create_token(
        &self,
        new: NewToken,
        pepper: Option<&str>,
    ) -> anyhow::Result<IssuedToken> {
        // Generated in a helper so the non-`Send` `ThreadRng` is dropped
        // before the first `.await`; holding one across an await point
        // makes the whole future non-`Send` and unusable in a handler.
        let (prefix_bytes, secret_bytes, salt) = random_token_material();

        let prefix = hex::encode(prefix_bytes);
        let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret_bytes);
        let hash = hash_secret(&salt, &secret, pepper);

        let (scope_all, repos) = match &new.scope {
            Scope::All => (true, Vec::new()),
            Scope::Repos(repos) => (false, repos.clone()),
        };

        let id = Uuid::new_v4();
        let row: TokenRow = sqlx::query_as(&format!(
            "INSERT INTO tokens (id, name, prefix, salt, secret_hash, permission, kind, \
                                 scope_all, repos, user_id, created_by, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
             RETURNING {SELECT_COLUMNS}"
        ))
        .bind(id)
        .bind(&new.name)
        .bind(&prefix)
        .bind(salt.as_slice())
        .bind(hash.as_slice())
        .bind(new.permission.as_str())
        .bind(new.kind.as_str())
        .bind(scope_all)
        .bind(&repos)
        .bind(new.user_id)
        .bind(new.created_by)
        .bind(new.expires_at)
        .fetch_one(self.pool())
        .await?;

        Ok(IssuedToken {
            token: row.into_token(),
            secret: format!("{TOKEN_PREFIX}{prefix}_{secret}"),
        })
    }

    /// Verifies a presented token string. Returns the token row only if
    /// the secret matches and the token is active.
    pub async fn verify_token(
        &self,
        presented: &str,
        pepper: Option<&str>,
    ) -> Result<Token, AuthError> {
        let (prefix, secret) = split_token(presented).ok_or(AuthError::Malformed)?;

        let row: Option<TokenRow> = sqlx::query_as(&format!(
            "SELECT {SELECT_COLUMNS} FROM tokens WHERE prefix = $1"
        ))
        .bind(prefix)
        .fetch_optional(self.pool())
        .await?;
        let row = row.ok_or(AuthError::Unknown)?;

        let expected = hash_secret(&row.salt, secret, pepper);
        if !constant_time_eq(&expected, &row.secret_hash) {
            return Err(AuthError::Unknown);
        }

        // A disabled account must not keep working through tokens it
        // issued earlier, so the check follows the token to its owner.
        if let Some(user_id) = row.user_id {
            let disabled: Option<(bool,)> =
                sqlx::query_as("SELECT disabled FROM users WHERE id = $1")
                    .bind(user_id)
                    .fetch_optional(self.pool())
                    .await?;
            if disabled.map(|(d,)| d).unwrap_or(true) {
                return Err(AuthError::UserDisabled);
            }
        }

        let token = row.into_token();
        let now = chrono::Utc::now();
        if token.revoked_at.is_some() {
            return Err(AuthError::Revoked);
        }
        if let Some(expires_at) = token.expires_at {
            if expires_at <= now {
                return Err(AuthError::Expired(expires_at));
            }
        }

        let stale = token
            .last_used_at
            .map(|t| now - t > LAST_USED_REFRESH)
            .unwrap_or(true);
        if stale {
            // Best-effort: a failed bookkeeping write must not fail an
            // otherwise valid request.
            let _ = sqlx::query("UPDATE tokens SET last_used_at = now() WHERE id = $1")
                .bind(token.id)
                .execute(self.pool())
                .await;
        }

        Ok(token)
    }

    pub async fn list_tokens(&self, include_revoked: bool) -> anyhow::Result<Vec<Token>> {
        let rows: Vec<TokenRow> = sqlx::query_as(&format!(
            "SELECT {SELECT_COLUMNS} FROM tokens \
             WHERE ($1 OR revoked_at IS NULL) AND kind = 'api' \
             ORDER BY created_at DESC"
        ))
        .bind(include_revoked)
        .fetch_all(self.pool())
        .await?;
        Ok(rows.into_iter().map(TokenRow::into_token).collect())
    }

    pub async fn find_token_by_name(&self, name: &str) -> anyhow::Result<Option<Token>> {
        let row: Option<TokenRow> = sqlx::query_as(&format!(
            "SELECT {SELECT_COLUMNS} FROM tokens WHERE name = $1 AND revoked_at IS NULL \
             ORDER BY created_at DESC LIMIT 1"
        ))
        .bind(name)
        .fetch_optional(self.pool())
        .await?;
        Ok(row.map(TokenRow::into_token))
    }

    /// Revokes by id or by name prefix. Returns the number of tokens
    /// affected; already-revoked tokens are not counted again.
    pub async fn revoke_token(&self, id: Uuid) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
        )
        .bind(id)
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// True when no non-revoked API token exists. Used to decide whether
    /// the bootstrap token needs to be minted on startup.
    pub async fn has_any_api_token(&self) -> anyhow::Result<bool> {
        let (count,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM tokens WHERE kind = 'api' AND revoked_at IS NULL \
             AND (expires_at IS NULL OR expires_at > now())",
        )
        .fetch_one(self.pool())
        .await?;
        Ok(count > 0)
    }

    /// Drops session tokens that expired more than a day ago. Called
    /// periodically so the table doesn't grow without bound.
    pub async fn purge_expired_sessions(&self) -> anyhow::Result<u64> {
        let result = sqlx::query(
            "DELETE FROM tokens WHERE kind = 'session' \
             AND expires_at IS NOT NULL AND expires_at < now() - interval '1 day'",
        )
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected())
    }
}

fn random_token_material() -> ([u8; PREFIX_BYTES], [u8; SECRET_BYTES], [u8; SALT_BYTES]) {
    let mut rng = rand::thread_rng();
    let mut prefix = [0u8; PREFIX_BYTES];
    let mut secret = [0u8; SECRET_BYTES];
    let mut salt = [0u8; SALT_BYTES];
    rng.fill_bytes(&mut prefix);
    rng.fill_bytes(&mut secret);
    rng.fill_bytes(&mut salt);
    (prefix, secret, salt)
}

fn hash_secret(salt: &[u8], secret: &str, pepper: Option<&str>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(secret.as_bytes());
    if let Some(pepper) = pepper {
        hasher.update(pepper.as_bytes());
    }
    hasher.finalize().to_vec()
}

/// Compares without early exit. Length is not secret here (both sides are
/// always 32-byte SHA-256 outputs), but a mismatch must not be detectable
/// from how long the comparison took.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Splits `silo_<prefix>_<secret>` into its two halves.
fn split_token(presented: &str) -> Option<(&str, &str)> {
    let rest = presented.strip_prefix(TOKEN_PREFIX)?;
    let (prefix, secret) = rest.split_once('_')?;
    if prefix.len() != PREFIX_BYTES * 2 || secret.is_empty() {
        return None;
    }
    Some((prefix, secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissions_are_ordered_read_write_admin() {
        assert!(Permission::Admin.satisfies(Permission::Write));
        assert!(Permission::Write.satisfies(Permission::Read));
        assert!(!Permission::Read.satisfies(Permission::Write));
        assert!(Permission::Read.satisfies(Permission::Read));
    }

    #[test]
    fn permission_parses_common_spellings() {
        assert_eq!("rw".parse::<Permission>().unwrap(), Permission::Write);
        assert_eq!(
            "read-write".parse::<Permission>().unwrap(),
            Permission::Write
        );
        assert_eq!("READ".parse::<Permission>().unwrap(), Permission::Read);
        assert!("root".parse::<Permission>().is_err());
    }

    #[test]
    fn scope_all_covers_repos_created_later() {
        assert!(Scope::All.covers("anything"));
    }

    #[test]
    fn repo_scope_is_exact() {
        let scope = Scope::Repos(vec!["a".into(), "b".into()]);
        assert!(scope.covers("a"));
        assert!(scope.covers("b"));
        assert!(!scope.covers("c"));
        assert!(!scope.covers("ab"));
    }

    #[test]
    fn empty_repo_scope_covers_nothing() {
        assert!(!Scope::Repos(vec![]).covers("a"));
    }

    fn token(permission: Permission, scope: Scope) -> Token {
        Token {
            id: Uuid::nil(),
            name: "t".into(),
            prefix: "0".repeat(12),
            permission,
            kind: TokenKind::Api,
            scope,
            user_id: None,
            created_by: None,
            created_at: chrono::Utc::now(),
            expires_at: None,
            last_used_at: None,
            revoked_at: None,
        }
    }

    #[test]
    fn allows_requires_both_permission_and_scope() {
        let t = token(Permission::Write, Scope::Repos(vec!["myrepo".into()]));
        assert!(t.allows("myrepo", Permission::Write));
        assert!(t.allows("myrepo", Permission::Read));
        assert!(!t.allows("other", Permission::Read));
        assert!(!t.allows("myrepo", Permission::Admin));
    }

    #[test]
    fn expiry_and_revocation_deactivate_a_token() {
        let now = chrono::Utc::now();
        let mut t = token(Permission::Read, Scope::All);
        assert!(t.is_active(now));

        t.expires_at = Some(now - chrono::Duration::seconds(1));
        assert!(!t.is_active(now));

        t.expires_at = Some(now + chrono::Duration::hours(1));
        assert!(t.is_active(now));

        t.revoked_at = Some(now);
        assert!(!t.is_active(now));
    }

    #[test]
    fn token_strings_split_into_prefix_and_secret() {
        let prefix = "a".repeat(12);
        let raw = format!("silo_{prefix}_deadbeefsecret");
        assert_eq!(split_token(&raw), Some((prefix.as_str(), "deadbeefsecret")));
    }

    #[test]
    fn malformed_token_strings_are_rejected() {
        assert!(split_token("nope").is_none());
        assert!(split_token("silo_short_secret").is_none());
        assert!(split_token("silo_aaaaaaaaaaaa_").is_none());
        assert!(split_token(&format!("silo_{}", "a".repeat(12))).is_none());
    }

    #[test]
    fn generated_token_material_is_random_and_correctly_sized() {
        let (prefix_a, secret_a, salt_a) = random_token_material();
        let (prefix_b, secret_b, salt_b) = random_token_material();
        assert_eq!(secret_a.len(), 32, "tokens must carry 256 bits of entropy");
        assert_ne!(prefix_a, prefix_b);
        assert_ne!(secret_a, secret_b);
        assert_ne!(salt_a, salt_b);
    }

    #[test]
    fn hashing_is_salted_and_peppered() {
        let a = hash_secret(b"salt-one", "secret", None);
        let b = hash_secret(b"salt-two", "secret", None);
        let c = hash_secret(b"salt-one", "secret", Some("pepper"));
        assert_ne!(a, b, "different salts must yield different hashes");
        assert_ne!(a, c, "the pepper must change the hash");
        assert_eq!(a, hash_secret(b"salt-one", "secret", None));
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn constant_time_eq_matches_normal_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn scope_describe_is_human_readable() {
        assert_eq!(Scope::All.describe(), "*");
        assert_eq!(Scope::Repos(vec!["a".into(), "b".into()]).describe(), "a,b");
        assert_eq!(Scope::Repos(vec![]).describe(), "(none)");
    }
}
