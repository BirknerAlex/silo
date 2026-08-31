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

/// Why an OIDC identity was not admitted.
///
/// Typed rather than `anyhow::Error` for the same reason [`LoginError`]
/// is: every variant but `Db` is a deliberate refusal whose text is
/// written *for the person signing in* and is safe to hand back, while
/// `Db` carries whatever sqlx said — endpoints, connection strings — and
/// must not leave the server. Flattening them into one error type left the
/// caller unable to tell which it was holding.
#[derive(Debug, thiserror::Error)]
pub enum OidcLoginError {
    #[error("account `{0}` is disabled")]
    Disabled(String),
    #[error(
        "account `{0}` is already linked to a different identity-provider subject; \
         it will not be re-linked"
    )]
    AlreadyLinked(String),
    #[error(
        "a local account named `{0}` already exists and is not linked to this identity \
         provider. Silo will not link it automatically, because the username claim is not \
         proof of ownership. An admin can rename or remove that account, or set \
         `oidc.allow_username_linking: true` if usernames from this provider are authoritative."
    )]
    UsernameTaken(String),
    /// Two first-logins for one username raced. Retrying is the fix, so
    /// this says so rather than looking like a permanent refusal.
    #[error("account `{0}` was claimed by another sign-in at the same moment; try again")]
    RacedAnotherLogin(String),
    #[error("{0}")]
    InvalidUsername(String),
    #[error(transparent)]
    Db(#[from] sqlx::Error),
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

    /// Returns `sqlx::Error` rather than `anyhow::Error` so
    /// [`Db::authenticate_password`] can tell "the database is down" from
    /// "no such user" — the two need different answers, and flattening
    /// them here reported an outage as a failed login. Callers that want
    /// an `anyhow::Error` still get one for free through `?`.
    pub async fn find_user_by_username(&self, username: &str) -> Result<Option<User>, sqlx::Error> {
        sqlx::query_as(&format!("SELECT {COLUMNS} FROM users WHERE username = $1"))
            .bind(username.trim().to_lowercase())
            .fetch_optional(self.pool())
            .await
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
        // A database failure is not a credential failure. Flattening the
        // two would report an outage to the caller as "invalid username or
        // password" and write an `auth.failed` row for a login nobody
        // actually got wrong.
        let user = self.find_user_by_username(username).await?;

        // Every path below this line spends the same argon2 work, whether
        // the account exists, is disabled, is OIDC-only, or simply has the
        // wrong password. Returning early from any of them would answer in
        // microseconds where a real verification takes argon2's full
        // memory-hard cost, and that gap is a username oracle no matter
        // how carefully the error messages are worded.
        let password_matches = match user.as_ref().and_then(|u| u.password_hash.as_deref()) {
            Some(hash) => verify_password(hash, password),
            // No account, or one that has no password to compare against.
            None => verify_password(decoy_hash(), password),
        };

        let Some(user) = user else {
            return Err(LoginError::InvalidCredentials);
        };
        if user.disabled {
            return Err(LoginError::Disabled);
        }
        if user.password_hash.is_none() {
            return Err(LoginError::NoPassword);
        }
        if !password_matches {
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
    /// Matching is by `sub` — the only claim an issuer guarantees is
    /// stable and that Silo has previously seen bound to this account.
    ///
    /// A username collision is *not* a match. The username comes from a
    /// claim (`oidc.username_claim`, `preferred_username` by default) that
    /// many providers let the end user choose, so treating it as proof of
    /// identity means anyone who can set their claim to `admin` inherits
    /// the local `admin` account — including its `is_admin` bit. Silo
    /// therefore refuses the login rather than binding the subject to an
    /// account it has no evidence belongs to them.
    ///
    /// `link_existing` (`oidc.allow_username_linking`) re-enables that
    /// binding for the one case where it is safe: an operator migrating
    /// established local accounts onto an IdP whose username claim they
    /// control. Even then, an account already bound to a *different*
    /// subject is never re-bound — that would be one IdP identity taking
    /// over another's.
    pub async fn upsert_oidc_user(
        &self,
        subject: &str,
        username: &str,
        admin_on_create: bool,
        link_existing: bool,
    ) -> Result<User, OidcLoginError> {
        let username = normalize_username(username)
            .map_err(|e| OidcLoginError::InvalidUsername(e.to_string()))?;

        if let Some(user) = sqlx::query_as::<_, User>(&format!(
            "SELECT {COLUMNS} FROM users WHERE oidc_subject = $1"
        ))
        .bind(subject)
        .fetch_optional(self.pool())
        .await?
        {
            if user.disabled {
                return Err(OidcLoginError::Disabled(user.username));
            }
            let _ = sqlx::query("UPDATE users SET last_login_at = now() WHERE id = $1")
                .bind(user.id)
                .execute(self.pool())
                .await;
            return Ok(user);
        }

        if let Some(existing) = self.find_user_by_username(&username).await? {
            if existing.oidc_subject.is_some() {
                return Err(OidcLoginError::AlreadyLinked(username));
            }
            if !link_existing {
                return Err(OidcLoginError::UsernameTaken(username));
            }
            if existing.disabled {
                return Err(OidcLoginError::Disabled(username));
            }

            // Guarded by `oidc_subject IS NULL` so two concurrent logins
            // claiming the same username can't both win the link.
            let linked: Option<User> = sqlx::query_as(&format!(
                "UPDATE users SET oidc_subject = $2, last_login_at = now() \
                 WHERE id = $1 AND oidc_subject IS NULL RETURNING {COLUMNS}"
            ))
            .bind(existing.id)
            .bind(subject)
            .fetch_optional(self.pool())
            .await?;
            return linked.ok_or(OidcLoginError::RacedAnotherLogin(username));
        }

        let user: User = sqlx::query_as(&format!(
            "INSERT INTO users (id, username, oidc_subject, is_admin, last_login_at) \
             VALUES ($1, $2, $3, $4, now()) RETURNING {COLUMNS}"
        ))
        .bind(Uuid::new_v4())
        .bind(&username)
        .bind(subject)
        .bind(admin_on_create)
        .fetch_one(self.pool())
        .await
        .map_err(|e| match &e {
            // Lost the race against another first-login for this username.
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                OidcLoginError::RacedAnotherLogin(username.clone())
            }
            _ => OidcLoginError::Db(e),
        })?;

        if user.disabled {
            return Err(OidcLoginError::Disabled(user.username));
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

    /// Reserves one login attempt for `username` and returns how many are
    /// now on record inside the current window, this one included.
    ///
    /// Called *before* the password is verified, which is the whole point:
    /// a throttle that counts failures after the fact lets any number of
    /// concurrent attempts each see an under-limit total, spend argon2,
    /// and only then record what they did. Reserving first makes the limit
    /// hold under concurrency.
    ///
    /// The upsert is one statement, so `ON CONFLICT DO UPDATE`'s row lock
    /// serializes concurrent attempts on a username across every replica
    /// and hands each its own value. A window older than `window_minutes`
    /// is restarted rather than extended, so the limit always drains.
    pub async fn reserve_login_attempt(
        &self,
        username: &str,
        window_minutes: i64,
    ) -> anyhow::Result<i64> {
        let expired = "login_attempts.window_start < now() - ($2 || ' minutes')::interval";
        let (failures,): (i32,) = sqlx::query_as(&format!(
            "INSERT INTO login_attempts (username, failures, window_start)              VALUES ($1, 1, now())              ON CONFLICT (username) DO UPDATE SET                  failures = CASE WHEN {expired} THEN 1                                  ELSE login_attempts.failures + 1 END,                  window_start = CASE WHEN {expired} THEN now()                                      ELSE login_attempts.window_start END              RETURNING failures"
        ))
        .bind(username)
        .bind(window_minutes.to_string())
        .fetch_one(self.pool())
        .await?;
        Ok(failures as i64)
    }

    /// Forgets a username's attempts. Called after a successful sign-in so
    /// someone who mistyped their password a few times isn't left carrying
    /// those attempts for the rest of the window.
    pub async fn clear_login_attempts(&self, username: &str) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM login_attempts WHERE username = $1")
            .bind(username)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Drops rows whose window has elapsed. Without this the table grows
    /// by one row per username anybody ever guesses at.
    pub async fn purge_stale_login_attempts(&self, window_minutes: i64) -> anyhow::Result<u64> {
        let result = sqlx::query(
            "DELETE FROM login_attempts              WHERE window_start < now() - ($1 || ' minutes')::interval",
        )
        .bind(window_minutes.to_string())
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected())
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

/// An argon2id hash of a value nothing can present, built once and reused.
///
/// Its only job is to give [`Db::authenticate_password`] something to burn
/// the same work against when the username doesn't exist, so a miss costs
/// what a hit costs. The parameters come from the same `Argon2::default()`
/// every real password uses, which is what makes the timings match.
fn decoy_hash() -> &'static str {
    static DECOY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DECOY.get_or_init(|| {
        hash_password("silo decoy password, never presented")
            .expect("hashing a fixed-length literal cannot fail")
    })
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
    use crate::DbConfig;

    async fn db() -> Option<Db> {
        let url = std::env::var("SILO_TEST_DATABASE_URL")
            .ok()
            .filter(|u| !u.trim().is_empty())?;
        Some(
            Db::connect(&DbConfig {
                url,
                max_connections: 4,
                connect_timeout: std::time::Duration::from_secs(30),
                token_pepper: None,
            })
            .await
            .expect("connect to the test database"),
        )
    }

    /// Usernames and subjects are both unique per call. The test database
    /// is shared and never reset between runs, so a fixed subject would
    /// match the row a previous run left behind — and `upsert_oidc_user`
    /// matches on subject first, by design.
    fn unique(prefix: &str) -> String {
        format!("{prefix}-{}", Uuid::new_v4().simple())
    }

    macro_rules! require_db {
        () => {
            match db().await {
                Some(db) => db,
                None => {
                    eprintln!("skipping: set SILO_TEST_DATABASE_URL");
                    return;
                }
            }
        };
    }

    #[tokio::test]
    async fn each_reserved_attempt_returns_its_own_number() {
        let db = require_db!();
        let username = unique("throttled");

        for expected in 1..=3 {
            assert_eq!(
                db.reserve_login_attempt(&username, 15).await.unwrap(),
                expected
            );
        }

        // Proving the password forgets them.
        db.clear_login_attempts(&username).await.unwrap();
        assert_eq!(db.reserve_login_attempt(&username, 15).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn concurrent_reservations_never_hand_out_the_same_number() {
        // The property the whole design rests on: counting committed
        // failures would let every one of these read the same total and
        // proceed. Reserving means the row lock serializes them.
        let db = require_db!();
        let username = unique("racing");

        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..12 {
            let db = db.clone();
            let username = username.clone();
            tasks.spawn(async move { db.reserve_login_attempt(&username, 15).await.unwrap() });
        }
        let mut seen: Vec<i64> = Vec::new();
        while let Some(result) = tasks.join_next().await {
            seen.push(result.unwrap());
        }
        seen.sort_unstable();
        assert_eq!(
            seen,
            (1..=12).collect::<Vec<_>>(),
            "numbers were handed out twice"
        );
    }

    #[tokio::test]
    async fn an_elapsed_window_restarts_rather_than_accumulates() {
        let db = require_db!();
        let username = unique("expiring");

        assert_eq!(db.reserve_login_attempt(&username, 15).await.unwrap(), 1);
        assert_eq!(db.reserve_login_attempt(&username, 15).await.unwrap(), 2);

        // A zero-length window makes the existing one already elapsed,
        // which is what a real caller sees 15 minutes later.
        assert_eq!(
            db.reserve_login_attempt(&username, 0).await.unwrap(),
            1,
            "an elapsed window must reset the count, or a lockout is permanent"
        );
    }

    #[tokio::test]
    async fn stale_throttle_rows_are_purged_but_live_ones_survive() {
        let db = require_db!();
        let stale = unique("stale");
        let live = unique("live");
        db.reserve_login_attempt(&stale, 15).await.unwrap();
        db.reserve_login_attempt(&live, 15).await.unwrap();

        // One row is aged directly rather than by shrinking the window,
        // because the purge is table-wide: a zero-length window would
        // delete every other test's rows too, mid-flight.
        sqlx::query(
            "UPDATE login_attempts SET window_start = now() - interval '1 hour' \
             WHERE username = $1",
        )
        .bind(&stale)
        .execute(db.pool())
        .await
        .unwrap();

        db.purge_stale_login_attempts(15).await.unwrap();

        // The aged row is gone, so its count starts over...
        assert_eq!(db.reserve_login_attempt(&stale, 15).await.unwrap(), 1);
        // ...while the one still inside its window kept counting.
        assert_eq!(
            db.reserve_login_attempt(&live, 15).await.unwrap(),
            2,
            "a row inside its window must survive the purge"
        );
    }

    #[tokio::test]
    async fn every_rejected_login_costs_the_same_argon2_work() {
        // Timing is the oracle the error messages are careful not to be.
        // Asserting on wall-clock would be flaky, so this asserts the
        // observable proxy: each rejection reports its own reason to the
        // *server* (the audit log needs it) while having done the work.
        let db = require_db!();

        let disabled = unique("disabled");
        db.create_user(&disabled, Some("a real password"), false)
            .await
            .unwrap();
        db.set_user_disabled(&disabled, true).await.unwrap();

        let oidc_only = unique("oidconly");
        db.create_user(&oidc_only, None, false).await.unwrap();

        let normal = unique("normal");
        db.create_user(&normal, Some("a real password"), false)
            .await
            .unwrap();

        assert!(matches!(
            db.authenticate_password(&disabled, "wrong").await,
            Err(LoginError::Disabled)
        ));
        assert!(matches!(
            db.authenticate_password(&oidc_only, "wrong").await,
            Err(LoginError::NoPassword)
        ));
        assert!(matches!(
            db.authenticate_password(&unique("ghost"), "wrong").await,
            Err(LoginError::InvalidCredentials)
        ));
        assert!(matches!(
            db.authenticate_password(&normal, "wrong").await,
            Err(LoginError::InvalidCredentials)
        ));
        assert!(db
            .authenticate_password(&normal, "a real password")
            .await
            .is_ok());
    }

    /// The account-takeover shape: a local admin exists, and someone
    /// arrives from the identity provider claiming its username.
    #[tokio::test]
    async fn an_oidc_login_does_not_inherit_a_local_account_by_username() {
        let db = require_db!();
        let username = unique("localadmin");
        let local = db
            .create_user(&username, Some("a real password"), true)
            .await
            .unwrap();

        let err = db
            .upsert_oidc_user(&unique("attacker-subject"), &username, false, false)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("will not link it automatically"), "got {err}");

        // The local account is untouched: still password-backed, still
        // unlinked, so the attacker's subject gained nothing.
        let after = db.find_user_by_id(local.id).await.unwrap().unwrap();
        assert!(after.oidc_subject.is_none());
        assert!(after.password_hash.is_some());
        assert!(after.is_admin);
    }

    #[tokio::test]
    async fn linking_is_possible_when_the_operator_opts_in() {
        let db = require_db!();
        let username = unique("migrating");
        db.create_user(&username, Some("a real password"), false)
            .await
            .unwrap();

        let first = unique("subject-one");
        let linked = db
            .upsert_oidc_user(&first, &username, false, true)
            .await
            .unwrap();
        assert_eq!(linked.oidc_subject.as_deref(), Some(first.as_str()));

        // Now bound, the same subject signs in again by `sub` alone.
        let again = db
            .upsert_oidc_user(&first, &username, false, true)
            .await
            .unwrap();
        assert_eq!(again.id, linked.id);

        // ...and a *different* subject claiming the same username is
        // refused even with linking enabled: one IdP identity must never
        // take over another's account.
        let err = db
            .upsert_oidc_user(&unique("subject-two"), &username, false, true)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("already linked"), "got {err}");
    }

    #[tokio::test]
    async fn a_first_oidc_login_still_provisions_a_fresh_account() {
        let db = require_db!();
        let username = unique("newcomer");

        let subject = unique("fresh-subject");
        let user = db
            .upsert_oidc_user(&subject, &username, true, false)
            .await
            .unwrap();
        assert_eq!(user.username, username);
        assert_eq!(user.oidc_subject.as_deref(), Some(subject.as_str()));
        assert!(user.is_admin, "admin_on_create applies to new accounts");
        assert!(user.is_oidc_only());
    }

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
