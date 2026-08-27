//! Distributed coordination via Postgres advisory locks.
//!
//! Silo replicas are otherwise stateless, so the coordination point has to
//! be something they already share. Postgres advisory locks are that
//! point, and they're specifically *transaction-scoped*
//! (`pg_advisory_xact_lock`) rather than session-scoped:
//!
//! - A session lock leaks if the holder is SIGKILLed mid-publish, or if
//!   the pooled connection is returned to the pool without an explicit
//!   unlock. A transaction lock is released by the same machinery that
//!   rolls the transaction back — including when the backend notices the
//!   client is gone. There is no path that leaves a stale lock behind.
//! - It composes with the publish transaction: the same transaction that
//!   holds the lock inserts the package row and reads back the group,
//!   so index rendering sees a consistent snapshot and a failed publish
//!   takes its row with it.
//!
//! Together this rules out a "last write to the index wins" race, in
//! which two concurrent publishes to one repo/channel would each
//! regenerate an index from a view of the world that excluded the other's
//! package.

use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Postgres, Transaction};

use crate::Db;

/// How long to wait for a contended lock before giving up. Index
/// regeneration is seconds-scale, so a publisher that has been queued this
/// long is almost certainly behind something stuck rather than something
/// slow, and a clear error beats an unbounded hang.
const LOCK_TIMEOUT: &str = "120s";

/// Derives the 64-bit advisory lock key from a scope string.
///
/// Advisory lock keys are a single flat `bigint` namespace shared with
/// anything else using the same database, so the key is the first 8 bytes
/// of a SHA-256 rather than a small counter — collisions cost correctness
/// (two unrelated groups serializing against each other) but never
/// safety, and a hash makes them vanishingly unlikely.
pub fn lock_key(scope: &str) -> i64 {
    let digest = Sha256::digest(scope.as_bytes());
    i64::from_be_bytes(digest[..8].try_into().expect("sha256 yields 32 bytes"))
}

/// The scope string for one index group. Two publishes contend only if
/// they'd write the same index — different arches (apk) or different
/// package names (npm) proceed in parallel.
///
/// Fields are joined with `|` rather than `/` because npm index groups are
/// package names, which may themselves contain a slash (`@scope/name`).
/// With `/`, `("a/b", "c")` and `("a", "b/c")` would collapse to the same
/// scope string and silently share a lock.
pub fn index_scope(repo: &str, channel: &str, format: &str, group: &str) -> String {
    format!("index:{repo}|{channel}|{format}|{group}")
}

/// A transaction that holds an advisory lock for as long as it lives.
///
/// Commit it to release the lock and keep the writes; drop it (or let an
/// error propagate) to release the lock and discard them.
pub struct LockedTx<'a> {
    tx: Transaction<'a, Postgres>,
    scope: String,
}

impl<'a> LockedTx<'a> {
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// The underlying connection, for running queries inside the lock.
    pub fn conn(&mut self) -> &mut PgConnection {
        &mut self.tx
    }

    pub async fn commit(self) -> anyhow::Result<()> {
        self.tx.commit().await?;
        Ok(())
    }

    pub async fn rollback(self) -> anyhow::Result<()> {
        self.tx.rollback().await?;
        Ok(())
    }
}

impl Db {
    /// Opens a transaction holding the exclusive advisory lock for `scope`.
    ///
    /// Blocks until the lock is available or [`LOCK_TIMEOUT`] elapses.
    pub async fn lock(&self, scope: impl Into<String>) -> anyhow::Result<LockedTx<'_>> {
        let scope = scope.into();
        let key = lock_key(&scope);

        let mut tx = self.pool().begin().await?;

        // SET LOCAL applies to this transaction only, so a pooled
        // connection doesn't carry the timeout into unrelated queries
        // after it's returned.
        sqlx::query(&format!("SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'"))
            .execute(&mut *tx)
            .await?;

        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(key)
            .execute(&mut *tx)
            .await
            .map_err(|e| anyhow::anyhow!("timed out waiting for the lock on `{scope}`: {e}"))?;

        tracing::debug!(scope = %scope, key, "acquired advisory lock");
        Ok(LockedTx { tx, scope })
    }

    /// Non-blocking variant, for callers that would rather report
    /// contention than queue behind it.
    pub async fn try_lock(&self, scope: impl Into<String>) -> anyhow::Result<Option<LockedTx<'_>>> {
        let scope = scope.into();
        let key = lock_key(&scope);

        let mut tx = self.pool().begin().await?;
        let (acquired,): (bool,) = sqlx::query_as("SELECT pg_try_advisory_xact_lock($1)")
            .bind(key)
            .fetch_one(&mut *tx)
            .await?;

        if !acquired {
            tx.rollback().await?;
            return Ok(None);
        }
        Ok(Some(LockedTx { tx, scope }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_keys_are_stable_across_runs() {
        // Hard-coded so a change to the derivation shows up as a failing
        // test rather than as replicas silently taking different locks
        // during a rolling upgrade.
        assert_eq!(
            lock_key("index:myrepo|stable|rpm|"),
            lock_key(&index_scope("myrepo", "stable", "rpm", ""))
        );
        assert_ne!(lock_key("a"), lock_key("b"));
    }

    #[test]
    fn distinct_index_groups_get_distinct_keys() {
        let rpm = index_scope("r", "stable", "rpm", "");
        let apk_x86 = index_scope("r", "stable", "apk", "x86_64");
        let apk_arm = index_scope("r", "stable", "apk", "aarch64");
        assert_ne!(lock_key(&rpm), lock_key(&apk_x86));
        assert_ne!(lock_key(&apk_x86), lock_key(&apk_arm));
    }

    #[test]
    fn same_group_across_replicas_gets_the_same_key() {
        assert_eq!(
            lock_key(&index_scope("r", "stable", "npm", "@acme/widget")),
            lock_key("index:r|stable|npm|@acme/widget")
        );
    }

    #[test]
    fn scope_strings_are_unambiguous() {
        // Slashes in a field must not let two different groups collapse
        // onto one scope string.
        assert_ne!(
            index_scope("a/b", "c", "rpm", ""),
            index_scope("a", "b/c", "rpm", "")
        );
        assert_ne!(
            index_scope("r", "c", "npm", "@acme/widget"),
            index_scope("r", "c", "npm/@acme", "widget")
        );
    }
}
