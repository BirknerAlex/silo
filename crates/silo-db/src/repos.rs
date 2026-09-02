//! Per-repo visibility.
//!
//! A repo row exists purely to carry the `public` bit — everything else
//! about a repo (what packages it holds, which channels, which formats)
//! is still derived from `packages`. A row shows up the moment a repo is
//! first published to, or the moment an admin sets its mode ahead of
//! that; either way `repo` is the primary key, so there's never more than
//! one.

use crate::Db;

impl Db {
    /// Creates the repo's row if it doesn't have one yet, defaulting to
    /// private. Called once per publish so every repo that has ever
    /// received a package has a row to look its mode up from.
    pub async fn ensure_repo(&self, repo: &str) -> anyhow::Result<()> {
        sqlx::query("INSERT INTO repos (repo) VALUES ($1) ON CONFLICT (repo) DO NOTHING")
            .bind(repo)
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Whether `repo` is public. A repo with no row (never published to,
    /// never explicitly configured) is treated as private — the safe
    /// default, and consistent with `ensure_repo`'s default.
    pub async fn is_repo_public(&self, repo: &str) -> anyhow::Result<bool> {
        let public: Option<bool> = sqlx::query_scalar("SELECT public FROM repos WHERE repo = $1")
            .bind(repo)
            .fetch_optional(self.pool())
            .await?;
        Ok(public.unwrap_or(false))
    }

    /// Sets a repo's mode, creating its row first if needed — an admin can
    /// configure a repo's visibility before anything has been published
    /// to it.
    pub async fn set_repo_public(&self, repo: &str, public: bool) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO repos (repo, public) VALUES ($1, $2) \
             ON CONFLICT (repo) DO UPDATE SET public = excluded.public, updated_at = now()",
        )
        .bind(repo)
        .bind(public)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Whether `repo` exists in any form — either it has a `repos` row, or
    /// it has packages. `packages.repo` carries no foreign key to `repos`,
    /// so a repo that predates `ensure_repo` (or one that lost its row some
    /// other way) can have packages without a row; checked here so `repo
    /// create` doesn't clobber it.
    pub async fn repo_exists(&self, repo: &str) -> anyhow::Result<bool> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM repos WHERE repo = $1) \
             OR EXISTS (SELECT 1 FROM packages WHERE repo = $1)",
        )
        .bind(repo)
        .fetch_one(self.pool())
        .await?;
        Ok(exists)
    }

    /// Creates a repo's row, failing (returning `false`) rather than
    /// upserting if it already exists — unlike `set_repo_public`, this is
    /// meant to be a distinct "create" verb, not an idempotent upsert.
    pub async fn create_repo(&self, repo: &str, public: bool) -> anyhow::Result<bool> {
        let inserted: Option<(String,)> = sqlx::query_as(
            "INSERT INTO repos (repo, public) VALUES ($1, $2) \
             ON CONFLICT (repo) DO NOTHING RETURNING repo",
        )
        .bind(repo)
        .bind(public)
        .fetch_optional(self.pool())
        .await?;
        Ok(inserted.is_some())
    }

    /// Deletes a repo's row along with any orphaned `prune_rules`/
    /// `prune_exemptions` for it, but only if it currently has no packages.
    /// Returns `false` (and changes nothing) if it does — including if a
    /// publish raced a package in between the caller's own emptiness check
    /// and this call, which is what the `NOT EXISTS` guard is for.
    pub async fn delete_repo(&self, repo: &str) -> anyhow::Result<bool> {
        let mut tx = self.pool().begin().await?;
        let deleted: Option<(String,)> = sqlx::query_as(
            "DELETE FROM repos WHERE repo = $1 \
             AND NOT EXISTS (SELECT 1 FROM packages WHERE packages.repo = repos.repo) \
             RETURNING repo",
        )
        .bind(repo)
        .fetch_optional(&mut *tx)
        .await?;
        if deleted.is_none() {
            tx.rollback().await?;
            return Ok(false);
        }
        sqlx::query("DELETE FROM prune_rules WHERE repo = $1")
            .bind(repo)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM prune_exemptions WHERE repo = $1")
            .bind(repo)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use crate::{Db, DbConfig};

    async fn db() -> Option<Db> {
        let url = std::env::var("SILO_TEST_DATABASE_URL").ok()?;
        if url.trim().is_empty() {
            return None;
        }
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

    fn unique_repo(prefix: &str) -> String {
        format!(
            "{prefix}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        )
    }

    #[tokio::test]
    async fn a_repo_with_no_row_is_private() {
        let Some(db) = db().await else {
            eprintln!("skipping: set SILO_TEST_DATABASE_URL");
            return;
        };
        let repo = unique_repo("norow");
        assert!(!db.is_repo_public(&repo).await.unwrap());
    }

    #[tokio::test]
    async fn ensure_repo_is_idempotent_and_defaults_private() {
        let Some(db) = db().await else {
            eprintln!("skipping: set SILO_TEST_DATABASE_URL");
            return;
        };
        let repo = unique_repo("ensure");
        db.ensure_repo(&repo).await.unwrap();
        db.ensure_repo(&repo).await.unwrap();
        assert!(!db.is_repo_public(&repo).await.unwrap());
    }

    #[tokio::test]
    async fn ensure_repo_never_resets_a_mode_that_was_already_set() {
        let Some(db) = db().await else {
            eprintln!("skipping: set SILO_TEST_DATABASE_URL");
            return;
        };
        let repo = unique_repo("keepmode");
        db.set_repo_public(&repo, true).await.unwrap();
        db.ensure_repo(&repo).await.unwrap();
        assert!(db.is_repo_public(&repo).await.unwrap());
    }

    #[tokio::test]
    async fn set_repo_public_upserts_before_any_row_exists() {
        let Some(db) = db().await else {
            eprintln!("skipping: set SILO_TEST_DATABASE_URL");
            return;
        };
        let repo = unique_repo("upsert");
        db.set_repo_public(&repo, true).await.unwrap();
        assert!(db.is_repo_public(&repo).await.unwrap());
        db.set_repo_public(&repo, false).await.unwrap();
        assert!(!db.is_repo_public(&repo).await.unwrap());
    }

    #[tokio::test]
    async fn create_repo_fails_the_second_time() {
        let Some(db) = db().await else {
            eprintln!("skipping: set SILO_TEST_DATABASE_URL");
            return;
        };
        let repo = unique_repo("create");
        assert!(!db.repo_exists(&repo).await.unwrap());
        assert!(db.create_repo(&repo, false).await.unwrap());
        assert!(db.repo_exists(&repo).await.unwrap());
        assert!(!db.create_repo(&repo, true).await.unwrap());
        // The failed second attempt must not have touched the mode set by
        // the first.
        assert!(!db.is_repo_public(&repo).await.unwrap());
    }

    #[tokio::test]
    async fn delete_repo_refuses_while_packages_exist() {
        let Some(db) = db().await else {
            eprintln!("skipping: set SILO_TEST_DATABASE_URL");
            return;
        };
        let repo = unique_repo("delnonempty");
        db.create_repo(&repo, false).await.unwrap();
        sqlx::query(
            "INSERT INTO packages (repo, channel, format, name, version, filename, \
             storage_key, size_bytes, sha256) \
             VALUES ($1, 'stable', 'rpm', 'pkg', '1.0', 'pkg.rpm', 'k', 0, 'x')",
        )
        .bind(&repo)
        .execute(db.pool())
        .await
        .unwrap();

        assert!(!db.delete_repo(&repo).await.unwrap());
        assert!(db.repo_exists(&repo).await.unwrap());
    }

    #[tokio::test]
    async fn delete_repo_removes_the_row_and_prune_config_when_empty() {
        let Some(db) = db().await else {
            eprintln!("skipping: set SILO_TEST_DATABASE_URL");
            return;
        };
        let repo = unique_repo("delempty");
        db.create_repo(&repo, false).await.unwrap();
        db.set_prune_rule(&repo, "stable", Some(5), None, "all")
            .await
            .unwrap();
        db.add_prune_exemption(&repo, "stable", "pkg")
            .await
            .unwrap();

        assert!(db.delete_repo(&repo).await.unwrap());
        assert!(!db.repo_exists(&repo).await.unwrap());
        assert!(db.get_prune_rule(&repo, "stable").await.unwrap().is_none());
        assert!(db
            .list_prune_exemptions(&repo, "stable")
            .await
            .unwrap()
            .is_empty());
    }
}
