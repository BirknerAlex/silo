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
}
