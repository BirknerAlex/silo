//! Per-(repo, channel) retention rules and per-package exemptions.
//!
//! A `prune_rules` row only exists once someone has configured a rule for
//! that repo/channel — absence means "nothing to prune here", the same
//! no-row-means-default convention `repos` uses for visibility.
//! `keep_last_n` and `max_age_days` are independent; a version is pruned
//! if it violates either one that's set.

use sqlx::FromRow;

use crate::{DateTime, Db};

#[derive(Debug, Clone, FromRow)]
pub struct PruneRuleRow {
    pub repo: String,
    pub channel: String,
    pub keep_last_n: Option<i32>,
    pub max_age_days: Option<i32>,
    /// `"all"` | `"local"` | `"upstream"` — see
    /// `silo_core::prune::OriginFilter`, which parses this column.
    pub origin_scope: String,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

const COLUMNS: &str =
    "repo, channel, keep_last_n, max_age_days, origin_scope, created_at, updated_at";

impl Db {
    /// Creates or replaces the rule for `(repo, channel)`. At least one of
    /// `keep_last_n`/`max_age_days` must be `Some` — enforced by a check
    /// constraint, so a caller passing both `None` gets a database error
    /// rather than a silently-stored no-op rule. `origin_scope` is
    /// `"all"`/`"local"`/`"upstream"`, validated by a check constraint the
    /// same way.
    pub async fn set_prune_rule(
        &self,
        repo: &str,
        channel: &str,
        keep_last_n: Option<i32>,
        max_age_days: Option<i32>,
        origin_scope: &str,
    ) -> anyhow::Result<PruneRuleRow> {
        Ok(sqlx::query_as(&format!(
            "INSERT INTO prune_rules (repo, channel, keep_last_n, max_age_days, origin_scope) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (repo, channel) DO UPDATE SET \
                 keep_last_n = excluded.keep_last_n, \
                 max_age_days = excluded.max_age_days, \
                 origin_scope = excluded.origin_scope, \
                 updated_at = now() \
             RETURNING {COLUMNS}"
        ))
        .bind(repo)
        .bind(channel)
        .bind(keep_last_n)
        .bind(max_age_days)
        .bind(origin_scope)
        .fetch_one(self.pool())
        .await?)
    }

    /// Removes the rule for `(repo, channel)`, if any. Returns whether a
    /// row was actually deleted.
    pub async fn clear_prune_rule(&self, repo: &str, channel: &str) -> anyhow::Result<bool> {
        let result = sqlx::query("DELETE FROM prune_rules WHERE repo = $1 AND channel = $2")
            .bind(repo)
            .bind(channel)
            .execute(self.pool())
            .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn get_prune_rule(
        &self,
        repo: &str,
        channel: &str,
    ) -> anyhow::Result<Option<PruneRuleRow>> {
        Ok(sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM prune_rules WHERE repo = $1 AND channel = $2"
        ))
        .bind(repo)
        .bind(channel)
        .fetch_optional(self.pool())
        .await?)
    }

    /// Every configured rule — what a scope-less prune run iterates over.
    pub async fn list_prune_rules(&self) -> anyhow::Result<Vec<PruneRuleRow>> {
        Ok(sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM prune_rules ORDER BY repo, channel"
        ))
        .fetch_all(self.pool())
        .await?)
    }

    /// Exempts every version of `name` within `(repo, channel)` from both
    /// rules. Idempotent — exempting an already-exempt name is a no-op.
    pub async fn add_prune_exemption(
        &self,
        repo: &str,
        channel: &str,
        name: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO prune_exemptions (repo, channel, name) VALUES ($1, $2, $3) \
             ON CONFLICT (repo, channel, name) DO NOTHING",
        )
        .bind(repo)
        .bind(channel)
        .bind(name)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Removes an exemption. Returns whether one existed.
    pub async fn remove_prune_exemption(
        &self,
        repo: &str,
        channel: &str,
        name: &str,
    ) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "DELETE FROM prune_exemptions WHERE repo = $1 AND channel = $2 AND name = $3",
        )
        .bind(repo)
        .bind(channel)
        .bind(name)
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn list_prune_exemptions(
        &self,
        repo: &str,
        channel: &str,
    ) -> anyhow::Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT name FROM prune_exemptions WHERE repo = $1 AND channel = $2 ORDER BY name",
        )
        .bind(repo)
        .bind(channel)
        .fetch_all(self.pool())
        .await?;
        Ok(rows.into_iter().map(|(name,)| name).collect())
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
    async fn a_repo_channel_with_no_row_has_no_rule() {
        let Some(db) = db().await else {
            eprintln!("skipping: set SILO_TEST_DATABASE_URL");
            return;
        };
        let repo = unique_repo("norule");
        assert!(db.get_prune_rule(&repo, "stable").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn set_prune_rule_upserts_and_get_roundtrips() {
        let Some(db) = db().await else {
            eprintln!("skipping: set SILO_TEST_DATABASE_URL");
            return;
        };
        let repo = unique_repo("setrule");
        db.set_prune_rule(&repo, "stable", Some(5), None, "all")
            .await
            .unwrap();
        let rule = db.get_prune_rule(&repo, "stable").await.unwrap().unwrap();
        assert_eq!(rule.keep_last_n, Some(5));
        assert_eq!(rule.max_age_days, None);
        assert_eq!(rule.origin_scope, "all");

        db.set_prune_rule(&repo, "stable", Some(3), Some(90), "local")
            .await
            .unwrap();
        let rule = db.get_prune_rule(&repo, "stable").await.unwrap().unwrap();
        assert_eq!(rule.keep_last_n, Some(3));
        assert_eq!(rule.max_age_days, Some(90));
        assert_eq!(rule.origin_scope, "local");
    }

    #[tokio::test]
    async fn clear_prune_rule_removes_the_row() {
        let Some(db) = db().await else {
            eprintln!("skipping: set SILO_TEST_DATABASE_URL");
            return;
        };
        let repo = unique_repo("clearrule");
        db.set_prune_rule(&repo, "stable", Some(5), None, "all")
            .await
            .unwrap();
        assert!(db.clear_prune_rule(&repo, "stable").await.unwrap());
        assert!(db.get_prune_rule(&repo, "stable").await.unwrap().is_none());
        assert!(!db.clear_prune_rule(&repo, "stable").await.unwrap());
    }

    #[tokio::test]
    async fn rule_without_either_field_is_rejected() {
        let Some(db) = db().await else {
            eprintln!("skipping: set SILO_TEST_DATABASE_URL");
            return;
        };
        let repo = unique_repo("norulefields");
        assert!(db
            .set_prune_rule(&repo, "stable", None, None, "all")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn exemptions_are_idempotent_and_listable() {
        let Some(db) = db().await else {
            eprintln!("skipping: set SILO_TEST_DATABASE_URL");
            return;
        };
        let repo = unique_repo("exempt");
        db.add_prune_exemption(&repo, "stable", "curl")
            .await
            .unwrap();
        db.add_prune_exemption(&repo, "stable", "curl")
            .await
            .unwrap();
        assert_eq!(
            db.list_prune_exemptions(&repo, "stable").await.unwrap(),
            vec!["curl".to_string()]
        );
        assert!(db
            .remove_prune_exemption(&repo, "stable", "curl")
            .await
            .unwrap());
        assert!(db
            .list_prune_exemptions(&repo, "stable")
            .await
            .unwrap()
            .is_empty());
        assert!(!db
            .remove_prune_exemption(&repo, "stable", "curl")
            .await
            .unwrap());
    }
}
