//! Audit log: who did what, to which repo, with which credential.
//!
//! Every mutating action and every authenticated download lands here. The
//! entries are deliberately denormalized — `actor_name` is copied in
//! rather than joined at read time — so the log still says who did
//! something after that token has been revoked and that user deleted.
//! `token_id`/`user_id` stay as nullable foreign keys for the cases where
//! the actor does still exist and you want to pivot on them.
//!
//! Writes are fire-and-forget from the caller's perspective (see
//! [`Db::record_audit`]): failing to write an audit row must not fail the
//! request that generated it, or an audit-table problem would take the
//! whole registry down.

use serde_json::{json, Value};
use sqlx::FromRow;
use uuid::Uuid;

use crate::{DateTime, Db};

/// Canonical action names. Free-form strings would drift
/// (`token.create` vs `create_token`) and make the log hard to query.
pub mod action {
    pub const PACKAGE_PUBLISH: &str = "package.publish";
    pub const PACKAGE_DOWNLOAD: &str = "package.download";
    pub const PACKAGE_DELETE: &str = "package.delete";
    pub const INDEX_REGENERATE: &str = "index.regenerate";
    pub const REPO_SET_MODE: &str = "repo.set_mode";
    pub const TOKEN_CREATE: &str = "token.create";
    pub const TOKEN_REVOKE: &str = "token.revoke";
    pub const USER_CREATE: &str = "user.create";
    pub const USER_DELETE: &str = "user.delete";
    pub const USER_DISABLE: &str = "user.disable";
    pub const AUTH_LOGIN: &str = "auth.login";
    pub const AUTH_FAILED: &str = "auth.failed";
    pub const SERVER_BOOTSTRAP: &str = "server.bootstrap";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorKind {
    Token,
    User,
    Anonymous,
    /// The server itself — startup bootstrap, background jobs.
    System,
}

impl ActorKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ActorKind::Token => "token",
            ActorKind::User => "user",
            ActorKind::Anonymous => "anonymous",
            ActorKind::System => "system",
        }
    }
}

/// Who performed an action. Built once per request and threaded through,
/// so handlers don't each re-derive identity from headers.
#[derive(Debug, Clone)]
pub struct Actor {
    pub kind: ActorKind,
    pub name: String,
    pub token_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub remote_addr: Option<String>,
}

impl Actor {
    pub fn system() -> Self {
        Self {
            kind: ActorKind::System,
            name: "system".to_string(),
            token_id: None,
            user_id: None,
            remote_addr: None,
        }
    }

    pub fn anonymous(remote_addr: Option<String>) -> Self {
        Self {
            kind: ActorKind::Anonymous,
            name: "anonymous".to_string(),
            token_id: None,
            user_id: None,
            remote_addr,
        }
    }

    pub fn with_remote_addr(mut self, addr: Option<String>) -> Self {
        self.remote_addr = addr;
        self
    }
}

/// One pending audit row.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub action: String,
    pub actor: Actor,
    pub repo: Option<String>,
    pub channel: Option<String>,
    pub target: Option<String>,
    pub success: bool,
    pub detail: Value,
}

impl AuditEntry {
    pub fn new(action: &str, actor: &Actor) -> Self {
        Self {
            action: action.to_string(),
            actor: actor.clone(),
            repo: None,
            channel: None,
            target: None,
            success: true,
            detail: json!({}),
        }
    }

    pub fn repo(mut self, repo: impl Into<String>) -> Self {
        self.repo = Some(repo.into());
        self
    }

    pub fn channel(mut self, channel: impl Into<String>) -> Self {
        self.channel = Some(channel.into());
        self
    }

    /// What was acted on: a package NEVRA, a token name, a username.
    pub fn target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    pub fn detail(mut self, detail: Value) -> Self {
        self.detail = detail;
        self
    }

    /// Marks the entry as a failure and records why. Failed attempts are
    /// the entries that matter most — a successful publish is visible in
    /// the package list, a rejected one is only visible here.
    pub fn failed(mut self, reason: impl std::fmt::Display) -> Self {
        self.success = false;
        if let Value::Object(map) = &mut self.detail {
            map.insert("error".to_string(), Value::String(reason.to_string()));
        } else {
            self.detail = json!({ "error": reason.to_string() });
        }
        self
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct AuditRow {
    pub id: i64,
    pub at: DateTime,
    pub action: String,
    pub actor_kind: String,
    pub actor_name: Option<String>,
    pub token_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub repo: Option<String>,
    pub channel: Option<String>,
    pub target: Option<String>,
    pub success: bool,
    pub remote_addr: Option<String>,
    pub detail: Value,
}

/// Filters for reading the log back.
#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    pub action: Option<String>,
    pub repo: Option<String>,
    pub actor: Option<String>,
    pub only_failures: bool,
    pub limit: i64,
}

const COLUMNS: &str = "id, at, action, actor_kind, actor_name, token_id, user_id, repo, channel, \
                       target, success, remote_addr, detail";

impl Db {
    /// Writes an audit row, logging rather than propagating failures.
    ///
    /// The audit log is a record of what the server did; it is not a
    /// precondition for doing it. A caller that had to handle "the audit
    /// write failed" would either ignore it (same as here, but repeated at
    /// every call site) or fail the user's request over bookkeeping.
    pub async fn record_audit(&self, entry: AuditEntry) {
        if let Err(e) = self.try_record_audit(&entry).await {
            tracing::error!(
                error = %e,
                action = %entry.action,
                "failed to write audit log entry"
            );
        }
    }

    pub async fn try_record_audit(&self, entry: &AuditEntry) -> anyhow::Result<i64> {
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO audit_log (action, actor_kind, actor_name, token_id, user_id, repo, \
                                    channel, target, success, remote_addr, detail) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id",
        )
        .bind(&entry.action)
        .bind(entry.actor.kind.as_str())
        .bind(&entry.actor.name)
        .bind(entry.actor.token_id)
        .bind(entry.actor.user_id)
        .bind(&entry.repo)
        .bind(&entry.channel)
        .bind(&entry.target)
        .bind(entry.success)
        .bind(&entry.actor.remote_addr)
        .bind(&entry.detail)
        .fetch_one(self.pool())
        .await?;
        Ok(id)
    }

    pub async fn query_audit(&self, query: &AuditQuery) -> anyhow::Result<Vec<AuditRow>> {
        let limit = query.limit.clamp(1, 1000);
        Ok(sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM audit_log \
             WHERE ($1::text IS NULL OR action = $1) \
               AND ($2::text IS NULL OR repo = $2) \
               AND ($3::text IS NULL OR actor_name = $3) \
               AND (NOT $4 OR success = FALSE) \
             ORDER BY at DESC, id DESC LIMIT $5"
        ))
        .bind(&query.action)
        .bind(&query.repo)
        .bind(&query.actor)
        .bind(query.only_failures)
        .bind(limit)
        .fetch_all(self.pool())
        .await?)
    }

    /// Trims entries older than `days`. Called on a timer so an
    /// unattended registry doesn't accumulate audit rows forever.
    pub async fn prune_audit(&self, days: i64) -> anyhow::Result<u64> {
        if days <= 0 {
            return Ok(0);
        }
        let result =
            sqlx::query("DELETE FROM audit_log WHERE at < now() - ($1 || ' days')::interval")
                .bind(days.to_string())
                .execute(self.pool())
                .await?;
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actor() -> Actor {
        Actor {
            kind: ActorKind::Token,
            name: "ci-publisher".into(),
            token_id: Some(Uuid::nil()),
            user_id: None,
            remote_addr: Some("10.0.0.1".into()),
        }
    }

    #[test]
    fn entries_default_to_success_with_empty_detail() {
        let entry = AuditEntry::new(action::PACKAGE_PUBLISH, &actor());
        assert!(entry.success);
        assert_eq!(entry.detail, json!({}));
        assert_eq!(entry.actor.name, "ci-publisher");
    }

    #[test]
    fn builder_fills_in_the_context_columns() {
        let entry = AuditEntry::new(action::PACKAGE_PUBLISH, &actor())
            .repo("myrepo")
            .channel("stable")
            .target("foo-1.0-1.x86_64");
        assert_eq!(entry.repo.as_deref(), Some("myrepo"));
        assert_eq!(entry.channel.as_deref(), Some("stable"));
        assert_eq!(entry.target.as_deref(), Some("foo-1.0-1.x86_64"));
    }

    #[test]
    fn failed_records_the_reason_without_dropping_existing_detail() {
        let entry = AuditEntry::new(action::PACKAGE_PUBLISH, &actor())
            .detail(json!({ "format": "rpm" }))
            .failed("invalid rpm");
        assert!(!entry.success);
        assert_eq!(entry.detail["error"], "invalid rpm");
        assert_eq!(entry.detail["format"], "rpm");
    }

    #[test]
    fn failed_replaces_non_object_detail() {
        let entry = AuditEntry::new(action::AUTH_FAILED, &actor())
            .detail(json!("scalar"))
            .failed("nope");
        assert_eq!(entry.detail["error"], "nope");
    }

    #[test]
    fn system_and_anonymous_actors_carry_no_identity() {
        let system = Actor::system();
        assert_eq!(system.kind, ActorKind::System);
        assert!(system.token_id.is_none());

        let anon = Actor::anonymous(Some("1.2.3.4".into()));
        assert_eq!(anon.kind, ActorKind::Anonymous);
        assert_eq!(anon.remote_addr.as_deref(), Some("1.2.3.4"));
    }

    #[test]
    fn audit_query_defaults_are_unfiltered() {
        let query = AuditQuery::default();
        assert!(query.action.is_none());
        assert!(!query.only_failures);
    }
}
