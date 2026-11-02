//! Aggregate figures for the admin console.
//!
//! Everything here is a read-only summary computed by the database. None
//! of it is cached: the queries scan indexes on tables an operator keeps
//! small (tokens, users, upstreams) or are bounded by a time window
//! (`audit_log`), and the console asks for them when a person opens a page.

use sqlx::FromRow;

use crate::{DateTime, Db};

/// Counts that describe the registry as a whole.
#[derive(Debug, Clone, Default, FromRow)]
pub struct Totals {
    pub repos: i64,
    pub public_repos: i64,
    pub channels: i64,
    pub packages: i64,
    pub bytes: i64,
    pub upstream_packages: i64,
    pub users: i64,
    pub admin_users: i64,
    pub disabled_users: i64,
    pub oidc_users: i64,
    pub api_tokens: i64,
    pub session_tokens: i64,
    pub revoked_tokens: i64,
    pub expired_tokens: i64,
}

#[derive(Debug, Clone, FromRow)]
pub struct FormatTotals {
    pub format: String,
    pub packages: i64,
    pub bytes: i64,
    pub repos: i64,
}

#[derive(Debug, Clone, FromRow)]
pub struct RepoTotals {
    pub repo: String,
    pub public: bool,
    pub channels: i64,
    pub packages: i64,
    pub bytes: i64,
}

/// One UTC day of audit activity.
#[derive(Debug, Clone, FromRow)]
pub struct DayActivity {
    pub day: DateTime,
    pub publishes: i64,
    pub downloads: i64,
    pub deletes: i64,
    pub logins: i64,
    pub failures: i64,
}

#[derive(Debug, Clone, FromRow)]
pub struct ActionTotals {
    pub action: String,
    pub count: i64,
    pub failures: i64,
}

#[derive(Debug, Clone, Default, FromRow)]
pub struct UpstreamTotals {
    pub total: i64,
    pub ok: i64,
    pub pending: i64,
    pub error: i64,
    pub indexed_packages: i64,
}

impl Db {
    pub async fn stats_totals(&self) -> anyhow::Result<Totals> {
        // One round trip: each scalar subquery is an index-only or small
        // table count. `coalesce(sum(..), 0)::bigint` because `sum` over a
        // bigint is NUMERIC, which does not decode into i64.
        Ok(sqlx::query_as(
            "SELECT \
               (SELECT count(*) FROM (SELECT repo FROM repos UNION SELECT repo FROM packages) r) AS repos, \
               (SELECT count(*) FROM repos WHERE public) AS public_repos, \
               (SELECT count(*) FROM (SELECT DISTINCT repo, channel FROM packages) c) AS channels, \
               (SELECT count(*) FROM packages) AS packages, \
               (SELECT coalesce(sum(size_bytes), 0)::bigint FROM packages) AS bytes, \
               (SELECT count(*) FROM packages WHERE origin_upstream_id IS NOT NULL) AS upstream_packages, \
               (SELECT count(*) FROM users) AS users, \
               (SELECT count(*) FROM users WHERE is_admin) AS admin_users, \
               (SELECT count(*) FROM users WHERE disabled) AS disabled_users, \
               (SELECT count(*) FROM users WHERE oidc_subject IS NOT NULL) AS oidc_users, \
               (SELECT count(*) FROM tokens WHERE kind = 'api' AND revoked_at IS NULL \
                   AND (expires_at IS NULL OR expires_at > now())) AS api_tokens, \
               (SELECT count(*) FROM tokens WHERE kind = 'session' AND revoked_at IS NULL \
                   AND (expires_at IS NULL OR expires_at > now())) AS session_tokens, \
               (SELECT count(*) FROM tokens WHERE revoked_at IS NOT NULL) AS revoked_tokens, \
               (SELECT count(*) FROM tokens WHERE revoked_at IS NULL \
                   AND expires_at IS NOT NULL AND expires_at <= now()) AS expired_tokens",
        )
        .fetch_one(self.pool())
        .await?)
    }

    pub async fn stats_by_format(&self) -> anyhow::Result<Vec<FormatTotals>> {
        Ok(sqlx::query_as(
            "SELECT format, count(*) AS packages, \
                    coalesce(sum(size_bytes), 0)::bigint AS bytes, \
                    count(DISTINCT repo) AS repos \
             FROM packages GROUP BY format ORDER BY bytes DESC, format",
        )
        .fetch_all(self.pool())
        .await?)
    }

    /// Every repo, including one with no packages yet and one whose
    /// packages have no `repos` row. The same set `stats_totals` counts.
    pub async fn stats_by_repo(&self) -> anyhow::Result<Vec<RepoTotals>> {
        Ok(sqlx::query_as(
            "SELECT n.repo, coalesce(r.public, false) AS public, \
                    count(DISTINCT p.channel) AS channels, \
                    count(p.id) AS packages, \
                    coalesce(sum(p.size_bytes), 0)::bigint AS bytes \
             FROM (SELECT repo FROM repos UNION SELECT repo FROM packages) n \
             LEFT JOIN repos r ON r.repo = n.repo \
             LEFT JOIN packages p ON p.repo = n.repo \
             GROUP BY n.repo, r.public ORDER BY bytes DESC, n.repo",
        )
        .fetch_all(self.pool())
        .await?)
    }

    /// Audit activity per UTC day over the last `days` days, with a row
    /// for every day in the window so a chart has no gaps to fill in.
    pub async fn stats_daily_activity(&self, days: i32) -> anyhow::Result<Vec<DayActivity>> {
        let days = days.clamp(1, 365);
        Ok(sqlx::query_as(
            "SELECT d.day, \
                    count(*) FILTER (WHERE a.action = 'package.publish' AND a.success) AS publishes, \
                    count(*) FILTER (WHERE a.action = 'package.download' AND a.success) AS downloads, \
                    count(*) FILTER (WHERE a.action = 'package.delete' AND a.success) AS deletes, \
                    count(*) FILTER (WHERE a.action = 'auth.login' AND a.success) AS logins, \
                    count(*) FILTER (WHERE NOT a.success) AS failures \
             FROM generate_series( \
                    date_trunc('day', now() AT TIME ZONE 'UTC') - make_interval(days => $1 - 1), \
                    date_trunc('day', now() AT TIME ZONE 'UTC'), \
                    interval '1 day') AS g(day_local) \
             CROSS JOIN LATERAL (SELECT g.day_local AT TIME ZONE 'UTC' AS day) d \
             LEFT JOIN audit_log a \
                    ON a.at >= d.day AND a.at < d.day + interval '1 day' \
             GROUP BY d.day ORDER BY d.day",
        )
        .bind(days)
        .fetch_all(self.pool())
        .await?)
    }

    pub async fn stats_action_totals(&self, days: i32) -> anyhow::Result<Vec<ActionTotals>> {
        let days = days.clamp(1, 365);
        Ok(sqlx::query_as(
            "SELECT action, count(*) AS count, count(*) FILTER (WHERE NOT success) AS failures \
             FROM audit_log \
             WHERE at >= date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' \
                        - make_interval(days => $1 - 1) \
             GROUP BY action ORDER BY count DESC, action",
        )
        .bind(days)
        .fetch_all(self.pool())
        .await?)
    }

    pub async fn stats_upstreams(&self) -> anyhow::Result<UpstreamTotals> {
        Ok(sqlx::query_as(
            "SELECT \
               (SELECT count(*) FROM upstreams) AS total, \
               (SELECT count(*) FROM upstreams WHERE status = 'ok') AS ok, \
               (SELECT count(*) FROM upstreams WHERE status = 'pending') AS pending, \
               (SELECT count(*) FROM upstreams WHERE status = 'error') AS error, \
               (SELECT count(*) FROM upstream_packages) AS indexed_packages",
        )
        .fetch_one(self.pool())
        .await?)
    }
}
