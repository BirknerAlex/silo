//! Background housekeeping.
//!
//! A small cron-scheduled job runner. Each job — `refresh_inventory`
//! (metrics, unconditional every tick), `session_cleanup`, `audit_prune`,
//! `package_prune` — has its own schedule, computed once at startup and
//! re-derived after every run via the `cron` crate. `session_cleanup` and
//! `audit_prune` ship with defaults that preserve the cadence silo has
//! always run housekeeping at; `package_prune` has no default, since
//! automatic pruning is opt-in even when `prune.enabled` is on.
//!
//! Every replica runs this loop, computing its own next-fire times
//! independently in memory — no persistence, no leader election. That's
//! deliberate: every job here is either idempotent (a delete that another
//! replica already did affects zero rows) or convergent (a metrics
//! refresh), so coordinating which replica runs it would cost more than
//! the rare duplicated work saves. Two replicas firing the same job in the
//! same minute is a cheap no-op the second time, not a correctness issue.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use cron::Schedule;

use crate::AppState;

/// How often the loop checks whether a job is due. The coarsest cron
/// granularity this runner bothers honoring — a schedule with sub-minute
/// fields won't fire more than once per tick.
const TICK: Duration = Duration::from_secs(60);

type JobFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

struct Job {
    name: &'static str,
    schedule: Option<Schedule>,
    next: Option<DateTime<Utc>>,
    run: Box<dyn Fn(Arc<AppState>) -> JobFuture + Send + Sync>,
}

impl Job {
    fn new(
        name: &'static str,
        schedule: Option<&str>,
        run: impl Fn(Arc<AppState>) -> JobFuture + Send + Sync + 'static,
    ) -> Self {
        // Schedules are already validated at `Config::load()` time, so a
        // parse failure here would mean a config was constructed without
        // going through that path (e.g. in a test) — falling back to "no
        // schedule" is safer than panicking a background task.
        let schedule = schedule.and_then(|s| match s.parse::<Schedule>() {
            Ok(schedule) => Some(schedule),
            Err(e) => {
                tracing::warn!(job = name, schedule = s, error = %e, "invalid cron schedule, job disabled");
                None
            }
        });
        let next = schedule.as_ref().and_then(|s| s.upcoming(Utc).next());
        Self {
            name,
            schedule,
            next,
            run: Box::new(run),
        }
    }
}

pub async fn run(state: Arc<AppState>) {
    let mut jobs = build_jobs(&state.config);
    loop {
        refresh_inventory(&state).await;

        for job in jobs.iter_mut() {
            let Some(next) = job.next else { continue };
            if Utc::now() >= next {
                tracing::debug!(job = job.name, "running scheduled job");
                (job.run)(state.clone()).await;
                job.next = job.schedule.as_ref().and_then(|s| s.upcoming(Utc).next());
            }
        }

        tokio::time::sleep(TICK).await;
    }
}

fn build_jobs(config: &silo_core::Config) -> Vec<Job> {
    vec![
        Job::new(
            "session_cleanup",
            Some(&config.jobs.session_cleanup),
            |state| Box::pin(async move { run_session_cleanup(&state).await }),
        ),
        Job::new("audit_prune", Some(&config.jobs.audit_prune), |state| {
            Box::pin(async move { run_audit_prune(&state).await })
        }),
        Job::new(
            "package_prune",
            config.jobs.package_prune.as_deref(),
            |state| Box::pin(async move { run_package_prune(&state).await }),
        ),
        Job::new(
            "upstream_sync",
            config.jobs.upstream_sync.as_deref(),
            |state| Box::pin(async move { run_upstream_sync(&state).await }),
        ),
    ]
}

/// Republishes the package-count gauges and the database liveness gauge.
/// Stays on the unconditional tick rather than a cron schedule — it's the
/// most latency-sensitive of these jobs, and a minute is well inside any
/// sensible Prometheus scrape interval.
async fn refresh_inventory(state: &AppState) {
    match state.db.list_repos().await {
        Ok(summaries) => {
            state.metrics.refresh_inventory(&summaries);
            state.metrics.database_up.set(1);
        }
        Err(e) => {
            // The gauge is the signal here; a failed refresh is exactly
            // the condition an operator wants to alert on.
            state.metrics.database_up.set(0);
            tracing::warn!(error = %e, "failed to refresh inventory metrics");
        }
    }
    match state.db.upstream_package_counts().await {
        Ok(counts) => state.metrics.refresh_upstream_inventory(&counts),
        Err(e) => tracing::warn!(error = %e, "failed to refresh upstream inventory metrics"),
    }
}

async fn run_session_cleanup(state: &AppState) {
    match state.db.purge_expired_sessions().await {
        Ok(0) => {}
        Ok(n) => tracing::info!(count = n, "purged expired session tokens"),
        Err(e) => tracing::warn!(error = %e, "failed to purge expired session tokens"),
    }

    // Login throttle rows outlive their window and are never read again.
    // Left alone, the table grows by one row per username anybody has ever
    // guessed at, which is unbounded and attacker-controlled.
    match state
        .db
        .purge_stale_login_attempts(crate::grpc_auth::LOGIN_FAILURE_WINDOW_MINUTES)
        .await
    {
        Ok(0) => {}
        Ok(n) => tracing::info!(count = n, "purged elapsed login throttle windows"),
        Err(e) => tracing::warn!(error = %e, "failed to purge login throttle rows"),
    }
}

async fn run_audit_prune(state: &AppState) {
    let retention = state.config.audit.retention_days;
    if retention <= 0 {
        return;
    }
    match state.db.prune_audit(retention).await {
        Ok(0) => {}
        Ok(n) => tracing::info!(count = n, days = retention, "pruned old audit entries"),
        Err(e) => tracing::warn!(error = %e, "failed to prune the audit log"),
    }
}

async fn run_package_prune(state: &AppState) {
    if !state.config.prune.enabled {
        return;
    }
    let scope = silo_core::prune::PruneScope::all();
    match silo_core::prune::run(
        &state.publish,
        &scope,
        false,
        &silo_db::audit::Actor::system(),
    )
    .await
    {
        Ok(report) => {
            if report.deleted > 0 || !report.failed.is_empty() {
                tracing::info!(
                    deleted = report.deleted,
                    failed = report.failed.len(),
                    "pruned packages on schedule"
                );
            }
        }
        Err(e) => tracing::warn!(error = %e, "scheduled package prune failed"),
    }
}

/// Bounded concurrency for how many upstreams sync at once — protects a
/// server with many configured upstreams from hammering all of them (and
/// itself) in the same tick. Not (yet) configurable; a fixed, conservative
/// default until real deployments show it needs to be.
const UPSTREAM_SYNC_CONCURRENCY: usize = 4;

/// Refreshes every configured upstream's synced index. One upstream's
/// failure is recorded on its own row and logged, never aborting the
/// batch — see `upstream_sync::sync_one`.
async fn run_upstream_sync(state: &AppState) {
    use futures::StreamExt;

    let upstreams = match state.db.list_all_upstreams().await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(error = %e, "failed to list upstreams for scheduled sync");
            return;
        }
    };
    if upstreams.is_empty() {
        return;
    }

    let results: Vec<(String, String, anyhow::Result<usize>)> = futures::stream::iter(upstreams)
        .map(|upstream| async move {
            let started = std::time::Instant::now();
            let result = silo_core::upstream_sync::sync_one(
                &state.db,
                state.upstream_http.clone(),
                state.upstream_secrets.as_ref(),
                &upstream,
            )
            .await;
            state.publish.upstream_index_cache.invalidate(upstream.id);
            if result.is_ok() {
                if let Ok(format) = upstream.format.parse::<silo_pkg::PackageFormat>() {
                    if let Err(e) = silo_core::repo::rebuild_index_for_upstream(
                        &state.publish,
                        &upstream.repo,
                        &upstream.channel,
                        format,
                        &upstream.arches,
                        &silo_db::audit::Actor::system(),
                    )
                    .await
                    {
                        tracing::warn!(
                            upstream = %upstream.name, error = %e,
                            "failed to rebuild the index after a scheduled upstream sync"
                        );
                    }
                }
            }
            state.metrics.record_upstream_sync(
                &upstream.format,
                result.is_ok(),
                started.elapsed().as_secs_f64(),
            );
            (upstream.name.clone(), upstream.format.clone(), result)
        })
        .buffer_unordered(UPSTREAM_SYNC_CONCURRENCY)
        .collect()
        .await;

    for (name, format, result) in results {
        match result {
            Ok(count) => {
                tracing::info!(upstream = %name, format = %format, packages = count, "synced upstream index")
            }
            Err(e) => {
                tracing::warn!(upstream = %name, format = %format, error = %e, "upstream sync failed")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upcoming_within(schedule: &str, max: Duration) {
        let schedule: Schedule = schedule.parse().unwrap();
        let next = schedule.upcoming(Utc).next().expect("a next fire time");
        let delta = (next - Utc::now()).to_std().unwrap();
        assert!(
            delta <= max,
            "expected next fire within {max:?}, got {delta:?}"
        );
    }

    #[test]
    fn default_session_cleanup_schedule_fires_within_five_minutes() {
        upcoming_within("0 */5 * * * *", Duration::from_secs(5 * 60));
    }

    #[test]
    fn default_audit_prune_schedule_fires_within_an_hour() {
        upcoming_within("0 0 * * * *", Duration::from_secs(3600));
    }

    #[test]
    fn job_with_no_schedule_never_has_a_next_fire_time() {
        let job = Job::new("package_prune", None, |_| Box::pin(async {}));
        assert!(job.next.is_none());
    }

    #[test]
    fn job_with_an_invalid_schedule_is_disabled_rather_than_panicking() {
        let job = Job::new("bad", Some("not a cron"), |_| Box::pin(async {}));
        assert!(job.next.is_none());
    }

    /// The one test in this module that runs the real tick body rather than
    /// just its scheduling — `packages`/`package_bytes` only ever move
    /// through `refresh_inventory`, so a synthetic call to
    /// `Metrics::refresh_inventory` (see `metrics.rs`'s own tests) would
    /// never catch a wiring mistake between the database and the job.
    #[tokio::test]
    async fn refreshing_inventory_against_a_real_repo_publishes_its_gauges() {
        let Ok(url) = std::env::var("SILO_TEST_DATABASE_URL") else {
            eprintln!("skipping: set SILO_TEST_DATABASE_URL");
            return;
        };
        if url.trim().is_empty() {
            eprintln!("skipping: set SILO_TEST_DATABASE_URL");
            return;
        }
        let db = silo_db::Db::connect(&silo_db::DbConfig {
            url,
            max_connections: 4,
            connect_timeout: std::time::Duration::from_secs(30),
            token_pepper: None,
        })
        .await
        .expect("connect to the test database");

        let mut state = crate::http::tests::test_state_with(|_| {});
        state.db = db.clone();
        state.publish.db = db;

        let repo = format!("refresh-inventory-{}", uuid::Uuid::new_v4().simple());
        let tarball = silo_pkg::testutil::build_test_rpm("widget", "1.0", "1", "x86_64");
        let size_bytes = tarball.len() as i64;
        silo_core::repo::publish(
            &state.publish,
            &repo,
            "stable",
            silo_pkg::PackageFormat::Rpm,
            tarball,
            &silo_db::audit::Actor::system(),
        )
        .await
        .expect("seed a package for the inventory refresh to pick up");

        refresh_inventory(&state).await;

        assert_eq!(state.metrics.database_up.get(), 1);
        assert_eq!(
            state
                .metrics
                .packages
                .with_label_values(&[&repo, "stable", "rpm"])
                .get(),
            1
        );
        assert_eq!(
            state
                .metrics
                .package_bytes
                .with_label_values(&[&repo, "stable", "rpm"])
                .get(),
            size_bytes
        );
    }
}
