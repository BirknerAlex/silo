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
}

async fn run_session_cleanup(state: &AppState) {
    match state.db.purge_expired_sessions().await {
        Ok(0) => {}
        Ok(n) => tracing::info!(count = n, "purged expired session tokens"),
        Err(e) => tracing::warn!(error = %e, "failed to purge expired session tokens"),
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
}
