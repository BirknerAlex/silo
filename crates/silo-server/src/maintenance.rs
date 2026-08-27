//! Background housekeeping.
//!
//! Three jobs that all have the same shape — run periodically, log
//! failures, never take the server down — so they share one loop rather
//! than three task spawns with three copies of the error handling.
//!
//! Every replica runs this loop. That's deliberate: the work is
//! idempotent (a delete that another replica already did affects zero
//! rows) and cheap, so coordinating it would cost more than the duplicated
//! effort it saves.

use std::sync::Arc;
use std::time::Duration;

use crate::AppState;

/// How often the loop ticks. Inventory gauges are the most latency
/// sensitive of the three jobs and a minute is well inside any sensible
/// Prometheus scrape interval.
const TICK: Duration = Duration::from_secs(60);

/// Ticks between the jobs that don't need to run every minute. Pruning an
/// audit log or expired sessions is a daily concern; running it hourly is
/// already generous and keeps the query off the database the rest of the
/// time.
const PRUNE_EVERY_TICKS: u64 = 60;

pub async fn run(state: Arc<AppState>) {
    let mut ticks: u64 = 0;
    loop {
        refresh_inventory(&state).await;

        if ticks.is_multiple_of(PRUNE_EVERY_TICKS) {
            prune(&state).await;
        }

        ticks = ticks.wrapping_add(1);
        tokio::time::sleep(TICK).await;
    }
}

/// Republishes the package-count gauges and the database liveness gauge.
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

async fn prune(state: &AppState) {
    match state.db.purge_expired_sessions().await {
        Ok(0) => {}
        Ok(n) => tracing::info!(count = n, "purged expired session tokens"),
        Err(e) => tracing::warn!(error = %e, "failed to purge expired session tokens"),
    }

    let retention = state.config.audit.retention_days;
    if retention > 0 {
        match state.db.prune_audit(retention).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(count = n, days = retention, "pruned old audit entries"),
            Err(e) => tracing::warn!(error = %e, "failed to prune the audit log"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prune_runs_hourly_relative_to_the_tick() {
        assert_eq!(TICK * PRUNE_EVERY_TICKS as u32, Duration::from_secs(3600));
    }

    #[test]
    fn the_first_tick_prunes() {
        // `ticks` starts at 0, so a freshly started server does its
        // housekeeping immediately rather than an hour in.
        assert!(0u64.is_multiple_of(PRUNE_EVERY_TICKS));
    }
}
