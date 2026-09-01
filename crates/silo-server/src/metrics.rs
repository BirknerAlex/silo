//! Prometheus metrics.
//!
//! Deliberately low-cardinality: labels are formats, actions, and coarse
//! outcome buckets, never repo/channel/package names. A registry with a
//! few thousand packages would otherwise turn a single counter into a few
//! thousand time series, which is how a metrics endpoint becomes the most
//! expensive thing a server does.
//!
//! The one exception is [`Metrics::refresh_inventory`], which does label
//! by repo/channel/format — that's a small, bounded set (operators create
//! repos deliberately) and it's the number people actually want on a
//! dashboard.

use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
    TextEncoder,
};

#[derive(Clone)]
pub struct Metrics {
    registry: Registry,
    pub http_requests: IntCounterVec,
    pub grpc_requests: IntCounterVec,
    pub publishes: IntCounterVec,
    pub publish_duration: HistogramVec,
    pub index_regenerations: IntCounterVec,
    pub downloads: IntCounterVec,
    pub auth_failures: IntCounterVec,
    pub packages: IntGaugeVec,
    pub package_bytes: IntGaugeVec,
    pub database_up: IntGauge,
}

impl Metrics {
    pub fn new() -> anyhow::Result<Self> {
        let registry = Registry::new_custom(Some("silo".to_string()), None)?;

        let http_requests = IntCounterVec::new(
            Opts::new(
                "http_requests_total",
                "HTTP requests served, by surface and outcome",
            ),
            &["surface", "status"],
        )?;
        let grpc_requests = IntCounterVec::new(
            Opts::new(
                "grpc_requests_total",
                "gRPC calls served, by method and outcome",
            ),
            &["method", "status"],
        )?;
        let publishes = IntCounterVec::new(
            Opts::new(
                "publishes_total",
                "Package publishes attempted, by format and outcome",
            ),
            &["format", "result"],
        )?;
        let publish_duration = HistogramVec::new(
            HistogramOpts::new(
                "publish_duration_seconds",
                "End-to-end publish latency, including index regeneration",
            )
            // Index regeneration dominates and is seconds-scale for a
            // large RPM repo, so the buckets run well past the default 10s.
            .buckets(vec![0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0]),
            &["format"],
        )?;
        let index_regenerations = IntCounterVec::new(
            Opts::new(
                "index_regenerations_total",
                "Index rebuilds, by format and outcome",
            ),
            &["format", "result"],
        )?;
        let downloads = IntCounterVec::new(
            Opts::new(
                "downloads_total",
                "Package fetches served, by format and how they were served",
            ),
            &["format", "mode"],
        )?;
        let auth_failures = IntCounterVec::new(
            Opts::new("auth_failures_total", "Rejected credentials, by reason"),
            &["reason"],
        )?;
        let packages = IntGaugeVec::new(
            Opts::new("packages", "Packages currently indexed"),
            &["repo", "channel", "format"],
        )?;
        let package_bytes = IntGaugeVec::new(
            Opts::new("package_bytes", "Total size of indexed packages in bytes"),
            &["repo", "channel", "format"],
        )?;
        let database_up = IntGauge::new("database_up", "1 when the last database ping succeeded")?;

        registry.register(Box::new(http_requests.clone()))?;
        registry.register(Box::new(grpc_requests.clone()))?;
        registry.register(Box::new(publishes.clone()))?;
        registry.register(Box::new(publish_duration.clone()))?;
        registry.register(Box::new(index_regenerations.clone()))?;
        registry.register(Box::new(downloads.clone()))?;
        registry.register(Box::new(auth_failures.clone()))?;
        registry.register(Box::new(packages.clone()))?;
        registry.register(Box::new(package_bytes.clone()))?;
        registry.register(Box::new(database_up.clone()))?;

        Ok(Self {
            registry,
            http_requests,
            grpc_requests,
            publishes,
            publish_duration,
            index_regenerations,
            downloads,
            auth_failures,
            packages,
            package_bytes,
            database_up,
        })
    }

    pub fn render(&self) -> anyhow::Result<(String, Vec<u8>)> {
        let encoder = TextEncoder::new();
        let mut buffer = Vec::new();
        encoder.encode(&self.registry.gather(), &mut buffer)?;
        Ok((encoder.format_type().to_string(), buffer))
    }

    /// Republishes the package-count/size gauges from the database.
    ///
    /// Gauges are reset first so a repo whose last package was deleted
    /// stops reporting a stale count instead of freezing at its final
    /// value forever.
    pub fn refresh_inventory(&self, summaries: &[silo_db::packages::RepoSummary]) {
        self.packages.reset();
        self.package_bytes.reset();
        for summary in summaries {
            // `list_repos` also returns a row for a repo that was created
            // but never published to, with no packages and no channel/
            // format to label a series with — skip it rather than emit a
            // bogus `{channel="",format=""}` zero series.
            if summary.packages == 0 {
                continue;
            }
            let labels = [
                summary.repo.as_str(),
                summary.channel.as_str(),
                summary.format.as_str(),
            ];
            self.packages
                .with_label_values(&labels)
                .set(summary.packages);
            self.package_bytes
                .with_label_values(&labels)
                .set(summary.total_bytes);
        }
    }

    pub fn record_publish(&self, format: &str, ok: bool, seconds: f64) {
        self.publishes
            .with_label_values(&[format, if ok { "ok" } else { "error" }])
            .inc();
        if ok {
            self.publish_duration
                .with_label_values(&[format])
                .observe(seconds);
        }
    }

    /// Records one gRPC call, by method and coarse ok/error outcome.
    ///
    /// There is no gRPC-wide middleware — a `tonic::Status`'s outcome is
    /// only known after a handler runs, and this codebase never captures
    /// metrics via response-rewriting middleware (see `serve_index`'s and
    /// `serve_package`'s own "build once, count once" comments), so every
    /// RPC method calls this itself before returning.
    pub fn record_grpc<T>(&self, method: &str, result: &Result<tonic::Response<T>, tonic::Status>) {
        self.grpc_requests
            .with_label_values(&[method, if result.is_ok() { "ok" } else { "error" }])
            .inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use silo_db::packages::RepoSummary;

    fn summary(repo: &str, packages: i64, bytes: i64) -> RepoSummary {
        RepoSummary {
            repo: repo.into(),
            channel: "stable".into(),
            format: "rpm".into(),
            packages,
            total_bytes: bytes,
            public: false,
        }
    }

    #[test]
    fn renders_registered_metrics_in_prometheus_text_format() {
        let metrics = Metrics::new().unwrap();
        metrics
            .http_requests
            .with_label_values(&["rpm", "200"])
            .inc();
        let (content_type, body) = metrics.render().unwrap();
        let body = String::from_utf8(body).unwrap();

        assert!(content_type.starts_with("text/plain"));
        assert!(body.contains("silo_http_requests_total"), "got: {body}");
        assert!(body.contains(r#"surface="rpm""#));
    }

    #[test]
    fn all_metric_names_carry_the_silo_prefix() {
        let metrics = Metrics::new().unwrap();
        metrics.publishes.with_label_values(&["apk", "ok"]).inc();
        metrics.downloads.with_label_values(&["npm", "proxy"]).inc();
        metrics.auth_failures.with_label_values(&["expired"]).inc();
        metrics.database_up.set(1);

        let (_, body) = metrics.render().unwrap();
        let body = String::from_utf8(body).unwrap();
        for line in body.lines().filter(|l| l.starts_with("# HELP")) {
            assert!(
                line.starts_with("# HELP silo_"),
                "metric is missing the namespace prefix: {line}"
            );
        }
    }

    #[test]
    fn publish_duration_is_only_observed_for_successes() {
        let metrics = Metrics::new().unwrap();
        metrics.record_publish("rpm", false, 3.0);
        assert_eq!(
            metrics
                .publish_duration
                .with_label_values(&["rpm"])
                .get_sample_count(),
            0,
            "a failed publish's latency is not meaningful"
        );

        metrics.record_publish("rpm", true, 3.0);
        assert_eq!(
            metrics
                .publish_duration
                .with_label_values(&["rpm"])
                .get_sample_count(),
            1
        );
        assert_eq!(
            metrics.publishes.with_label_values(&["rpm", "error"]).get(),
            1
        );
        assert_eq!(metrics.publishes.with_label_values(&["rpm", "ok"]).get(), 1);
    }

    #[test]
    fn refreshing_inventory_drops_repos_that_no_longer_exist() {
        let metrics = Metrics::new().unwrap();
        metrics.refresh_inventory(&[summary("a", 3, 300), summary("b", 5, 500)]);
        assert_eq!(
            metrics
                .packages
                .with_label_values(&["a", "stable", "rpm"])
                .get(),
            3
        );

        // `b` is gone; its series must not linger at 5.
        metrics.refresh_inventory(&[summary("a", 4, 400)]);
        let (_, body) = metrics.render().unwrap();
        let body = String::from_utf8(body).unwrap();
        assert!(body.contains(r#"repo="a""#));
        assert!(
            !body.contains(r#"repo="b""#),
            "stale series survived: {body}"
        );
        assert_eq!(
            metrics
                .packages
                .with_label_values(&["a", "stable", "rpm"])
                .get(),
            4
        );
    }
}
