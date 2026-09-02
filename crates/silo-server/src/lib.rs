// Every fallible function on the gRPC and HTTP surfaces returns
// `tonic::Status` (176 bytes) or an axum `Response`, because that is what
// the generated service traits and axum's handler signatures require.
// Neither type is ours to shrink, and boxing them — the lint's suggestion —
// would mean unboxing at every `?` on the way out. `silo-proto` carries the
// same allow over tonic's generated code for the same reason.
#![allow(clippy::result_large_err)]

pub mod admin;
pub mod auth;
pub mod bootstrap;
pub mod grpc;
pub mod grpc_auth;
pub mod http;
pub mod maintenance;
pub mod metrics;

use std::sync::Arc;

use silo_core::oidc::Verifier;
use silo_core::secret_box::SecretBox;
use silo_core::{Config, PublishContext, Storage};
use silo_db::Db;

use crate::metrics::Metrics;

pub struct AppState {
    pub config: Config,
    pub storage: Storage,
    pub db: Db,
    pub publish: PublishContext,
    /// `None` unless OIDC is configured. Built at startup so a broken
    /// issuer is a boot failure, not a first-login failure.
    pub oidc: Option<Arc<Verifier>>,
    pub metrics: Metrics,
    /// `None` unless `upstream_secret` is configured — every upstream
    /// with a credential requires it, but a server with no credentialed
    /// upstreams need not carry one.
    pub upstream_secrets: Option<SecretBox>,
    /// Shared, pooled client for outbound requests to upstreams — sync
    /// and pull-through fetches alike, so connections to a frequently-hit
    /// upstream are reused rather than reopened per request.
    pub upstream_http: reqwest::Client,
}

impl AppState {
    /// The absolute base URL to embed in npm packuments.
    ///
    /// Prefers the configured value; otherwise reconstructs it from the
    /// request's forwarding headers, which is what makes the config
    /// optional behind a normal reverse proxy. `Host` is attacker-
    /// controlled in principle, but the only thing it influences is the
    /// tarball URL handed back to the same client that sent it.
    pub fn base_url_for(&self, headers: &axum::http::HeaderMap) -> String {
        if let Some(configured) = self.config.public_base_url() {
            return configured.trim_end_matches('/').to_string();
        }

        let header = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                // A proxy chain sends a comma-separated list; the first
                // entry is the original client-facing hop.
                .and_then(|v| v.split(',').next())
                .map(|v| v.trim())
                .filter(|v| !v.is_empty())
        };

        let scheme = header("x-forwarded-proto").unwrap_or("http");
        let host = header("x-forwarded-host")
            .or_else(|| header("host"))
            .unwrap_or("localhost");
        format!("{scheme}://{host}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (k, v) in pairs {
            headers.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        headers
    }

    fn state_with_base(base: Option<&str>) -> AppState {
        crate::http::tests::test_state_with(|cfg| {
            cfg.public_base_url = base.map(|b| b.to_string());
        })
    }

    #[tokio::test]
    async fn configured_base_url_wins_and_is_normalized() {
        let state = state_with_base(Some("https://silo.example.com/"));
        assert_eq!(
            state.base_url_for(&headers(&[("host", "ignored.example")])),
            "https://silo.example.com"
        );
    }

    #[tokio::test]
    async fn base_url_falls_back_to_the_host_header() {
        let state = state_with_base(None);
        assert_eq!(
            state.base_url_for(&headers(&[("host", "silo.internal:8080")])),
            "http://silo.internal:8080"
        );
    }

    #[tokio::test]
    async fn forwarding_headers_are_preferred_over_host() {
        let state = state_with_base(None);
        assert_eq!(
            state.base_url_for(&headers(&[
                ("host", "silo-svc.cluster.local"),
                ("x-forwarded-proto", "https"),
                ("x-forwarded-host", "packages.example.com"),
            ])),
            "https://packages.example.com"
        );
    }

    #[tokio::test]
    async fn only_the_first_hop_of_a_forwarded_chain_is_used() {
        let state = state_with_base(None);
        assert_eq!(
            state.base_url_for(&headers(&[
                ("x-forwarded-proto", "https, http"),
                ("x-forwarded-host", "packages.example.com, internal.svc"),
            ])),
            "https://packages.example.com"
        );
    }

    #[tokio::test]
    async fn base_url_has_a_last_resort_default() {
        let state = state_with_base(None);
        assert_eq!(state.base_url_for(&HeaderMap::new()), "http://localhost");
    }
}
