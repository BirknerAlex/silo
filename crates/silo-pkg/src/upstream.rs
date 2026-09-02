//! Fetching and parsing a third party's package index — the read half of
//! pull-through caching.
//!
//! [`crate::Format`] is deliberately one-directional: parse *our own*
//! uploaded bytes, render *our own* index from database rows, with no
//! network access anywhere in that path (`IndexContext` is documented as
//! excluding it). Fetching someone else's index is a different concern —
//! async I/O against a third party, parsing a document silo doesn't
//! control the shape of — so it gets its own trait rather than bolting
//! onto `Format` and forcing every existing call site to carry an HTTP
//! client it doesn't need.
//!
//! Each format's upstream index is a structurally different document (see
//! the per-format modules), but every implementation follows the same
//! split: a pure `parse_*` function that turns already-fetched bytes into
//! `Vec<UpstreamPackage>` (unit-testable with canned bytes, no network),
//! called from `fetch_index` after an [`UpstreamHttp::get`].

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use serde_json::Value;
use thiserror::Error;

use crate::PackageFormat;

/// Ceiling on a single upstream response. Generous — a full Alpine/Debian
/// `Packages`/`APKINDEX` file for one architecture is tens of megabytes —
/// but bounded so a misbehaving or malicious upstream can't run a server
/// out of memory the same way [`crate::MAX_INFLATED_BYTES`] bounds a
/// package upload.
pub const MAX_UPSTREAM_RESPONSE_BYTES: u64 = 512 * 1024 * 1024;

/// One package entry read out of an upstream's index, normalized across
/// every format's wildly different wire shape into what the sync job
/// needs to store and what the pull-through decision needs to compare
/// against a local copy.
#[derive(Debug, Clone, PartialEq)]
pub struct UpstreamPackage {
    pub name: String,
    pub epoch: u32,
    pub version: String,
    pub release: String,
    pub arch: String,
    pub filename: String,
    /// Always an absolute URL, already resolved against the upstream's
    /// base URL — a caller never needs to know how a format's index
    /// spells a relative location.
    pub download_url: String,
    /// `None` when the upstream's index doesn't state it upfront (not
    /// every format does); known once the artifact is actually fetched.
    pub size_bytes: Option<i64>,
    pub sha256: Option<String>,
    pub metadata: Value,
}

#[derive(Debug, Error)]
pub enum UpstreamError {
    #[error("network error fetching {path}: {message}")]
    Fetch { path: String, message: String },
    #[error("upstream returned HTTP {status} for {path}")]
    Status { status: u16, path: String },
    #[error("could not parse upstream index: {0}")]
    Parse(String),
    #[error("response for {path} exceeded the {limit_bytes} byte limit")]
    TooLarge { path: String, limit_bytes: u64 },
}

impl UpstreamError {
    pub fn parse(msg: impl Into<String>) -> Self {
        UpstreamError::Parse(msg.into())
    }
}

/// Format-specific knobs a sync needs beyond the base URL.
///
/// Every field is meaningful to only some formats: `arches` is apk/pacman
/// (which architectures to sync — apk/pacman have no arch-agnostic root
/// index) and one axis of deb's cardinality; `suite`/`components` are
/// deb-only (its other two axes — see the `deb` upstream module doc for
/// why apt's shape needs all three where every other format needs at most
/// one). rpm and npm ignore all three.
#[derive(Debug, Clone, Default)]
pub struct UpstreamFetchOptions {
    pub arches: Vec<String>,
    pub suite: Option<String>,
    pub components: Vec<String>,
}

/// The per-format seam, symmetric with [`crate::Format`]: one
/// implementation per supported format, dispatched through
/// [`PackageFormat::upstream_handler`].
pub trait UpstreamIndex: Send + Sync {
    fn format(&self) -> PackageFormat;

    /// Fetches and parses the upstream's index into a normalized list.
    /// `opts` supplies whatever format-specific axes [`UpstreamFetchOptions`]
    /// documents; formats that don't use a given field ignore it.
    fn fetch_index<'a>(
        &'a self,
        http: &'a UpstreamHttp,
        opts: &'a UpstreamFetchOptions,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<UpstreamPackage>, UpstreamError>> + Send + 'a>>;
}

/// A thin, injectable wrapper over an upstream's base URL and resolved
/// credential — the seam that keeps index *parsing* unit-testable with
/// canned bytes, independent of the actual network fetch (which is only
/// exercised by integration tests against a mock server).
///
/// Deliberately carries an already-resolved auth header rather than a
/// credential: decrypting a stored upstream secret is `silo-core`'s job
/// (it owns the key — see `silo_core::secret_box`), so by the time this
/// crate sees a header, whether it's Basic or Bearer is no longer this
/// module's concern.
#[derive(Clone)]
pub struct UpstreamHttp {
    client: reqwest::Client,
    base_url: String,
    /// `(header name, header value)`, e.g. `("Authorization", "Basic ...")`.
    auth_header: Option<(String, String)>,
}

impl UpstreamHttp {
    pub fn new(client: reqwest::Client, base_url: impl Into<String>) -> Self {
        Self {
            client,
            base_url: base_url.into(),
            auth_header: None,
        }
    }

    pub fn with_auth_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.auth_header = Some((name.into(), value.into()));
        self
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Resolves `path` against the base URL. `path` may be a full absolute
    /// URL (some index formats embed one directly) or a path relative to
    /// the base.
    pub fn resolve(&self, path: &str) -> String {
        if path.starts_with("http://") || path.starts_with("https://") {
            return path.to_string();
        }
        format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }

    /// Whether `url` shares scheme, host, and port with the configured
    /// base URL — the credential is only ever attached to a request that
    /// stays there. An index document (rpm's `repomd.xml` href, say) can
    /// embed an absolute URL of its own; without this check, a malicious
    /// or compromised upstream could point that at a different host and
    /// have the stored credential handed straight to it.
    fn is_same_origin(&self, url: &str) -> bool {
        let (Ok(base), Ok(target)) = (
            reqwest::Url::parse(&self.base_url),
            reqwest::Url::parse(url),
        ) else {
            return false;
        };
        base.scheme() == target.scheme()
            && base.host_str() == target.host_str()
            && base.port_or_known_default() == target.port_or_known_default()
    }

    /// GETs `path` (see [`Self::resolve`]), applying the resolved auth
    /// header if one is set and the resolved URL is same-origin with the
    /// configured base URL, and returns the body capped at
    /// [`MAX_UPSTREAM_RESPONSE_BYTES`].
    pub async fn get(&self, path: &str) -> Result<Vec<u8>, UpstreamError> {
        let url = self.resolve(path);
        let mut request = self.client.get(&url).timeout(Duration::from_secs(60));
        if self.is_same_origin(&url) {
            if let Some((name, value)) = &self.auth_header {
                request = request.header(name.as_str(), value.as_str());
            }
        }
        let response = request.send().await.map_err(|e| UpstreamError::Fetch {
            path: url.clone(),
            message: e.to_string(),
        })?;
        if !response.status().is_success() {
            return Err(UpstreamError::Status {
                status: response.status().as_u16(),
                path: url,
            });
        }
        if let Some(len) = response.content_length() {
            if len > MAX_UPSTREAM_RESPONSE_BYTES {
                return Err(UpstreamError::TooLarge {
                    path: url,
                    limit_bytes: MAX_UPSTREAM_RESPONSE_BYTES,
                });
            }
        }
        // `content_length` is only a pre-check — chunked or lying
        // upstreams can omit or misstate it, and `Response::bytes()`
        // would buffer the whole body before any check ran. Reading
        // chunk by chunk and rejecting as soon as the cap is crossed
        // means a misbehaving upstream can't force an unbounded buffer.
        let mut response = response;
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| UpstreamError::Fetch {
            path: url.clone(),
            message: e.to_string(),
        })? {
            body.extend_from_slice(&chunk);
            if body.len() as u64 > MAX_UPSTREAM_RESPONSE_BYTES {
                return Err(UpstreamError::TooLarge {
                    path: url,
                    limit_bytes: MAX_UPSTREAM_RESPONSE_BYTES,
                });
            }
        }
        Ok(body)
    }

    /// A lightweight reachability probe: `true` on any successful status,
    /// `false` on a 404, an error otherwise. Used by formats (npm) that
    /// can't enumerate a whole index but still validate `add-upstream`
    /// against a real request.
    pub async fn probe(&self, path: &str) -> Result<bool, UpstreamError> {
        let url = self.resolve(path);
        let mut request = self.client.get(&url).timeout(Duration::from_secs(30));
        if self.is_same_origin(&url) {
            if let Some((name, value)) = &self.auth_header {
                request = request.header(name.as_str(), value.as_str());
            }
        }
        let response = request.send().await.map_err(|e| UpstreamError::Fetch {
            path: url.clone(),
            message: e.to_string(),
        })?;
        if response.status().as_u16() == 404 {
            return Ok(false);
        }
        if !response.status().is_success() {
            return Err(UpstreamError::Status {
                status: response.status().as_u16(),
                path: url,
            });
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_joins_a_relative_path_to_the_base() {
        let http = UpstreamHttp::new(reqwest::Client::new(), "https://example.com/repo/");
        assert_eq!(
            http.resolve("repodata/repomd.xml"),
            "https://example.com/repo/repodata/repomd.xml"
        );
        assert_eq!(
            http.resolve("/repodata/repomd.xml"),
            "https://example.com/repo/repodata/repomd.xml"
        );
    }

    #[test]
    fn resolve_passes_an_absolute_url_through_unchanged() {
        let http = UpstreamHttp::new(reqwest::Client::new(), "https://example.com/repo");
        assert_eq!(
            http.resolve("https://cdn.example.com/elsewhere/pkg.rpm"),
            "https://cdn.example.com/elsewhere/pkg.rpm"
        );
    }

    #[test]
    fn base_url_without_a_trailing_slash_still_joins_cleanly() {
        let http = UpstreamHttp::new(reqwest::Client::new(), "https://example.com/repo");
        assert_eq!(
            http.resolve("Packages.gz"),
            "https://example.com/repo/Packages.gz"
        );
    }
}
