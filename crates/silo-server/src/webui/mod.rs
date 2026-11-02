//! The web admin console, served under `/admin` on the same listener as
//! everything else.
//!
//! Three things live here:
//!
//! - **The single-page app**, compiled into the binary (see `build.rs`).
//!   Any path under `/admin` that is not a file falls back to `index.html`
//!   so client-side routes survive a reload.
//! - **A JSON gateway** ([`gateway`]) over the same service implementations
//!   the gRPC listener serves. A browser cannot speak gRPC, and a second,
//!   hand-written admin API would be a second place to get authorization
//!   wrong; the gateway instead feeds each request through the gRPC
//!   handlers, so authentication, scoping, auditing and metrics are the
//!   ones the CLI already gets.
//! - **An OIDC device-flow relay** ([`oidc_device`]). The identity provider
//!   does not allow cross-origin calls from the console, so the server makes
//!   the two device-flow requests on the browser's behalf. The user still
//!   signs in at the provider, and the ID token is still verified by the
//!   same code `silo login` uses.
//!
//! The console holds a session or API token in `sessionStorage` and sends
//! it as a bearer token. Nothing is stored in a cookie, so a page on
//! another origin cannot make the browser send a credential here, and no
//! CSRF defence is needed.

use std::sync::Arc;

use axum::extract::Request;
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use tower_http::compression::CompressionLayer;

use crate::AppState;

pub mod gateway;
pub mod oidc_device;

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/ui_assets.rs"));
}

/// The path prefix everything in this module is served under.
pub const MOUNT: &str = "/admin";

/// Content-Security-Policy for every response under `/admin`.
///
/// Scripts and connections are limited to this origin, so a stored string
/// that slips past React's escaping still cannot load code or send the
/// session token anywhere. Styles allow `'unsafe-inline'` because
/// PatternFly's charts position elements with inline `style` attributes.
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; \
    style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; \
    connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; \
    frame-ancestors 'none'";

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/admin", get(|| async { Redirect::permanent("/admin/") }))
        .route("/admin/", get(index))
        .route("/admin/api/rpc/{method}", post(gateway::rpc))
        .route("/admin/api/oidc/device", post(oidc_device::start))
        .route("/admin/api/oidc/token", post(oidc_device::poll))
        .route("/admin/{*path}", get(asset))
        .with_state(state)
        .layer(CompressionLayer::new().gzip(true))
        .layer(middleware::from_fn(security_headers))
}

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

fn find(path: &str) -> Option<&'static [u8]> {
    embedded::ASSETS
        .iter()
        .find(|(name, _)| *name == path)
        .map(|(_, bytes)| *bytes)
}

async fn index() -> Response {
    serve("index.html")
}

async fn asset(axum::extract::Path(path): axum::extract::Path<String>) -> Response {
    // API paths that matched no route are errors, not pages: answering a
    // mistyped RPC with HTML would hide the mistake behind a 200.
    if path.starts_with("api/") {
        return (StatusCode::NOT_FOUND, "no such admin API route").into_response();
    }
    if find(&path).is_some() {
        return serve(&path);
    }
    // A request for something that looks like a file but is not one is a
    // real 404; anything else is a client-side route.
    let last = path.rsplit('/').next().unwrap_or("");
    if last.contains('.') {
        return StatusCode::NOT_FOUND.into_response();
    }
    serve("index.html")
}

fn serve(path: &str) -> Response {
    let Some(bytes) = find(path) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // Vite fingerprints everything under `assets/`, so those can be cached
    // forever; the entry page names them and must always be revalidated.
    let cache = if path.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    (
        [
            (header::CONTENT_TYPE, content_type(path)),
            (header::CACHE_CONTROL, cache),
        ],
        bytes,
    )
        .into_response()
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_types_cover_what_a_vite_build_emits() {
        assert_eq!(
            content_type("assets/index-abc.js"),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(
            content_type("assets/index-abc.css"),
            "text/css; charset=utf-8"
        );
        assert_eq!(content_type("assets/font.woff2"), "font/woff2");
        assert_eq!(content_type("index.html"), "text/html; charset=utf-8");
        assert_eq!(content_type("unknown.bin"), "application/octet-stream");
    }

    #[test]
    fn the_entry_page_is_always_embedded() {
        assert!(find("index.html").is_some());
    }
}
