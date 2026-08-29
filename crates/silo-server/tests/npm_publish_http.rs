//! `npm publish`/`yarn publish` speak a fixed wire protocol — a `PUT` of a
//! JSON envelope with a base64 tarball attachment — that no external tool
//! can be reconfigured to send over gRPC instead. These tests drive the
//! HTTP route the same way a real npm client would, rather than calling
//! `silo_core::repo::publish` directly like `tests/publish_flow.rs` does,
//! to prove the adapter (auth, JSON parsing, base64 decoding) works end to
//! end and lands in the exact same place gRPC publishes do.
//!
//! See `tests/common/mod.rs` for how to point these at a database.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use common::{unique_repo, Harness};
use silo_db::tokens::Permission;
use silo_pkg::testutil::build_test_npm;
use tower::ServiceExt;

/// Builds the JSON body `npm publish` sends: only `_attachments` matters,
/// since the server re-derives name/version/dist from the tarball itself.
fn publish_body(filename: &str, tarball: &[u8]) -> String {
    serde_json::json!({
        "_attachments": {
            filename: {
                "content_type": "application/octet-stream",
                "data": base64::engine::general_purpose::STANDARD.encode(tarball),
                "length": tarball.len(),
            }
        }
    })
    .to_string()
}

async fn put_publish(
    harness: &Harness,
    repo: &str,
    channel: &str,
    name: &str,
    token: Option<&str>,
    body: String,
) -> axum::response::Response {
    let mut req = Request::builder()
        .method("PUT")
        .uri(format!("/{repo}/{channel}/npm/{name}"))
        .header("content-type", "application/json");
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    silo_server::http::router(harness.state.clone())
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap()
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn npm_publish_over_http_is_indexed_and_downloadable() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("npm-http-publish");
    let writer = harness.publisher_token(&repo).await;

    let tarball = build_test_npm("widget", "1.0.0");
    let body = publish_body("widget-1.0.0.tgz", &tarball);
    let resp = put_publish(
        &harness,
        &repo,
        "stable",
        "widget",
        Some(&writer.secret),
        body,
    )
    .await;
    let status = resp.status();
    let text = body_string(resp).await;
    assert_eq!(status, StatusCode::OK, "{text}");

    // Indexed exactly like a gRPC/CLI publish would be: the packument
    // lists the version and a tarball fetched back through the ordinary
    // GET route matches what was uploaded.
    let packument = harness
        .state
        .storage
        .get(&format!("{repo}/stable/npm/widget/packument.json"))
        .await
        .unwrap()
        .expect("packument was written");
    let doc: serde_json::Value = serde_json::from_slice(&packument).unwrap();
    assert_eq!(doc["dist-tags"]["latest"], "1.0.0");
    assert!(doc["versions"]["1.0.0"].is_object());

    let get_resp = silo_server::http::router(harness.state.clone())
        .oneshot(
            Request::builder()
                .uri(format!("/{repo}/stable/npm/widget/-/widget-1.0.0.tgz"))
                .header("authorization", format!("Bearer {}", writer.secret))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_resp.status(), StatusCode::OK);
    let downloaded = axum::body::to_bytes(get_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(downloaded.as_ref(), tarball.as_slice());
}

#[tokio::test]
async fn npm_publish_over_http_and_via_grpc_converge_on_one_packument() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("npm-http-and-core");
    let writer = harness.publisher_token(&repo).await;

    // One version published the way the `silo` CLI does today...
    silo_core::repo::publish(
        &harness.state.publish,
        &repo,
        "stable",
        silo_pkg::PackageFormat::Npm,
        build_test_npm("widget", "1.0.0"),
        &silo_db::audit::Actor {
            kind: silo_db::audit::ActorKind::Token,
            name: "cli".into(),
            token_id: None,
            user_id: None,
            remote_addr: None,
        },
    )
    .await
    .expect("publish over the core function directly");

    // ...and a second version published the way a real `npm publish`
    // would, over HTTP.
    let tarball = build_test_npm("widget", "2.0.0");
    let body = publish_body("widget-2.0.0.tgz", &tarball);
    let resp = put_publish(
        &harness,
        &repo,
        "stable",
        "widget",
        Some(&writer.secret),
        body,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let packument = harness
        .state
        .storage
        .get(&format!("{repo}/stable/npm/widget/packument.json"))
        .await
        .unwrap()
        .expect("packument was written");
    let doc: serde_json::Value = serde_json::from_slice(&packument).unwrap();
    // Both versions land in the same packument regardless of which
    // publish path wrote them.
    assert_eq!(doc["versions"].as_object().unwrap().len(), 2);
    assert_eq!(doc["dist-tags"]["latest"], "2.0.0");
}

#[tokio::test]
async fn npm_publish_over_http_requires_a_credential() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("npm-http-nocred");

    let tarball = build_test_npm("widget", "1.0.0");
    let body = publish_body("widget-1.0.0.tgz", &tarball);
    let resp = put_publish(&harness, &repo, "stable", "widget", None, body).await;
    // A missing credential becomes an anonymous caller rather than an
    // auth error (see `auth::authenticate_http`), and an anonymous caller
    // never has write access — so this is the same `Forbidden` a
    // wrong-scope token gets, not `Unauthorized`. That mirrors
    // `auth::require_repo` on the gRPC side, which keeps `Write`/`Admin`
    // refusals as `PermissionDenied` regardless of whether a token was
    // presented at all.
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(
        body_string(resp).await.contains("\"error\""),
        "npm prints the `error` field verbatim, so failures must be shaped that way"
    );
}

#[tokio::test]
async fn npm_publish_over_http_rejects_a_malformed_credential() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("npm-http-malformed");

    let tarball = build_test_npm("widget", "1.0.0");
    let body = publish_body("widget-1.0.0.tgz", &tarball);
    let resp = silo_server::http::router(harness.state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/{repo}/stable/npm/widget"))
                .header("content-type", "application/json")
                // An unsupported scheme is a credential that was presented
                // but doesn't parse — distinct from presenting none at
                // all, so it has to fail loudly rather than fall back to
                // anonymous.
                .header("authorization", "Digest not-a-bearer-token")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn npm_publish_over_http_rejects_a_read_only_token() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("npm-http-readonly");
    let reader = harness
        .token(
            "reader",
            Permission::Read,
            silo_db::tokens::Scope::Repos(vec![repo.clone()]),
        )
        .await;

    let tarball = build_test_npm("widget", "1.0.0");
    let body = publish_body("widget-1.0.0.tgz", &tarball);
    let resp = put_publish(
        &harness,
        &repo,
        "stable",
        "widget",
        Some(&reader.secret),
        body,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let rows = harness
        .db
        .list_packages(&repo, "stable", None)
        .await
        .unwrap();
    assert!(rows.is_empty(), "a rejected publish must not write a row");
}

#[tokio::test]
async fn npm_publish_over_http_rejects_an_invalid_tarball() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("npm-http-invalid");
    let writer = harness.publisher_token(&repo).await;

    let body = publish_body("widget-1.0.0.tgz", b"not a gzipped tarball");
    let resp = put_publish(
        &harness,
        &repo,
        "stable",
        "widget",
        Some(&writer.secret),
        body,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
