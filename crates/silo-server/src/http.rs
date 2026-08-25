//! Plain HTTP surface for `dnf`/`yum`: repodata + package downloads.
//!
//! dnf's `.repo` files support `username=`/`password=` on a baseurl, which
//! curl (and therefore dnf) sends as HTTP Basic auth — so the read token
//! is checked as a Basic-auth password here rather than requiring a custom
//! header dnf can't easily send. The username is ignored.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use base64::Engine;

use crate::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/:repo/:channel/repodata/*file", get(get_repodata))
        .route("/:repo/:channel/Packages/*file", get(get_package))
        .with_state(state)
}

#[allow(clippy::result_large_err)] // Response is axum's standard response type; boxing it here would just push the cost to every caller
fn check_read_auth(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    let unauthorized = || {
        (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"silo\"")],
            "unauthorized",
        )
            .into_response()
    };

    let Some(auth) = headers.get(header::AUTHORIZATION) else {
        return Err(unauthorized());
    };
    let Ok(auth) = auth.to_str() else {
        return Err(unauthorized());
    };
    let Some(encoded) = auth.strip_prefix("Basic ") else {
        return Err(unauthorized());
    };
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
        return Err(unauthorized());
    };
    let Ok(decoded) = String::from_utf8(decoded) else {
        return Err(unauthorized());
    };
    let password = decoded.split_once(':').map(|(_, p)| p).unwrap_or("");

    if password == state.config.auth.read_token {
        Ok(())
    } else {
        Err(unauthorized())
    }
}

async fn get_repodata(
    State(state): State<Arc<AppState>>,
    Path((repo, channel, file)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = check_read_auth(&state, &headers) {
        return resp;
    }

    let key = format!(
        "{}/{file}",
        silo_core::repo::repodata_prefix(&repo, &channel)
    );
    match state.storage.get(&key).await {
        Ok(Some(bytes)) => (StatusCode::OK, bytes).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_package(
    State(state): State<Arc<AppState>>,
    Path((repo, channel, file)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = check_read_auth(&state, &headers) {
        return resp;
    }

    let key = format!(
        "{}/{file}",
        silo_core::repo::packages_prefix(&repo, &channel)
    );

    match state.storage.presigned_get_url(&key).await {
        Ok(Some(url)) => return Redirect::temporary(&url).into_response(),
        Ok(None) => {}
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }

    match state.storage.get(&key).await {
        Ok(Some(bytes)) => (StatusCode::OK, bytes).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AppState;
    use axum::body::Body;
    use axum::http::Request;
    use silo_core::{
        config::{AuthConfig, Config, StorageConfig},
        Storage,
    };
    use tower::ServiceExt;

    fn test_state() -> Arc<AppState> {
        Arc::new(AppState {
            config: Config {
                grpc_addr: "127.0.0.1:0".into(),
                http_addr: "127.0.0.1:0".into(),
                storage: StorageConfig {
                    bucket: "test".into(),
                    endpoint: None,
                    region: "us-east-1".into(),
                    access_key_id: "x".into(),
                    secret_access_key: "x".into(),
                    allow_http: false,
                },
                auth: AuthConfig {
                    publish_token: "pub-token".into(),
                    read_token: "read-token".into(),
                },
                gpg: None,
            },
            storage: Storage::in_memory(),
        })
    }

    fn basic_auth_header(password: &str) -> String {
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("silo:{password}"));
        format!("Basic {encoded}")
    }

    #[tokio::test]
    async fn repodata_requires_auth() {
        let state = test_state();
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/myrepo/stable/repodata/repomd.xml")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn repodata_rejects_wrong_password() {
        let state = test_state();
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/myrepo/stable/repodata/repomd.xml")
                    .header(header::AUTHORIZATION, basic_auth_header("wrong"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn repodata_returns_404_when_missing() {
        let state = test_state();
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/myrepo/stable/repodata/repomd.xml")
                    .header(header::AUTHORIZATION, basic_auth_header("read-token"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn repodata_serves_stored_bytes() {
        let state = test_state();
        state
            .storage
            .put("myrepo/stable/repodata/repomd.xml", b"<repomd/>".to_vec())
            .await
            .unwrap();
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/myrepo/stable/repodata/repomd.xml")
                    .header(header::AUTHORIZATION, basic_auth_header("read-token"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"<repomd/>");
    }

    #[tokio::test]
    async fn package_falls_back_to_proxying_bytes_without_a_signer() {
        // in-memory storage backend has no presigning support, so this
        // exercises the direct-proxy fallback path.
        let state = test_state();
        state
            .storage
            .put(
                "myrepo/stable/Packages/foo-1.0-1.x86_64.rpm",
                b"rpmbytes".to_vec(),
            )
            .await
            .unwrap();
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/myrepo/stable/Packages/foo-1.0-1.x86_64.rpm")
                    .header(header::AUTHORIZATION, basic_auth_header("read-token"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"rpmbytes");
    }
}
