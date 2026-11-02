//! The web admin console: the JSON gateway, the embedded pages, and the
//! guarantee that both sit beside the package routes without shadowing
//! them.
//!
//! See `tests/common/mod.rs` for how to point these at a database.

mod common;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use common::{unique_repo, Harness};
use silo_db::tokens::{Permission, Scope};
use tower::ServiceExt;

fn app(harness: &Harness) -> axum::Router {
    silo_server::http::router(harness.state.clone())
        .merge(silo_server::webui::router(harness.state.clone()))
}

async fn rpc(
    app: &axum::Router,
    method: &str,
    token: Option<&str>,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(format!("/admin/api/rpc/{method}"))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or_default())
}

async fn get(app: &axum::Router, uri: &str) -> axum::response::Response {
    app.clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn the_console_is_served_with_a_restrictive_content_security_policy() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let app = app(&harness);

    let response = get(&app, "/admin/").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/html; charset=utf-8"
    );
    let csp = response.headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap();
    assert!(csp.contains("script-src 'self'"), "{csp}");
    assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
    assert_eq!(
        response.headers()[header::X_CONTENT_TYPE_OPTIONS],
        "nosniff"
    );
}

#[tokio::test]
async fn unknown_client_routes_fall_back_to_the_page_but_missing_files_do_not() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let app = app(&harness);

    assert_eq!(get(&app, "/admin/users").await.status(), StatusCode::OK);
    assert_eq!(
        get(&app, "/admin/repos/some/deep/path").await.status(),
        StatusCode::OK
    );
    assert_eq!(
        get(&app, "/admin/assets/nope.js").await.status(),
        StatusCode::NOT_FOUND
    );
    // A mistyped API path is an error, not a page.
    assert_eq!(
        get(&app, "/admin/api/nope").await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(&app, "/admin").await.status(),
        StatusCode::PERMANENT_REDIRECT
    );
}

#[tokio::test]
async fn package_routes_still_work_beside_the_console() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let app = app(&harness);

    // A repo named like any other still reaches the package handlers, not
    // the console's catch-all.
    let response = get(&app, "/somerepo/stable/repodata/repomd.xml").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(
        response
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .is_none(),
        "package responses are not console pages"
    );
}

#[tokio::test]
async fn the_name_admin_cannot_be_used_for_a_repo() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let app = app(&harness);
    let admin = harness.admin_token().await;

    let (status, body) = rpc(
        &app,
        "CreateRepo",
        Some(&admin.secret),
        serde_json::json!({ "repo": "admin" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["message"].as_str().unwrap().contains("reserved"));
}

#[tokio::test]
async fn an_unauthenticated_call_to_an_admin_method_is_refused() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let app = app(&harness);

    let (status, body) = rpc(&app, "ListUsers", None, serde_json::json!({})).await;
    assert!(
        matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN),
        "{status}: {body}"
    );
    assert!(body["code"].is_string());
}

#[tokio::test]
async fn a_non_admin_token_cannot_reach_admin_methods_through_the_gateway() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let app = app(&harness);
    let reader = harness.token("reader", Permission::Read, Scope::All).await;

    for method in ["ListUsers", "ListTokens", "GetStats", "GetServerInfo"] {
        let (status, body) = rpc(&app, method, Some(&reader.secret), serde_json::json!({})).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method}: {body}");
        assert_eq!(body["code"], "permission_denied");
    }
}

#[tokio::test]
async fn an_unknown_method_is_not_found() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let app = app(&harness);

    let (status, body) = rpc(&app, "Publish", None, serde_json::json!({})).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn an_admin_can_run_the_registry_through_the_gateway() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let app = app(&harness);
    let admin = harness.admin_token().await;
    let token = Some(admin.secret.as_str());
    let repo = unique_repo("gw");

    // Repo lifecycle.
    let (status, body) = rpc(
        &app,
        "CreateRepo",
        token,
        serde_json::json!({ "repo": repo, "mode": 1 }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = rpc(
        &app,
        "SetRepoMode",
        token,
        serde_json::json!({ "repo": repo, "mode": 2 }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["mode"], 2);

    let (status, body) = rpc(&app, "ListRepos", token, serde_json::json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["repos"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["repo"] == repo.as_str() && r["mode"] == 2));

    // Tokens: the secret is returned once, on create.
    let (status, body) = rpc(
        &app,
        "CreateToken",
        token,
        serde_json::json!({
            "name": format!("ci-{repo}"),
            "permission": "write",
            "scope": 2,
            "repos": [repo],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["token"].as_str().unwrap().len() > 20);
    assert_eq!(body["info"]["repos"][0], repo.as_str());

    // Users.
    let username = format!("user-{repo}");
    let (status, body) = rpc(
        &app,
        "CreateUser",
        token,
        serde_json::json!({ "username": username, "password": "correct horse battery" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // That user can sign in through the gateway and use what they get.
    let (status, session) = rpc(
        &app,
        "Login",
        None,
        serde_json::json!({ "username": username, "password": "correct horse battery" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{session}");
    let session_token = session["token"].as_str().unwrap().to_string();
    let (status, who) = rpc(&app, "WhoAmI", Some(&session_token), serde_json::json!({})).await;
    assert_eq!(status, StatusCode::OK, "{who}");
    assert_eq!(who["username"], username.as_str());

    // A wrong password is one uniform refusal.
    let (status, body) = rpc(
        &app,
        "Login",
        None,
        serde_json::json!({ "username": username, "password": "wrong" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

    // The login and the failed attempt are in the audit log, with the
    // gateway's caller recorded as an ordinary actor.
    let (status, audit) = rpc(
        &app,
        "QueryAudit",
        token,
        serde_json::json!({ "actor": username, "limit": 10 }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{audit}");
    assert!(audit["entries"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["action"] == "auth.login"));

    // Cleanup through the same door.
    let (status, body) = rpc(
        &app,
        "DeleteUser",
        token,
        serde_json::json!({ "username": username }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = rpc(
        &app,
        "DeleteRepo",
        token,
        serde_json::json!({ "repo": repo }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn stats_describe_what_was_published() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let app = app(&harness);
    let admin = harness.admin_token().await;
    let repo = unique_repo("stats");

    silo_core::repo::publish(
        &harness.state.publish,
        &repo,
        "stable",
        silo_pkg::PackageFormat::Rpm,
        silo_pkg::testutil::build_test_rpm("widget", "1.0", "1", "x86_64"),
        &silo_db::audit::Actor {
            kind: silo_db::audit::ActorKind::Token,
            name: "stats-test".into(),
            token_id: None,
            user_id: None,
            remote_addr: None,
        },
    )
    .await
    .expect("seed a package");

    let (status, stats) = rpc(
        &app,
        "GetStats",
        Some(&admin.secret),
        serde_json::json!({ "days": 7 }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{stats}");

    assert_eq!(stats["days"], 7);
    assert_eq!(stats["activity"].as_array().unwrap().len(), 7);
    assert!(stats["totals"]["packages"].as_i64().unwrap() >= 1);
    assert!(stats["totals"]["bytes"].as_i64().unwrap() > 0);

    let mine = stats["repos"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["repo"] == repo.as_str())
        .expect("the seeded repo appears in the per-repo breakdown");
    assert_eq!(mine["packages"], 1);
    assert_eq!(mine["channels"], 1);

    assert!(stats["formats"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["format"] == 1 && f["packages"].as_i64().unwrap() >= 1));

    // Today is the last bucket, and the publish landed in it.
    let today = stats["activity"].as_array().unwrap().last().unwrap();
    assert!(today["publishes"].as_i64().unwrap() >= 1, "{today}");

    assert!(stats["recent_packages"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p["name"] == "widget"));
}

#[tokio::test]
async fn a_repo_scoped_admin_cannot_read_registry_wide_stats() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let app = app(&harness);
    let repo = unique_repo("scoped");
    let scoped = harness
        .token("scoped", Permission::Admin, Scope::Repos(vec![repo]))
        .await;

    let (status, body) = rpc(
        &app,
        "GetStats",
        Some(&scoped.secret),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn server_info_reports_configuration_without_secrets() {
    let url = require_db!();
    let harness = Harness::with_config(&url, |config| {
        config.prune.enabled = true;
    })
    .await;
    let app = app(&harness);
    let admin = harness.admin_token().await;

    let (status, info) = rpc(
        &app,
        "GetServerInfo",
        Some(&admin.secret),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{info}");
    assert_eq!(info["prune_enabled"], true);
    assert_eq!(info["password_login_enabled"], true);
    assert_eq!(info["oidc_enabled"], false);
    assert_eq!(info["upstream_secret_configured"], true);
    assert!(info["jobs"].as_array().unwrap().len() >= 5);
    assert!(!info.to_string().contains("pepper"));
}

#[tokio::test]
async fn the_oidc_relay_refuses_when_oidc_is_not_configured() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let app = app(&harness);

    for (uri, body) in [
        ("/admin/api/oidc/device", "{}"),
        ("/admin/api/oidc/token", r#"{"device_code":"x"}"#),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(uri)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
    }
}
