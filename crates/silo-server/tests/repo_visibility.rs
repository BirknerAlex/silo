//! Per-repo public/private mode: creation defaults, admin-only mode
//! changes, unauthenticated reads against public repos, and that private
//! repos stay invisible to everyone without access to them.
//!
//! See `tests/common/mod.rs` for how to point these at a database.

mod common;

use common::{unique_repo, Harness};
use silo_db::audit::{Actor, ActorKind};
use silo_pkg::testutil::build_test_apk;
use silo_pkg::PackageFormat;
use silo_proto::v1::admin_service_server::AdminService;
use silo_proto::v1::read_service_server::ReadService;
use silo_proto::v1::{ListPackagesRequest, ListReposRequest, RepoMode, SetRepoModeRequest};
use silo_server::admin::AdminServiceImpl;
use silo_server::grpc::ReadServiceImpl;

fn actor() -> Actor {
    Actor {
        kind: ActorKind::Token,
        name: "test-publisher".into(),
        token_id: None,
        user_id: None,
        remote_addr: Some("10.0.0.1".into()),
    }
}

/// Builds a gRPC request with a bearer token, or none at all for an
/// anonymous caller — `None` never inserts the header rather than
/// inserting an empty one, matching what a real client without a
/// credential sends.
fn request<T>(msg: T, token: Option<&str>) -> tonic::Request<T> {
    let mut req = tonic::Request::new(msg);
    if let Some(token) = token {
        req.metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
    }
    req
}

#[tokio::test]
async fn publishing_creates_a_private_repo_by_default() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("newrepo");

    silo_core::repo::publish(
        &harness.state.publish,
        &repo,
        "edge",
        PackageFormat::Apk,
        build_test_apk("hello", "1.0-r0", "x86_64"),
        &actor(),
    )
    .await
    .expect("publish apk");

    assert!(!harness.db.is_repo_public(&repo).await.unwrap());
}

#[tokio::test]
async fn only_an_admin_token_can_change_a_repos_mode() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("modeauth");
    let admin_service = AdminServiceImpl {
        state: harness.state.clone(),
    };

    // A write-permission token — even one scoped to exactly this repo —
    // is not an admin token and must be refused.
    let writer = harness.publisher_token(&repo).await;
    let err = admin_service
        .set_repo_mode(request(
            SetRepoModeRequest {
                repo: repo.clone(),
                mode: RepoMode::Public as i32,
            },
            Some(&writer.secret),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    assert!(!harness.db.is_repo_public(&repo).await.unwrap());

    // No credential at all: same refusal, not a different error shape
    // that would hint the repo exists.
    let err = admin_service
        .set_repo_mode(request(
            SetRepoModeRequest {
                repo: repo.clone(),
                mode: RepoMode::Public as i32,
            },
            None,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    // An admin token succeeds.
    let admin = harness.admin_token().await;
    let response = admin_service
        .set_repo_mode(request(
            SetRepoModeRequest {
                repo: repo.clone(),
                mode: RepoMode::Public as i32,
            },
            Some(&admin.secret),
        ))
        .await
        .expect("admin can set repo mode")
        .into_inner();
    assert_eq!(response.mode, RepoMode::Public as i32);
    assert!(harness.db.is_repo_public(&repo).await.unwrap());
}

#[tokio::test]
async fn going_public_only_adds_unauthenticated_read_write_access_is_untouched() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("publicwrite");

    let writer = harness.publisher_token(&repo).await;
    silo_core::repo::publish(
        &harness.state.publish,
        &repo,
        "edge",
        PackageFormat::Apk,
        build_test_apk("hello", "1.0-r0", "x86_64"),
        &actor(),
    )
    .await
    .expect("initial publish");

    harness.db.set_repo_public(&repo, true).await.unwrap();

    let read_service = ReadServiceImpl {
        state: harness.state.clone(),
    };

    // Reading now needs no credential at all.
    let response = read_service
        .list_packages(request(
            ListPackagesRequest {
                repo: repo.clone(),
                channel: "edge".into(),
                format: 0,
            },
            None,
        ))
        .await
        .expect("anonymous read of a public repo succeeds")
        .into_inner();
    assert_eq!(response.packages.len(), 1);

    // `auth::require_repo` is exactly the check `PublishService::publish`
    // runs before accepting a single byte — this exercises the real
    // decision without needing to hand-build a `Streaming<PublishRequest>`
    // (a concrete, connection-backed tonic type the publish RPC's own
    // streaming byte-handling is already covered elsewhere for).
    let write_scoped = silo_server::auth::authenticate(&harness.state, &writer.secret, None)
        .await
        .expect("the write token verifies");
    silo_server::auth::require_repo(
        &harness.state,
        &write_scoped,
        &repo,
        silo_db::tokens::Permission::Write,
    )
    .await
    .expect("a write-scoped token keeps working on a public repo");

    // But public never grants write to an uncredentialed caller.
    let anon = silo_server::auth::Authenticated::anonymous(None);
    let err = silo_server::auth::require_repo(
        &harness.state,
        &anon,
        &repo,
        silo_db::tokens::Permission::Write,
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn going_back_to_private_removes_the_unauthenticated_read_but_not_write_access() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("backprivate");

    let writer = harness.publisher_token(&repo).await;
    silo_core::repo::publish(
        &harness.state.publish,
        &repo,
        "edge",
        PackageFormat::Apk,
        build_test_apk("hello", "1.0-r0", "x86_64"),
        &actor(),
    )
    .await
    .expect("initial publish");

    harness.db.set_repo_public(&repo, true).await.unwrap();
    harness.db.set_repo_public(&repo, false).await.unwrap();

    let read_service = ReadServiceImpl {
        state: harness.state.clone(),
    };

    // Anonymous reads are refused again, indistinguishably from a repo
    // that never existed.
    let err = read_service
        .list_packages(request(
            ListPackagesRequest {
                repo: repo.clone(),
                channel: "edge".into(),
                format: 0,
            },
            None,
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);

    // The write-scoped token was never touched by either mode change.
    let response = read_service
        .list_packages(request(
            ListPackagesRequest {
                repo: repo.clone(),
                channel: "edge".into(),
                format: 0,
            },
            Some(&writer.secret),
        ))
        .await
        .expect("the scoped token still reads")
        .into_inner();
    assert_eq!(response.packages.len(), 1);
}

#[tokio::test]
async fn a_private_repo_is_invisible_to_anonymous_and_out_of_scope_callers_alike() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let private_repo = unique_repo("hidden");
    let other_repo = unique_repo("elsewhere");

    silo_core::repo::publish(
        &harness.state.publish,
        &private_repo,
        "edge",
        PackageFormat::Apk,
        build_test_apk("hello", "1.0-r0", "x86_64"),
        &actor(),
    )
    .await
    .expect("publish to the private repo");

    let read_service = ReadServiceImpl {
        state: harness.state.clone(),
    };
    let outsider = harness.publisher_token(&other_repo).await;

    let anon_err = read_service
        .list_packages(request(
            ListPackagesRequest {
                repo: private_repo.clone(),
                channel: "edge".into(),
                format: 0,
            },
            None,
        ))
        .await
        .unwrap_err();
    let scoped_err = read_service
        .list_packages(request(
            ListPackagesRequest {
                repo: private_repo.clone(),
                channel: "edge".into(),
                format: 0,
            },
            Some(&outsider.secret),
        ))
        .await
        .unwrap_err();

    // Both callers get exactly the same refusal — nothing distinguishes
    // "private" from "doesn't exist" or from "scoped elsewhere".
    assert_eq!(anon_err.code(), tonic::Code::NotFound);
    assert_eq!(scoped_err.code(), tonic::Code::NotFound);

    // And neither sees it in a repo listing.
    for token in [None, Some(outsider.secret.as_str())] {
        let repos = read_service
            .list_repos(request(ListReposRequest {}, token))
            .await
            .unwrap()
            .into_inner()
            .repos;
        assert!(
            !repos.iter().any(|r| r.repo == private_repo),
            "private repo leaked to {token:?}"
        );
    }
}

#[tokio::test]
async fn list_repos_shows_a_scoped_tokens_own_repos_plus_public_ones_only() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let mine = unique_repo("mine");
    let private_other = unique_repo("notmine");
    let public_other = unique_repo("everyonesrepo");

    for repo in [&mine, &private_other, &public_other] {
        silo_core::repo::publish(
            &harness.state.publish,
            repo,
            "edge",
            PackageFormat::Apk,
            build_test_apk("hello", "1.0-r0", "x86_64"),
            &actor(),
        )
        .await
        .expect("publish");
    }
    harness
        .db
        .set_repo_public(&public_other, true)
        .await
        .unwrap();

    let token = harness.publisher_token(&mine).await;
    let read_service = ReadServiceImpl {
        state: harness.state.clone(),
    };
    let repos: std::collections::BTreeSet<String> = read_service
        .list_repos(request(ListReposRequest {}, Some(&token.secret)))
        .await
        .unwrap()
        .into_inner()
        .repos
        .into_iter()
        .map(|r| r.repo)
        .collect();

    assert!(repos.contains(&mine));
    assert!(repos.contains(&public_other));
    assert!(!repos.contains(&private_other));
}

#[tokio::test]
async fn http_pull_of_a_public_repo_needs_no_credential_private_still_404s() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let public_repo = unique_repo("httppublic");
    let private_repo = unique_repo("httpprivate");

    for repo in [&public_repo, &private_repo] {
        harness
            .state
            .storage
            .put(
                &format!("{repo}/edge/repodata/repomd.xml"),
                b"<repomd/>".to_vec(),
            )
            .await
            .unwrap();
    }
    harness
        .db
        .set_repo_public(&public_repo, true)
        .await
        .unwrap();

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    let public_resp = silo_server::http::router(harness.state.clone())
        .oneshot(
            Request::builder()
                .uri(format!("/{public_repo}/edge/repodata/repomd.xml"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(public_resp.status(), StatusCode::OK);

    let private_resp = silo_server::http::router(harness.state.clone())
        .oneshot(
            Request::builder()
                .uri(format!("/{private_repo}/edge/repodata/repomd.xml"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(private_resp.status(), StatusCode::NOT_FOUND);
}
