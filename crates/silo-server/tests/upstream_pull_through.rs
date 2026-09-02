//! Pull-through cache: adding an upstream (validation + first sync),
//! serving a cache miss through it (cache/no-cache, authed/unauthed), the
//! index merge that makes an unfetched upstream package requestable at
//! all, and origin-scoped pruning.
//!
//! See `tests/common/mod.rs` for how to point these at a database. The
//! upstream itself is a `wiremock` server standing in for a real Alpine
//! repository — apk is used throughout because its upstream index (a
//! plain-text `APKINDEX` inside a small tar.gz) is the cheapest of the
//! five formats to hand-build without vendoring a real mirror snippet.

mod common;

use common::{unique_repo, Harness};
use flate2::write::GzEncoder;
use flate2::Compression;
use silo_pkg::testutil::build_test_apk;
use silo_pkg::{Format, PackageFormat};
use silo_proto::v1::admin_service_server::AdminService;
use silo_proto::v1::{
    AddUpstreamRequest, RemoveUpstreamRequest, RunPruneRequest, SetPruneRuleRequest,
    SyncUpstreamRequest, UpstreamAuth, UpstreamCacheMode,
};
use silo_server::admin::AdminServiceImpl;
use std::io::Write;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn request<T>(msg: T, token: &str) -> tonic::Request<T> {
    let mut req = tonic::Request::new(msg);
    req.metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    req
}

/// A single-member `APKINDEX.tar.gz` listing one package — the same wire
/// shape `ApkFormat::build_index` produces, hand-built here since the
/// tar/gzip helpers that build it are private to `silo-pkg`.
fn build_apkindex_tar_gz(name: &str, version: &str, arch: &str, size: usize) -> Vec<u8> {
    let text = format!("C:Q1abc\nP:{name}\nV:{version}\nA:{arch}\nS:{size}\n\n");
    let mut tar = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_ustar();
    header.set_path("APKINDEX").unwrap();
    header.set_size(text.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append(&header, text.as_bytes()).unwrap();
    let tar_bytes = tar.into_inner().unwrap();

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_bytes).unwrap();
    encoder.finish().unwrap()
}

async fn get(state: &std::sync::Arc<silo_server::AppState>, uri: &str) -> axum::response::Response {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    silo_server::http::router(state.clone())
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn add_upstream_validates_and_syncs_before_creating_the_row() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("addup");
    let admin = harness.admin_token().await;
    let service = AdminServiceImpl {
        state: harness.state.clone(),
    };

    let mock = MockServer::start().await;
    let apk_bytes = build_test_apk("hello", "1.0-r0", "x86_64");
    Mock::given(method("GET"))
        .and(path("/x86_64/APKINDEX.tar.gz"))
        .respond_with(
            ResponseTemplate::new(200).set_body_bytes(build_apkindex_tar_gz(
                "hello",
                "1.0-r0",
                "x86_64",
                apk_bytes.len(),
            )),
        )
        .mount(&mock)
        .await;

    let response = service
        .add_upstream(request(
            AddUpstreamRequest {
                repo: repo.clone(),
                channel: "stable".into(),
                name: "alpine".into(),
                format: silo_proto::v1::PackageFormat::Apk as i32,
                base_url: mock.uri(),
                cache_mode: UpstreamCacheMode::Cache as i32,
                cache_index_in_memory: false,
                auth: None,
                arches: vec!["x86_64".into()],
                suite: String::new(),
                components: vec![],
            },
            &admin.secret,
        ))
        .await
        .expect("add_upstream")
        .into_inner();

    let upstream = response.upstream.expect("upstream in response");
    assert_eq!(upstream.status, "ok");
    assert!(!upstream.id.is_empty());

    let row = harness
        .db
        .get_upstream(&repo, "stable", "alpine")
        .await
        .unwrap()
        .expect("row persisted");
    let synced = harness.db.list_all_upstream_packages(row.id).await.unwrap();
    assert_eq!(synced.len(), 1);
    assert_eq!(synced[0].name, "hello");
}

#[tokio::test]
async fn add_upstream_against_an_unreachable_url_creates_no_row() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("addupbad");
    let admin = harness.admin_token().await;
    let service = AdminServiceImpl {
        state: harness.state.clone(),
    };

    let result = service
        .add_upstream(request(
            AddUpstreamRequest {
                repo: repo.clone(),
                channel: "stable".into(),
                name: "broken".into(),
                format: silo_proto::v1::PackageFormat::Apk as i32,
                base_url: "http://127.0.0.1:1".into(), // nothing listens here
                cache_mode: UpstreamCacheMode::Cache as i32,
                cache_index_in_memory: false,
                auth: None,
                arches: vec!["x86_64".into()],
                suite: String::new(),
                components: vec![],
            },
            &admin.secret,
        ))
        .await;

    assert!(result.is_err());
    assert!(harness
        .db
        .get_upstream(&repo, "stable", "broken")
        .await
        .unwrap()
        .is_none());
}

/// Sets up a repo with a `cache`-mode apk upstream, synced, and returns
/// the mock server plus the artifact's real bytes.
async fn setup_cache_upstream(
    harness: &Harness,
    repo: &str,
    cache_mode: UpstreamCacheMode,
    auth: Option<UpstreamAuth>,
) -> (MockServer, Vec<u8>) {
    let admin = harness.admin_token().await;
    let service = AdminServiceImpl {
        state: harness.state.clone(),
    };
    let mock = MockServer::start().await;
    let apk_bytes = build_test_apk("hello", "1.0-r0", "x86_64");

    Mock::given(method("GET"))
        .and(path("/x86_64/APKINDEX.tar.gz"))
        .respond_with(
            ResponseTemplate::new(200).set_body_bytes(build_apkindex_tar_gz(
                "hello",
                "1.0-r0",
                "x86_64",
                apk_bytes.len(),
            )),
        )
        .mount(&mock)
        .await;

    Mock::given(method("GET"))
        .and(path("/x86_64/hello-1.0-r0.apk"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(apk_bytes.clone()))
        .mount(&mock)
        .await;

    service
        .add_upstream(request(
            AddUpstreamRequest {
                repo: repo.to_string(),
                channel: "stable".into(),
                name: "alpine".into(),
                format: silo_proto::v1::PackageFormat::Apk as i32,
                base_url: mock.uri(),
                cache_mode: cache_mode as i32,
                cache_index_in_memory: false,
                auth,
                arches: vec!["x86_64".into()],
                suite: String::new(),
                components: vec![],
            },
            &admin.secret,
        ))
        .await
        .expect("add_upstream");

    (mock, apk_bytes)
}

#[tokio::test]
async fn cache_mode_miss_fetches_and_persists_then_serves_locally_on_the_second_request() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("cachemiss");
    let (mock, apk_bytes) =
        setup_cache_upstream(&harness, &repo, UpstreamCacheMode::Cache, None).await;
    harness.db.set_repo_public(&repo, true).await.unwrap();

    let uri = format!("/{repo}/stable/apk/x86_64/hello-1.0-r0.apk");
    let first = get(&harness.state, &uri).await;
    assert_eq!(first.status(), axum::http::StatusCode::OK);
    let body = axum::body::to_bytes(first.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(body.to_vec(), apk_bytes);

    // The package must now exist locally, tagged with its upstream's origin.
    let rows = harness
        .db
        .list_packages(&repo, "stable", None)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].origin_upstream_id.is_some());

    // A second request must not hit the upstream again.
    let requests_before = mock.received_requests().await.unwrap().len();
    let second = get(&harness.state, &uri).await;
    assert_eq!(second.status(), axum::http::StatusCode::OK);
    let requests_after = mock.received_requests().await.unwrap().len();
    assert_eq!(
        requests_before, requests_after,
        "a package already cached locally must not re-fetch upstream"
    );
}

#[tokio::test]
async fn no_cache_unauthenticated_upstream_redirects_and_persists_nothing() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("nocache");
    let (_mock, _bytes) =
        setup_cache_upstream(&harness, &repo, UpstreamCacheMode::NoCache, None).await;
    harness.db.set_repo_public(&repo, true).await.unwrap();

    let uri = format!("/{repo}/stable/apk/x86_64/hello-1.0-r0.apk");
    let response = get(&harness.state, &uri).await;
    assert_eq!(response.status(), axum::http::StatusCode::FOUND);
    let location = response
        .headers()
        .get(axum::http::header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(location.contains("hello-1.0-r0.apk"), "got: {location}");

    let rows = harness
        .db
        .list_packages(&repo, "stable", None)
        .await
        .unwrap();
    assert!(rows.is_empty(), "no-cache must never persist a package");
}

#[tokio::test]
async fn no_cache_authenticated_upstream_proxies_sends_the_credential_upstream_and_never_leaks_it_to_the_client(
) {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("nocacheauth");
    let auth = UpstreamAuth {
        kind: "bearer".into(),
        username: String::new(),
        secret: "s3cr3t-upstream-token".into(),
    };
    let (mock, apk_bytes) =
        setup_cache_upstream(&harness, &repo, UpstreamCacheMode::NoCache, Some(auth)).await;
    harness.db.set_repo_public(&repo, true).await.unwrap();

    // Re-mount the package route requiring the credential, since
    // `setup_cache_upstream`'s mount didn't check for one.
    Mock::given(method("GET"))
        .and(path("/x86_64/hello-1.0-r0.apk"))
        .and(wiremock::matchers::header(
            "Authorization",
            "Bearer s3cr3t-upstream-token",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(apk_bytes.clone()))
        .mount(&mock)
        .await;

    let uri = format!("/{repo}/stable/apk/x86_64/hello-1.0-r0.apk");
    let response = get(&harness.state, &uri).await;
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(body.to_vec(), apk_bytes);

    // The credential must never appear anywhere in what the client sees.
    for (_, value) in headers.iter() {
        assert!(
            !value
                .to_str()
                .unwrap_or("")
                .contains("s3cr3t-upstream-token"),
            "the upstream credential leaked into a response header"
        );
    }

    // And the mock server actually required it — a request without the
    // header would have 404'd against the second, credential-gated mount
    // (wiremock matches the most specific mount; if the credential were
    // never sent, this whole request would have failed rather than 200'd).
    let seen = mock.received_requests().await.unwrap();
    assert!(seen.iter().any(|r| r
        .headers
        .get("authorization")
        .is_some_and(|v| v == "Bearer s3cr3t-upstream-token")));

    let rows = harness
        .db
        .list_packages(&repo, "stable", None)
        .await
        .unwrap();
    assert!(rows.is_empty(), "no-cache must never persist a package");
}

#[tokio::test]
async fn prune_origin_scope_upstream_only_touches_pulled_through_packages() {
    let url = require_db!();
    let harness = Harness::with_config(&url, |c| c.prune.enabled = true).await;
    let repo = unique_repo("originprune");
    let (_mock, _bytes) =
        setup_cache_upstream(&harness, &repo, UpstreamCacheMode::Cache, None).await;
    harness.db.set_repo_public(&repo, true).await.unwrap();

    // Pull the upstream package through, so it's cached locally with an origin.
    let uri = format!("/{repo}/stable/apk/x86_64/hello-1.0-r0.apk");
    assert_eq!(
        get(&harness.state, &uri).await.status(),
        axum::http::StatusCode::OK
    );

    // And publish an unrelated local package of the same name pattern.
    silo_core::repo::publish(
        &harness.state.publish,
        &repo,
        "stable",
        PackageFormat::Apk,
        build_test_apk("local-only", "1.0-r0", "x86_64"),
        &silo_db::audit::Actor::system(),
    )
    .await
    .unwrap();

    assert_eq!(
        harness
            .db
            .list_packages(&repo, "stable", None)
            .await
            .unwrap()
            .len(),
        2
    );

    // Back-date the pulled-through copy so a `max_age_days` rule has
    // something to violate; the fresh local-only package would never
    // trip it anyway, but scoping to `upstream` means it's never even
    // considered.
    sqlx::query(
        "UPDATE packages SET published_at = now() - interval '2 days' WHERE origin_upstream_id IS NOT NULL AND repo = $1",
    )
    .bind(&repo)
    .execute(harness.db.pool())
    .await
    .unwrap();

    let admin = harness.admin_token().await;
    let service = AdminServiceImpl {
        state: harness.state.clone(),
    };
    service
        .set_prune_rule(request(
            SetPruneRuleRequest {
                repo: repo.clone(),
                channel: "stable".into(),
                keep_last_n: None,
                max_age_days: Some(1),
                origin_scope: silo_proto::v1::OriginScope::Upstream as i32,
            },
            &admin.secret,
        ))
        .await
        .expect("set prune rule");

    let response = service
        .run_prune(request(
            RunPruneRequest {
                repo: repo.clone(),
                channel: "stable".into(),
                dry_run: false,
            },
            &admin.secret,
        ))
        .await
        .expect("run prune")
        .into_inner();
    assert_eq!(
        response.deleted, 1,
        "only the upstream-origin package should be pruned"
    );

    let remaining = harness
        .db
        .list_packages(&repo, "stable", None)
        .await
        .unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].name, "local-only");
    assert!(remaining[0].origin_upstream_id.is_none());
}

#[tokio::test]
async fn sync_upstream_and_remove_upstream_prune_flag_round_trip() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("removeup");
    let (_mock, _bytes) =
        setup_cache_upstream(&harness, &repo, UpstreamCacheMode::Cache, None).await;
    harness.db.set_repo_public(&repo, true).await.unwrap();

    let admin = harness.admin_token().await;
    let service = AdminServiceImpl {
        state: harness.state.clone(),
    };

    // sync-upstream re-syncs on demand.
    let synced = service
        .sync_upstream(request(
            SyncUpstreamRequest {
                repo: repo.clone(),
                channel: "stable".into(),
                name: "alpine".into(),
            },
            &admin.secret,
        ))
        .await
        .expect("sync_upstream")
        .into_inner();
    assert_eq!(synced.packages_synced, 1);

    // Pull the package through so it's cached, then remove the upstream
    // without --prune: the package must survive, relabeled as local.
    let uri = format!("/{repo}/stable/apk/x86_64/hello-1.0-r0.apk");
    assert_eq!(
        get(&harness.state, &uri).await.status(),
        axum::http::StatusCode::OK
    );

    let removed = service
        .remove_upstream(request(
            RemoveUpstreamRequest {
                repo: repo.clone(),
                channel: "stable".into(),
                name: "alpine".into(),
                prune: false,
            },
            &admin.secret,
        ))
        .await
        .expect("remove_upstream")
        .into_inner();
    assert!(removed.removed);
    assert_eq!(removed.packages_pruned, 0);

    let rows = harness
        .db
        .list_packages(&repo, "stable", None)
        .await
        .unwrap();
    assert_eq!(
        rows.len(),
        1,
        "the cached package must survive removal without --prune"
    );
    assert!(
        rows[0].origin_upstream_id.is_none(),
        "it must be relabeled as local"
    );
}

#[tokio::test]
async fn the_rendered_index_advertises_an_unfetched_upstream_package() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("indexmerge");
    let (_mock, _bytes) =
        setup_cache_upstream(&harness, &repo, UpstreamCacheMode::Cache, None).await;
    harness.db.set_repo_public(&repo, true).await.unwrap();

    // Publishing a second, unrelated local package triggers a real index
    // regeneration for the same group, which is where the merge happens.
    silo_core::repo::publish(
        &harness.state.publish,
        &repo,
        "stable",
        PackageFormat::Apk,
        build_test_apk("local-only", "2.0-r0", "x86_64"),
        &silo_db::audit::Actor::system(),
    )
    .await
    .unwrap();

    let response = get(
        &harness.state,
        &format!("/{repo}/stable/apk/x86_64/APKINDEX.tar.gz"),
    )
    .await;
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();

    let mut inflated = Vec::new();
    std::io::Read::read_to_end(
        &mut flate2::bufread::MultiGzDecoder::new(bytes.as_ref()),
        &mut inflated,
    )
    .unwrap();
    let mut archive = tar::Archive::new(inflated.as_slice());
    let mut apkindex_text = String::new();
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        if entry.path().unwrap().to_string_lossy() == "APKINDEX" {
            std::io::Read::read_to_string(&mut entry, &mut apkindex_text).unwrap();
        }
    }
    assert!(apkindex_text.contains("P:local-only"), "{apkindex_text}");
    assert!(
        apkindex_text.contains("P:hello"),
        "the unfetched upstream package must still be advertised: {apkindex_text}"
    );
}

/// A noarch upstream package has to fold into *every* concrete
/// architecture's merged index, not just a group literally named
/// "noarch" — apk-tools only ever fetches its own host architecture's
/// APKINDEX and never looks in a noarch tree on its own (see `apk.rs`'s
/// module doc). Real Alpine mirrors satisfy this by duplicating a noarch
/// package's entry into every concrete architecture's real APKINDEX,
/// which is exactly what this test's mock upstream does — the synced
/// entry's own `A:` field still says `noarch` even though it was fetched
/// from the `aarch64` index.
#[tokio::test]
async fn a_noarch_upstream_package_is_merged_into_every_concrete_architecture() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("noarchfold");
    let admin = harness.admin_token().await;
    let service = AdminServiceImpl {
        state: harness.state.clone(),
    };

    let mock = MockServer::start().await;
    let apk_bytes = build_test_apk("hello", "1.0-r0", "noarch");
    // A real Alpine mirror serves this exact shape: the noarch package's
    // entry duplicated into the concrete architecture's own index, `A:`
    // field unchanged.
    let text = format!(
        "C:Q1abc\nP:hello\nV:1.0-r0\nA:noarch\nS:{}\n\n",
        apk_bytes.len()
    );
    let index_tar = {
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_ustar();
        header.set_path("APKINDEX").unwrap();
        header.set_size(text.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append(&header, text.as_bytes()).unwrap();
        tar.into_inner().unwrap()
    };
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&index_tar).unwrap();
    let index_gz = encoder.finish().unwrap();

    Mock::given(method("GET"))
        .and(path("/aarch64/APKINDEX.tar.gz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(index_gz))
        .mount(&mock)
        .await;

    service
        .add_upstream(request(
            AddUpstreamRequest {
                repo: repo.clone(),
                channel: "stable".into(),
                name: "alpine".into(),
                format: silo_proto::v1::PackageFormat::Apk as i32,
                base_url: mock.uri(),
                cache_mode: UpstreamCacheMode::Cache as i32,
                cache_index_in_memory: false,
                auth: None,
                arches: vec!["aarch64".into()],
                suite: String::new(),
                components: vec![],
            },
            &admin.secret,
        ))
        .await
        .expect("add_upstream");
    harness.db.set_repo_public(&repo, true).await.unwrap();

    let response = get(
        &harness.state,
        &format!("/{repo}/stable/apk/aarch64/APKINDEX.tar.gz"),
    )
    .await;
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let mut inflated = Vec::new();
    std::io::Read::read_to_end(
        &mut flate2::bufread::MultiGzDecoder::new(bytes.as_ref()),
        &mut inflated,
    )
    .unwrap();
    let mut archive = tar::Archive::new(inflated.as_slice());
    let mut apkindex_text = String::new();
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        if entry.path().unwrap().to_string_lossy() == "APKINDEX" {
            std::io::Read::read_to_string(&mut entry, &mut apkindex_text).unwrap();
        }
    }
    assert!(
        apkindex_text.contains("P:hello"),
        "a noarch upstream package must be merged into a concrete arch's index: {apkindex_text}"
    );
}

/// The opt-in in-memory index accelerator is purely a fast-path (see
/// `silo_core::upstream_index_cache`) — enabling it must not change any
/// observable behavior, only (potentially) latency. This exercises it
/// through the real pull-through path end to end rather than only via
/// the cache's own unit tests, which know nothing about `PublishContext`
/// or the HTTP surface.
#[tokio::test]
async fn cache_index_in_memory_does_not_change_pull_through_behavior() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("idxcache");
    let admin = harness.admin_token().await;
    let service = AdminServiceImpl {
        state: harness.state.clone(),
    };
    let mock = MockServer::start().await;
    let apk_bytes = build_test_apk("hello", "1.0-r0", "x86_64");
    Mock::given(method("GET"))
        .and(path("/x86_64/APKINDEX.tar.gz"))
        .respond_with(
            ResponseTemplate::new(200).set_body_bytes(build_apkindex_tar_gz(
                "hello",
                "1.0-r0",
                "x86_64",
                apk_bytes.len(),
            )),
        )
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path("/x86_64/hello-1.0-r0.apk"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(apk_bytes.clone()))
        .mount(&mock)
        .await;

    service
        .add_upstream(request(
            AddUpstreamRequest {
                repo: repo.clone(),
                channel: "stable".into(),
                name: "alpine".into(),
                format: silo_proto::v1::PackageFormat::Apk as i32,
                base_url: mock.uri(),
                cache_mode: UpstreamCacheMode::Cache as i32,
                cache_index_in_memory: true,
                auth: None,
                arches: vec!["x86_64".into()],
                suite: String::new(),
                components: vec![],
            },
            &admin.secret,
        ))
        .await
        .expect("add_upstream");
    harness.db.set_repo_public(&repo, true).await.unwrap();

    let uri = format!("/{repo}/stable/apk/x86_64/hello-1.0-r0.apk");
    let response = get(&harness.state, &uri).await;
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(body.to_vec(), apk_bytes);

    let rows = harness
        .db
        .list_packages(&repo, "stable", None)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].origin_upstream_id.is_some());
}

/// A repo/channel that has never had a single local publish must still
/// get a real index once an upstream is added — otherwise a real client
/// (which always fetches the whole index before ever asking for one
/// artifact by name) could never discover anything to install at all.
#[tokio::test]
async fn add_upstream_produces_a_real_index_for_a_repo_that_was_never_published_to() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("mirroronly");
    let (_mock, _bytes) =
        setup_cache_upstream(&harness, &repo, UpstreamCacheMode::Cache, None).await;
    harness.db.set_repo_public(&repo, true).await.unwrap();

    // Never published locally: the index has to come purely from the
    // upstream sync's eager rebuild.
    assert!(harness
        .db
        .list_packages(&repo, "stable", None)
        .await
        .unwrap()
        .is_empty());

    let response = get(
        &harness.state,
        &format!("/{repo}/stable/apk/x86_64/APKINDEX.tar.gz"),
    )
    .await;
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();

    let mut inflated = Vec::new();
    std::io::Read::read_to_end(
        &mut flate2::bufread::MultiGzDecoder::new(bytes.as_ref()),
        &mut inflated,
    )
    .unwrap();
    let mut archive = tar::Archive::new(inflated.as_slice());
    let mut apkindex_text = String::new();
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        if entry.path().unwrap().to_string_lossy() == "APKINDEX" {
            std::io::Read::read_to_string(&mut entry, &mut apkindex_text).unwrap();
        }
    }
    assert!(
        apkindex_text.contains("P:hello"),
        "a pure-mirror repo's index must advertise its upstream's packages: {apkindex_text}"
    );
}

/// npm has no eager index to rebuild (see `silo-pkg`'s `npm` module doc),
/// so a packument request for a name that's never been fetched has to
/// trigger a lazy sync-and-render on the spot rather than 404ing forever.
#[tokio::test]
async fn npm_packument_miss_lazily_syncs_and_renders_from_the_upstream() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("npmlazy");
    let admin = harness.admin_token().await;
    let service = AdminServiceImpl {
        state: harness.state.clone(),
    };

    let mock = MockServer::start().await;
    // The registry-root probe `add-upstream` does for npm.
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "db_name": "registry" })),
        )
        .mount(&mock)
        .await;
    let packument = serde_json::json!({
        "name": "widget",
        "versions": {
            "1.0.0": {
                "name": "widget",
                "version": "1.0.0",
                "dist": {
                    "tarball": format!("{}/widget/-/widget-1.0.0.tgz", mock.uri()),
                    "shasum": "abc123",
                },
            },
        },
    });
    Mock::given(method("GET"))
        .and(path("/widget"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&packument))
        .mount(&mock)
        .await;

    service
        .add_upstream(request(
            AddUpstreamRequest {
                repo: repo.clone(),
                channel: "stable".into(),
                name: "npmjs".into(),
                format: silo_proto::v1::PackageFormat::Npm as i32,
                base_url: mock.uri(),
                cache_mode: UpstreamCacheMode::Cache as i32,
                cache_index_in_memory: false,
                auth: None,
                arches: vec![],
                suite: String::new(),
                components: vec![],
            },
            &admin.secret,
        ))
        .await
        .expect("add_upstream");
    harness.db.set_repo_public(&repo, true).await.unwrap();

    // No wholesale sync populates npm's upstream_packages — the first
    // request for this exact name is what has to trigger it.
    assert!(harness
        .db
        .list_all_upstream_packages(
            harness
                .db
                .get_upstream(&repo, "stable", "npmjs")
                .await
                .unwrap()
                .unwrap()
                .id
        )
        .await
        .unwrap()
        .is_empty());

    let response = get(&harness.state, &format!("/{repo}/stable/npm/widget")).await;
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(doc["versions"]["1.0.0"].is_object(), "{doc}");
    let tarball = doc["versions"]["1.0.0"]["dist"]["tarball"]
        .as_str()
        .unwrap();
    // The packument must point at *our own* tarball URL (so the next hop
    // routes through our pull-through artifact fetch), not the upstream's.
    assert!(
        tarball.contains(&format!("/{repo}/stable/npm/widget/-/")),
        "got: {tarball}"
    );
}

/// Signing rewrites an rpm's bytes (see `repo.rs`'s `index_metadata` doc),
/// so a *synthetic* (never-fetched) entry's checksum — copied from the
/// upstream's own, unsigned index — would go stale the instant a
/// `cache`-mode fetch actually signs and re-publishes the real file. If
/// that entry were merged into the index, a client that fetched it in the
/// window before the first real capture would cache a checksum that no
/// longer matches by the time it downloads the package, and report
/// corruption rather than simply "not yet available". So: with rpm
/// signing configured, an unfetched `cache`-mode upstream rpm must not
/// appear in the rendered repodata at all — only after it has actually
/// been captured once, at which point its checksum is the real, final,
/// signed one and self-consistent for good.
#[tokio::test]
async fn a_cache_mode_signed_rpm_upstream_is_not_advertised_until_actually_fetched() {
    let url = require_db!();
    let harness = Harness::with_config(&url, |c| {
        c.signing.gpg = Some(silo_core::config::GpgConfig {
            key: Some(silo_core::signing::TEST_GPG_SECRET_KEY.to_string()),
            key_path: None,
            passphrase: None,
        });
    })
    .await;
    let repo = unique_repo("rpmsign");
    let admin = harness.admin_token().await;
    let service = AdminServiceImpl {
        state: harness.state.clone(),
    };

    // A real rpm and its real repodata, standing in for the upstream.
    let rpm_bytes = silo_pkg::testutil::build_test_rpm("hello", "1.0", "1", "x86_64");
    let parsed = silo_pkg::rpm::RpmFormat.parse(&rpm_bytes).unwrap();
    let record = silo_pkg::PackageRecord {
        format: PackageFormat::Rpm,
        name: parsed.name.clone(),
        epoch: parsed.epoch,
        version: parsed.version.clone(),
        release: parsed.release.clone(),
        arch: parsed.arch.clone(),
        filename: parsed.filename.clone(),
        storage_key: format!("upstream/Packages/{}", parsed.filename),
        size_bytes: rpm_bytes.len() as i64,
        sha256: "0".repeat(64),
        metadata: parsed.metadata.clone(),
        published_at: 0,
    };
    let ctx = silo_pkg::IndexContext {
        repo: "upstream",
        channel: "stable",
        group: "",
        records: std::slice::from_ref(&record),
        public_base_url: None,
        signer: None,
    };
    let objects = silo_pkg::Format::build_index(&silo_pkg::rpm::RpmFormat, &ctx)
        .await
        .unwrap();
    let repomd = objects.iter().find(|o| o.name == "repomd.xml").unwrap();
    let primary = objects.iter().find(|o| o.name.contains("primary")).unwrap();

    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repodata/repomd.xml"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(repomd.bytes.clone()))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/repodata/{}", primary.name)))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(primary.bytes.clone()))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/Packages/{}", parsed.filename)))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(rpm_bytes.clone()))
        .mount(&mock)
        .await;

    service
        .add_upstream(request(
            AddUpstreamRequest {
                repo: repo.clone(),
                channel: "stable".into(),
                name: "fedora".into(),
                format: silo_proto::v1::PackageFormat::Rpm as i32,
                base_url: mock.uri(),
                cache_mode: UpstreamCacheMode::Cache as i32,
                cache_index_in_memory: false,
                auth: None,
                arches: vec![],
                suite: String::new(),
                components: vec![],
            },
            &admin.secret,
        ))
        .await
        .expect("add_upstream");
    harness.db.set_repo_public(&repo, true).await.unwrap();

    let upstream = harness
        .db
        .get_upstream(&repo, "stable", "fedora")
        .await
        .unwrap()
        .unwrap();
    // The metadata sync itself succeeded...
    assert_eq!(
        harness
            .db
            .list_all_upstream_packages(upstream.id)
            .await
            .unwrap()
            .len(),
        1
    );

    // ...but the rendered repodata must not advertise it yet.
    let primary_before = fetch_primary_xml(&harness.state, &repo).await;
    assert!(
        !primary_before.contains(&format!("<name>{}</name>", parsed.name)),
        "an unfetched signed-rpm upstream package must not appear in the index yet: {primary_before}"
    );

    // Requesting the file directly (as a client resolving a dependency
    // some other way, or an operator pre-warming the cache, would) still
    // works — it triggers the real fetch, sign, and re-publish.
    let key = format!("Packages/{}", parsed.filename);
    let uri = format!("/{repo}/stable/{key}");
    let response = get(&harness.state, &uri).await;
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let cached_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    // The signed, re-published bytes differ from the unsigned upstream
    // ones — that's the whole reason the synthetic checksum was unsafe.
    assert_ne!(cached_bytes.to_vec(), rpm_bytes);

    // And now the index reflects the real, final, self-consistent entry.
    let primary_after = fetch_primary_xml(&harness.state, &repo).await;
    assert!(
        primary_after.contains(&format!("<name>{}</name>", parsed.name)),
        "the package must be advertised once it has actually been captured: {primary_after}"
    );
}

async fn fetch_primary_xml(state: &std::sync::Arc<silo_server::AppState>, repo: &str) -> String {
    let listing = state
        .storage
        .list(&format!("{repo}/stable/repodata"))
        .await
        .unwrap();
    let primary_key = listing
        .iter()
        .find(|k| k.contains("primary"))
        .unwrap_or_else(|| panic!("no primary.xml.gz in {listing:?}"));
    let bytes = state.storage.get(primary_key).await.unwrap().unwrap();
    let mut inflated = Vec::new();
    std::io::Read::read_to_end(
        &mut flate2::bufread::GzDecoder::new(bytes.as_slice()),
        &mut inflated,
    )
    .unwrap();
    String::from_utf8(inflated).unwrap()
}

/// axum's `*path` wildcard on the main npm route never matches a
/// zero-length remainder, so `/repo/channel/npm` and its trailing-slash
/// twin need their own routes (see `get_npm_root`) or `add-upstream`'s
/// npm reachability probe — which hits exactly this path when the
/// upstream is another silo — 404s unconditionally and npm pull-through
/// can never work silo-to-silo.
#[tokio::test]
async fn the_npm_registry_root_answers_with_and_without_a_trailing_slash() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("npmroot");
    harness.db.set_repo_public(&repo, true).await.unwrap();

    for uri in [
        format!("/{repo}/stable/npm"),
        format!("/{repo}/stable/npm/"),
    ] {
        let resp = get(&harness.state, &uri).await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK, "GET {uri}");
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(doc.is_object(), "GET {uri} -> {doc}");
    }

    // A real package name must still 404 as before — the new routes must
    // not have shadowed the existing packument/tarball route.
    let miss = get(
        &harness.state,
        &format!("/{repo}/stable/npm/does-not-exist"),
    )
    .await;
    assert_eq!(miss.status(), axum::http::StatusCode::NOT_FOUND);
}
