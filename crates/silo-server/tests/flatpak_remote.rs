//! A Flatpak remote, end to end through the real router and database:
//! publishing a `.flatpak` bundle, serving the OSTree tree it becomes, and
//! the write side a pushing client uses.
//!
//! The bundle is `flatpak build-bundle` output (see `silo-pkg`'s test
//! fixtures), so the bytes under test are what a real build produces. What
//! `flatpak` itself makes of the result is `ci/e2e/verify-flatpak.sh`'s job.
//!
//! See `tests/common/mod.rs` for how to point these at a database.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{unique_repo, Harness};
use silo_core::config::GpgConfig;
use silo_db::audit::Actor;
use silo_db::tokens::Permission;
use silo_pkg::ostree::archive;
use silo_pkg::ostree::delta::read_bundle;
use silo_pkg::ostree::gvariant::View;
use silo_pkg::ostree::object::ObjType;
use silo_pkg::PackageFormat;
use tower::ServiceExt;

const HELLO: &[u8] = include_bytes!("../../silo-pkg/tests/fixtures/hello.flatpak");
const REF: &str = "app/org.example.Hello/x86_64/stable";
const COMMIT: &str = "6bff8a2710a3eb3d2124d3804230e388836e089e9e4761293f6c0d160e38151e";

fn actor() -> Actor {
    Actor::system()
}

fn signed(config: &mut silo_core::config::Config) {
    config.signing.gpg = Some(GpgConfig {
        key: Some(silo_core::signing::TEST_GPG_SECRET_KEY.to_string()),
        key_path: None,
        passphrase: None,
    });
}

async fn publish_hello(harness: &Harness, repo: &str, channel: &str) {
    silo_core::repo::publish(
        &harness.state.publish,
        repo,
        channel,
        PackageFormat::Flatpak,
        HELLO.to_vec(),
        &actor(),
    )
    .await
    .expect("publish the bundle");
}

async fn send(
    harness: &Harness,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Vec<u8>,
) -> axum::response::Response {
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    silo_server::http::router(harness.state.clone())
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap()
}

async fn get(harness: &Harness, uri: &str, token: Option<&str>) -> axum::response::Response {
    send(harness, "GET", uri, token, Vec::new()).await
}

async fn bytes_of(resp: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

async fn text_of(resp: axum::response::Response) -> String {
    String::from_utf8_lossy(&bytes_of(resp).await).into_owned()
}

async fn make_public(harness: &Harness, repo: &str) {
    harness.db.ensure_repo(repo).await.unwrap();
    harness.db.set_repo_public(repo, true).await.unwrap();
}

fn object_path(ty: ObjType, hex: &str) -> String {
    format!(
        "objects/{}/{}.{}",
        &hex[..2],
        &hex[2..],
        ty.archive_extension()
    )
}

#[tokio::test]
async fn publishing_a_bundle_records_one_ref_and_writes_the_remote() {
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("fp-publish");

    publish_hello(&harness, &repo, "stable").await;

    let rows = harness
        .db
        .list_packages(&repo, "stable", Some(PackageFormat::Flatpak))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name, "app/org.example.Hello");
    assert_eq!(rows[0].arch, "x86_64");
    assert_eq!(rows[0].version, "stable");
    assert_eq!(
        rows[0].storage_key,
        format!("{repo}/stable/ostree/refs/heads/{REF}")
    );

    let storage = &harness.state.storage;
    for key in ["summary", "summary.sig", "config"] {
        assert!(
            storage
                .head(&format!("{repo}/stable/ostree/{key}"))
                .await
                .unwrap(),
            "{key} is written"
        );
    }
    assert_eq!(
        storage
            .get(&format!("{repo}/stable/ostree/refs/heads/{REF}"))
            .await
            .unwrap()
            .unwrap(),
        format!("{COMMIT}\n").into_bytes()
    );
    // The commit's signature sits beside the commit.
    assert!(storage
        .head(&format!(
            "{repo}/stable/ostree/objects/{}/{}.commitmeta",
            &COMMIT[..2],
            &COMMIT[2..]
        ))
        .await
        .unwrap());
}

#[tokio::test]
async fn the_served_summary_lists_the_ref_and_its_commit() {
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("fp-summary");
    publish_hello(&harness, &repo, "stable").await;
    make_public(&harness, &repo).await;

    let resp = get(&harness, &format!("/{repo}/stable/ostree/summary"), None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = bytes_of(resp).await;
    let view = View::new("(a(s(taya{sv}))a{sv})", &body).unwrap();
    let refs = view.child(0).unwrap();
    assert_eq!(refs.len().unwrap(), 1);
    let entry = refs.at(0).unwrap();
    assert_eq!(entry.child(0).unwrap().as_str().unwrap(), REF);
    assert_eq!(
        entry
            .child(1)
            .unwrap()
            .child(1)
            .unwrap()
            .as_byte_array()
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        COMMIT
    );
    assert!(view
        .child(1)
        .unwrap()
        .dict_get("xa.cache")
        .unwrap()
        .is_some());

    // And the ref and config, the other two small files clients read.
    let resp = get(
        &harness,
        &format!("/{repo}/stable/ostree/refs/heads/{REF}"),
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(text_of(resp).await, format!("{COMMIT}\n"));
    let resp = get(&harness, &format!("/{repo}/stable/ostree/config"), None).await;
    assert!(text_of(resp).await.contains("mode=archive-z2"));
}

#[tokio::test]
async fn every_object_of_the_commit_is_served_and_intact() {
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("fp-objects");
    publish_hello(&harness, &repo, "stable").await;
    make_public(&harness, &repo).await;

    let bundle = read_bundle(HELLO).unwrap();
    for object in &bundle.objects {
        let path = object_path(object.ty, &object.checksum.hex());
        let resp = get(&harness, &format!("/{repo}/stable/ostree/{path}"), None).await;
        assert_eq!(resp.status(), StatusCode::OK, "{path}");
        let body = bytes_of(resp).await;
        // What a client downloads checksums to the name it asked for.
        let sum = archive::checksum_of(object.ty, &body, 1 << 20).unwrap();
        assert_eq!(sum, object.checksum, "{path}");
    }

    let commitmeta = object_path(ObjType::Commit, COMMIT).replace(".commit", ".commitmeta");
    let resp = get(
        &harness,
        &format!("/{repo}/stable/ostree/{commitmeta}"),
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let sigs = bytes_of(resp).await;
    let sigs = View::new("a{sv}", &sigs).unwrap();
    let list = sigs.dict_get("ostree.gpgsigs").unwrap().unwrap();
    assert_eq!(list.len().unwrap(), 1);
    assert!(!list.at(0).unwrap().as_byte_array().unwrap().is_empty());
}

#[tokio::test]
async fn only_known_shapes_are_served() {
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("fp-shapes");
    publish_hello(&harness, &repo, "stable").await;
    make_public(&harness, &repo).await;

    for path in [
        "summary.idx",
        "summaries/abc.gz",
        "deltas/aa/bb",
        "refs/heads/not-a-ref",
        "refs/heads/app/x/y",
        "objects/zz/zzzz.filez",
        "objects/6b/ff.commit",
        "tmp/anything",
    ] {
        let resp = get(&harness, &format!("/{repo}/stable/ostree/{path}"), None).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
    }
    for path in ["objects/../../x", "refs/heads/../summary"] {
        let resp = get(&harness, &format!("/{repo}/stable/ostree/{path}"), None).await;
        assert!(
            resp.status() == StatusCode::BAD_REQUEST || resp.status() == StatusCode::NOT_FOUND,
            "{path}: {}",
            resp.status()
        );
    }
}

#[tokio::test]
async fn a_private_remote_is_invisible_without_a_credential() {
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("fp-private");
    publish_hello(&harness, &repo, "stable").await;

    for path in [
        "ostree/summary",
        "silo.flatpakrepo",
        "flatpakref/org.example.Hello.flatpakref",
    ] {
        let resp = get(&harness, &format!("/{repo}/stable/{path}"), None).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
    }

    // With a read token the same request works.
    let reader = harness
        .token(
            "reader",
            Permission::Read,
            silo_db::tokens::Scope::Repos(vec![repo.clone()]),
        )
        .await;
    let resp = get(
        &harness,
        &format!("/{repo}/stable/ostree/summary"),
        Some(&reader.secret),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn the_flatpakrepo_and_flatpakref_point_clients_at_the_remote() {
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("fp-files");
    publish_hello(&harness, &repo, "stable").await;
    make_public(&harness, &repo).await;

    let resp = get(&harness, &format!("/{repo}/stable/silo.flatpakrepo"), None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()["content-type"],
        "application/vnd.flatpak.repo"
    );
    let file = text_of(resp).await;
    assert!(file.starts_with("[Flatpak Repo]"), "{file}");
    assert!(
        file.contains(&format!("Url=https://silo.test/{repo}/stable/ostree\n")),
        "{file}"
    );
    assert!(file.contains("GPGKey="), "{file}");
    assert!(!file.contains("GPGVerify=false"), "{file}");

    let resp = get(
        &harness,
        &format!("/{repo}/stable/flatpakref/org.example.Hello.flatpakref"),
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let file = text_of(resp).await;
    assert!(file.contains("Name=org.example.Hello\n"), "{file}");
    assert!(file.contains("Branch=stable\n"), "{file}");
    assert!(file.contains("IsRuntime=false\n"), "{file}");

    let resp = get(
        &harness,
        &format!("/{repo}/stable/flatpakref/org.example.Nope.flatpakref"),
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let resp = get(
        &harness,
        &format!("/{repo}/stable/flatpakref/org.example.Hello.flatpakref?branch=beta"),
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_flatpakref_points_at_this_remote_for_a_runtime_published_beside_the_app() {
    // flatpak does not look for an app's runtime in the remote its ref file
    // names, only in configured remotes and at `RuntimeRepo`.
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("fp-runtime-repo");
    for bundle in [
        include_bytes!("../../silo-pkg/tests/fixtures/mini-runtime.flatpak").as_slice(),
        include_bytes!("../../silo-pkg/tests/fixtures/mini-app.flatpak").as_slice(),
        HELLO,
    ] {
        silo_core::repo::publish(
            &harness.state.publish,
            &repo,
            "stable",
            PackageFormat::Flatpak,
            bundle.to_vec(),
            &actor(),
        )
        .await
        .expect("publish");
    }
    make_public(&harness, &repo).await;

    // The mini app's runtime is in the channel.
    let resp = get(
        &harness,
        &format!("/{repo}/stable/flatpakref/org.example.MiniApp.flatpakref"),
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let file = text_of(resp).await;
    assert!(
        file.contains(&format!(
            "RuntimeRepo=https://silo.test/{repo}/stable/silo.flatpakrepo\n"
        )),
        "{file}"
    );

    // Hello's runtime (a Freedesktop one) is not, so there is nothing
    // honest to point at.
    let resp = get(
        &harness,
        &format!("/{repo}/stable/flatpakref/org.example.Hello.flatpakref"),
        None,
    )
    .await;
    let file = text_of(resp).await;
    assert!(!file.contains("RuntimeRepo"), "{file}");

    // A runtime's own ref file never has one.
    let resp = get(
        &harness,
        &format!("/{repo}/stable/flatpakref/org.example.Mini.flatpakref"),
        None,
    )
    .await;
    let file = text_of(resp).await;
    assert!(file.contains("IsRuntime=true"), "{file}");
    assert!(!file.contains("RuntimeRepo"), "{file}");
}

#[tokio::test]
async fn publishing_reports_a_signed_remote_the_same_way_on_both_paths() {
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("fp-signed-flag");
    let bundle = silo_core::repo::publish(
        &harness.state.publish,
        &repo,
        "stable",
        PackageFormat::Flatpak,
        HELLO.to_vec(),
        &actor(),
    )
    .await
    .unwrap();
    assert!(bundle.signed, "a bundle publish signs the commit");

    let unsigned = Harness::new(&url).await;
    let repo = unique_repo("fp-unsigned-flag");
    let outcome = silo_core::repo::publish(
        &unsigned.state.publish,
        &repo,
        "stable",
        PackageFormat::Flatpak,
        HELLO.to_vec(),
        &actor(),
    )
    .await
    .unwrap();
    assert!(!outcome.signed);
}

#[tokio::test]
async fn without_a_configured_public_url_the_host_a_client_used_is_the_remote() {
    let url = require_db!();
    let harness = Harness::with_config(&url, |c| {
        signed(c);
        c.public_base_url = None;
    })
    .await;
    let repo = unique_repo("fp-host");
    publish_hello(&harness, &repo, "stable").await;
    make_public(&harness, &repo).await;

    let req = Request::builder()
        .uri(format!("/{repo}/stable/silo.flatpakrepo"))
        .header("host", "silo.internal:8080")
        .body(Body::empty())
        .unwrap();
    let resp = silo_server::http::router(harness.state.clone())
        .oneshot(req)
        .await
        .unwrap();
    let file = text_of(resp).await;
    assert!(
        file.contains(&format!(
            "Url=http://silo.internal:8080/{repo}/stable/ostree\n"
        )),
        "{file}"
    );
}

#[tokio::test]
async fn behind_a_tls_terminating_proxy_the_links_are_https() {
    // With no public URL configured the address comes from the forwarding
    // headers, as it does for npm. A link that said `http://` here would
    // send the client to a port the proxy may not even serve.
    let url = require_db!();
    let harness = Harness::with_config(&url, |c| {
        signed(c);
        c.public_base_url = None;
    })
    .await;
    let repo = unique_repo("fp-proxy");
    for bundle in [
        include_bytes!("../../silo-pkg/tests/fixtures/mini-runtime.flatpak").as_slice(),
        include_bytes!("../../silo-pkg/tests/fixtures/mini-app.flatpak").as_slice(),
    ] {
        silo_core::repo::publish(
            &harness.state.publish,
            &repo,
            "stable",
            PackageFormat::Flatpak,
            bundle.to_vec(),
            &actor(),
        )
        .await
        .expect("publish");
    }
    make_public(&harness, &repo).await;

    let behind_proxy = |uri: String| {
        Request::builder()
            .uri(uri)
            .header("host", "silo:8080")
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-host", "silo.example.com")
            .body(Body::empty())
            .unwrap()
    };
    let router = || silo_server::http::router(harness.state.clone());

    let file = text_of(
        router()
            .oneshot(behind_proxy(format!("/{repo}/stable/silo.flatpakrepo")))
            .await
            .unwrap(),
    )
    .await;
    assert!(
        file.contains(&format!(
            "Url=https://silo.example.com/{repo}/stable/ostree\n"
        )),
        "{file}"
    );

    let file = text_of(
        router()
            .oneshot(behind_proxy(format!(
                "/{repo}/stable/flatpakref/org.example.MiniApp.flatpakref"
            )))
            .await
            .unwrap(),
    )
    .await;
    assert!(
        file.contains(&format!(
            "Url=https://silo.example.com/{repo}/stable/ostree\n"
        )),
        "{file}"
    );
    assert!(
        file.contains(&format!(
            "RuntimeRepo=https://silo.example.com/{repo}/stable/silo.flatpakrepo\n"
        )),
        "{file}"
    );
}

#[tokio::test]
async fn well_formed_paths_to_things_that_do_not_exist_are_404() {
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("fp-absent");
    publish_hello(&harness, &repo, "stable").await;
    make_public(&harness, &repo).await;

    let absent = "ab".to_string() + &"cd".repeat(31);
    for path in [
        format!("objects/ab/{}.filez", &absent[2..]),
        format!("objects/ab/{}.commitmeta", &absent[2..]),
        "refs/heads/app/org.example.Nope/x86_64/stable".to_string(),
    ] {
        let resp = get(&harness, &format!("/{repo}/stable/ostree/{path}"), None).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path}");
    }
    // A channel that was never published to has no summary.
    let resp = get(&harness, &format!("/{repo}/never/ostree/summary"), None).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    // A ref-file URL has to end in `.flatpakref`.
    let resp = get(
        &harness,
        &format!("/{repo}/stable/flatpakref/org.example.Hello"),
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    // Names that fail validation are refused before anything is looked up.
    let resp = get(&harness, "/bad%20repo/stable/ostree/summary", None).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn an_upload_is_refused_on_an_invalid_repo_name() {
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let writer = harness
        .token("w", Permission::Write, silo_db::tokens::Scope::All)
        .await;
    let resp = send(
        &harness,
        "PUT",
        &format!(
            "/bad%20repo/stable/ostree/{}",
            object_path(ObjType::Commit, COMMIT)
        ),
        Some(&writer.secret),
        b"x".to_vec(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let resp = send(
        &harness,
        "POST",
        "/bad%20repo/stable/ostree/refs",
        Some(&writer.secret),
        b"{}".to_vec(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn an_unsigned_server_declares_its_remote_unsigned() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("fp-unsigned");
    publish_hello(&harness, &repo, "stable").await;
    make_public(&harness, &repo).await;

    let storage = &harness.state.storage;
    assert!(storage
        .head(&format!("{repo}/stable/ostree/summary"))
        .await
        .unwrap());
    assert!(!storage
        .head(&format!("{repo}/stable/ostree/summary.sig"))
        .await
        .unwrap());

    let resp = get(&harness, &format!("/{repo}/stable/silo.flatpakrepo"), None).await;
    let file = text_of(resp).await;
    assert!(file.contains("GPGVerify=false"), "{file}");
    assert!(!file.contains("GPGKey"), "{file}");
}

#[tokio::test]
async fn republishing_a_ref_moves_it_and_a_second_ref_joins_the_summary() {
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("fp-two-refs");
    publish_hello(&harness, &repo, "stable").await;
    publish_hello(&harness, &repo, "stable").await;

    let rows = harness
        .db
        .list_packages(&repo, "stable", Some(PackageFormat::Flatpak))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "the same ref replaces its row");

    // The same bundle into another channel is an independent remote.
    publish_hello(&harness, &repo, "beta").await;
    let beta = harness
        .db
        .list_packages(&repo, "beta", Some(PackageFormat::Flatpak))
        .await
        .unwrap();
    assert_eq!(beta.len(), 1);
    assert!(harness
        .state
        .storage
        .head(&format!("{repo}/beta/ostree/summary"))
        .await
        .unwrap());
}

#[tokio::test]
async fn deleting_a_ref_removes_it_from_the_summary_but_keeps_the_objects() {
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("fp-delete");
    publish_hello(&harness, &repo, "stable").await;

    let rows = harness
        .db
        .list_packages(&repo, "stable", Some(PackageFormat::Flatpak))
        .await
        .unwrap();
    silo_core::repo::delete_package(&harness.state.publish, rows[0].id, &actor(), None)
        .await
        .unwrap()
        .expect("the row existed");

    let summary = harness
        .state
        .storage
        .get(&format!("{repo}/stable/ostree/summary"))
        .await
        .unwrap()
        .unwrap();
    let view = View::new("(a(s(taya{sv}))a{sv})", &summary).unwrap();
    assert_eq!(view.child(0).unwrap().len().unwrap(), 0);
    assert!(
        !harness
            .state
            .storage
            .head(&format!("{repo}/stable/ostree/refs/heads/{REF}"))
            .await
            .unwrap(),
        "the ref file goes with the row"
    );
    // Objects are shared between commits and outlive any one ref.
    assert!(harness
        .state
        .storage
        .head(&format!(
            "{repo}/stable/ostree/{}",
            object_path(ObjType::Commit, COMMIT)
        ))
        .await
        .unwrap());
}

#[tokio::test]
async fn a_publish_is_audited_as_a_flatpak_publish() {
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("fp-audit");
    publish_hello(&harness, &repo, "stable").await;

    let rows = harness
        .db
        .query_audit(&silo_db::audit::AuditQuery {
            repo: Some(repo.clone()),
            limit: 10,
            ..Default::default()
        })
        .await
        .expect("read the audit log");
    let publish = rows
        .iter()
        .find(|r| r.action == "package.publish")
        .expect("the publish was audited");
    assert_eq!(publish.target.as_deref(), Some(REF));
    assert_eq!(publish.detail["format"], "flatpak");
}

#[tokio::test]
async fn a_bundle_that_is_not_a_bundle_is_rejected_and_leaves_nothing() {
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("fp-bad-bundle");

    let err = silo_core::repo::publish(
        &harness.state.publish,
        &repo,
        "stable",
        PackageFormat::Flatpak,
        b"definitely not a flatpak".to_vec(),
        &actor(),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().starts_with("invalid flatpak"), "{err}");

    let rows = harness
        .db
        .list_packages(&repo, "stable", Some(PackageFormat::Flatpak))
        .await
        .unwrap();
    assert!(rows.is_empty());
}

// ------------------------------------------------------- pushing objects

/// The objects of the bundle in the form a pushing client has on disk.
fn local_objects() -> Vec<(ObjType, String, Vec<u8>)> {
    read_bundle(HELLO)
        .unwrap()
        .objects
        .iter()
        .map(|o| (o.ty, o.checksum.hex(), archive::encode(o).unwrap()))
        .collect()
}

async fn put_object(
    harness: &Harness,
    repo: &str,
    token: &str,
    ty: ObjType,
    hex: &str,
    body: Vec<u8>,
) -> axum::response::Response {
    send(
        harness,
        "PUT",
        &format!("/{repo}/stable/ostree/{}", object_path(ty, hex)),
        Some(token),
        body,
    )
    .await
}

async fn move_ref(
    harness: &Harness,
    repo: &str,
    token: &str,
    reference: &str,
    commit: &str,
) -> axum::response::Response {
    send(
        harness,
        "POST",
        &format!("/{repo}/stable/ostree/refs"),
        Some(token),
        serde_json::json!({ "ref": reference, "commit": commit })
            .to_string()
            .into_bytes(),
    )
    .await
}

#[tokio::test]
async fn pushed_objects_and_a_ref_update_publish_the_same_remote_a_bundle_does() {
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("fp-push");
    let writer = harness.publisher_token(&repo).await;
    make_public(&harness, &repo).await;

    // Nothing is on the server, so everything is missing.
    let objects = local_objects();
    let wanted: Vec<String> = objects
        .iter()
        .map(|(ty, hex, _)| object_path(*ty, hex))
        .collect();
    let resp = send(
        &harness,
        "POST",
        &format!("/{repo}/stable/ostree/missing"),
        Some(&writer.secret),
        serde_json::json!({ "objects": wanted })
            .to_string()
            .into_bytes(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let missing: serde_json::Value = serde_json::from_slice(&bytes_of(resp).await).unwrap();
    assert_eq!(missing["missing"].as_array().unwrap().len(), objects.len());

    for (ty, hex, bytes) in &objects {
        let resp = put_object(&harness, &repo, &writer.secret, *ty, hex, bytes.clone()).await;
        assert_eq!(resp.status(), StatusCode::CREATED, "{hex}");
    }

    // Uploading one again is a no-op, not an error.
    let (ty, hex, bytes) = &objects[0];
    let resp = put_object(&harness, &repo, &writer.secret, *ty, hex, bytes.clone()).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Now nothing is missing.
    let resp = send(
        &harness,
        "POST",
        &format!("/{repo}/stable/ostree/missing"),
        Some(&writer.secret),
        serde_json::json!({ "objects": wanted })
            .to_string()
            .into_bytes(),
    )
    .await;
    let missing: serde_json::Value = serde_json::from_slice(&bytes_of(resp).await).unwrap();
    assert!(missing["missing"].as_array().unwrap().is_empty());

    // Not visible until the ref moves.
    let resp = get(&harness, &format!("/{repo}/stable/ostree/summary"), None).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let resp = move_ref(&harness, &repo, &writer.secret, REF, COMMIT).await;
    let status = resp.status();
    let text = text_of(resp).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert!(text.contains("\"signed\":true"), "{text}");

    let resp = get(&harness, &format!("/{repo}/stable/ostree/summary"), None).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let rows = harness
        .db
        .list_packages(&repo, "stable", Some(PackageFormat::Flatpak))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name, "app/org.example.Hello");

    // The commit was signed on the way through, as for a bundle.
    assert!(harness
        .state
        .storage
        .head(&format!(
            "{repo}/stable/ostree/objects/{}/{}.commitmeta",
            &COMMIT[..2],
            &COMMIT[2..]
        ))
        .await
        .unwrap());
}

#[tokio::test]
async fn a_ref_cannot_move_until_every_object_under_its_commit_is_present() {
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("fp-incomplete");
    let writer = harness.publisher_token(&repo).await;

    let objects = local_objects();
    // Everything but one file.
    let withheld = objects
        .iter()
        .position(|(ty, _, _)| *ty == ObjType::File)
        .unwrap();
    for (i, (ty, hex, bytes)) in objects.iter().enumerate() {
        if i != withheld {
            let resp = put_object(&harness, &repo, &writer.secret, *ty, hex, bytes.clone()).await;
            assert_eq!(resp.status(), StatusCode::CREATED);
        }
    }

    let resp = move_ref(&harness, &repo, &writer.secret, REF, COMMIT).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(text_of(resp).await.contains("has not been uploaded"));

    let rows = harness
        .db
        .list_packages(&repo, "stable", Some(PackageFormat::Flatpak))
        .await
        .unwrap();
    assert!(rows.is_empty(), "no half-published ref");

    // Supplying the missing object lets the same request through.
    let (ty, hex, bytes) = &objects[withheld];
    put_object(&harness, &repo, &writer.secret, *ty, hex, bytes.clone()).await;
    let resp = move_ref(&harness, &repo, &writer.secret, REF, COMMIT).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn an_object_is_refused_under_a_name_that_is_not_its_checksum() {
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("fp-wrong-name");
    let writer = harness.publisher_token(&repo).await;

    let objects = local_objects();
    let files: Vec<_> = objects
        .iter()
        .filter(|(t, _, _)| *t == ObjType::File)
        .collect();
    // A real file's bytes under another real file's name.
    let resp = put_object(
        &harness,
        &repo,
        &writer.secret,
        ObjType::File,
        &files[0].1,
        files[1].2.clone(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // A metadata object whose bytes are altered.
    let tree = objects
        .iter()
        .find(|(t, _, _)| *t == ObjType::DirTree)
        .unwrap();
    let mut tampered = tree.2.clone();
    *tampered.last_mut().unwrap() ^= 0xff;
    let resp = put_object(
        &harness,
        &repo,
        &writer.secret,
        ObjType::DirTree,
        &tree.1,
        tampered,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Nothing was stored.
    assert!(!harness
        .state
        .storage
        .head(&format!(
            "{repo}/stable/ostree/{}",
            object_path(ObjType::File, &files[0].1)
        ))
        .await
        .unwrap());
}

#[tokio::test]
async fn a_push_needs_a_write_credential() {
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("fp-auth");
    let reader = harness
        .token(
            "reader",
            Permission::Read,
            silo_db::tokens::Scope::Repos(vec![repo.clone()]),
        )
        .await;
    let other_writer = harness.publisher_token("some-other-repo").await;
    let objects = local_objects();
    let (ty, hex, bytes) = &objects[0];

    let resp = put_object(&harness, &repo, &reader.secret, *ty, hex, bytes.clone()).await;
    assert!(
        resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::NOT_FOUND,
        "a read token cannot upload: {}",
        resp.status()
    );
    let resp = put_object(
        &harness,
        &repo,
        &other_writer.secret,
        *ty,
        hex,
        bytes.clone(),
    )
    .await;
    assert!(
        resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::NOT_FOUND,
        "a token for another repo cannot upload: {}",
        resp.status()
    );
    // No credential is an anonymous caller, who can read a public repo
    // and write nothing; a credential that does not verify is refused
    // outright.
    let uri = format!("/{repo}/stable/ostree/{}", object_path(*ty, hex));
    let resp = send(&harness, "PUT", &uri, None, bytes.clone()).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let resp = send(
        &harness,
        "PUT",
        &uri,
        Some("not-a-real-token"),
        bytes.clone(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = move_ref(&harness, &repo, &reader.secret, REF, COMMIT).await;
    assert!(resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn malformed_push_requests_are_the_clients_error() {
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("fp-malformed");
    let writer = harness.publisher_token(&repo).await;

    // A path that is not an object, and one that names `commitmeta`,
    // which only the server writes.
    let resp = send(
        &harness,
        "PUT",
        &format!("/{repo}/stable/ostree/summary"),
        Some(&writer.secret),
        b"x".to_vec(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let meta = object_path(ObjType::Commit, COMMIT).replace(".commit", ".commitmeta");
    let resp = send(
        &harness,
        "PUT",
        &format!("/{repo}/stable/ostree/{meta}"),
        Some(&writer.secret),
        b"x".to_vec(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    for body in [
        &b"not json"[..],
        br#"{"ref": "app/x/y/z"}"#,
        br#"{"ref": "bogus", "commit": "00"}"#,
    ] {
        let resp = send(
            &harness,
            "POST",
            &format!("/{repo}/stable/ostree/refs"),
            Some(&writer.secret),
            body.to_vec(),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "{:?}",
            String::from_utf8_lossy(body)
        );
    }

    // A well-formed request for a commit that was never uploaded.
    let resp = move_ref(&harness, &repo, &writer.secret, REF, COMMIT).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // A listing with a bad name, and an unknown POST target.
    let resp = send(
        &harness,
        "POST",
        &format!("/{repo}/stable/ostree/missing"),
        Some(&writer.secret),
        br#"{"objects": ["objects/../x"]}"#.to_vec(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let resp = send(
        &harness,
        "POST",
        &format!("/{repo}/stable/ostree/elsewhere"),
        Some(&writer.secret),
        Vec::new(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_commit_bound_to_another_ref_cannot_be_published_under_this_one() {
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("fp-binding");
    let writer = harness.publisher_token(&repo).await;
    for (ty, hex, bytes) in local_objects() {
        put_object(&harness, &repo, &writer.secret, ty, &hex, bytes).await;
    }

    // The commit says it is `app/org.example.Hello/...`; presenting it as
    // another app would let one signed commit impersonate another.
    let resp = move_ref(
        &harness,
        &repo,
        &writer.secret,
        "app/org.example.Other/x86_64/stable",
        COMMIT,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(text_of(resp).await.contains("bound to other refs"));
}

#[tokio::test]
async fn bundles_cannot_be_used_as_a_pull_through_upstream() {
    // A flatpak channel has no upstream rows, so asking the sync job to
    // rebuild one is a no-op rather than an error.
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("fp-upstream");
    silo_core::repo::rebuild_index_for_upstream(
        &harness.state.publish,
        &repo,
        "stable",
        PackageFormat::Flatpak,
        &[],
        &actor(),
    )
    .await
    .unwrap();
}
