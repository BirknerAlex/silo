//! Collecting the objects of a Flatpak remote that no ref reaches.
//!
//! Objects are shared between commits and outlive the refs that named them,
//! so the sweep has to remove exactly what nothing reaches: not an object a
//! live ref needs (including one two refs share), not one a publish may still
//! be about to point a ref at, and nothing at all if it cannot tell what is
//! reachable. Everything runs against a real database and the real router.
//!
//! In-memory storage stamps every object with the moment it was written, so
//! the tests that need an object old enough to remove pass a zero grace
//! period, and the ones about the grace period itself pass a real one.
//!
//! See `tests/common/mod.rs` for how to point these at a database.

mod common;

use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{unique_repo, Harness};
use silo_core::config::GpgConfig;
use silo_core::ostree::{gc_all, gc_channel, sweep_if_unchanged, GcReport, GC_GRACE};
use silo_db::audit::{Actor, AuditQuery};
use silo_pkg::ostree::delta::read_bundle;
use silo_pkg::ostree::object::ObjType;
use silo_pkg::PackageFormat;
use tower::ServiceExt;

const HELLO: &[u8] = include_bytes!("../../silo-pkg/tests/fixtures/hello.flatpak");
const RUNTIME: &[u8] = include_bytes!("../../silo-pkg/tests/fixtures/mini-runtime.flatpak");
const APP: &[u8] = include_bytes!("../../silo-pkg/tests/fixtures/mini-app.flatpak");
/// The same ref as `HELLO`, built again with different content: an update.
const HELLO_V2: &[u8] = include_bytes!("../../silo-pkg/tests/fixtures/hello-v2.flatpak");

fn signed(config: &mut silo_core::config::Config) {
    config.signing.gpg = Some(GpgConfig {
        key: Some(silo_core::signing::TEST_GPG_SECRET_KEY.to_string()),
        key_path: None,
        passphrase: None,
    });
}

async fn publish(harness: &Harness, repo: &str, channel: &str, bundle: &[u8]) {
    silo_core::repo::publish(
        &harness.state.publish,
        repo,
        channel,
        PackageFormat::Flatpak,
        bundle.to_vec(),
        &Actor::system(),
    )
    .await
    .expect("publish");
}

/// Removes a ref the way `silo delete` does.
async fn remove_ref(harness: &Harness, repo: &str, channel: &str, name: &str) {
    let rows = harness
        .db
        .list_packages(repo, channel, Some(PackageFormat::Flatpak))
        .await
        .unwrap();
    let row = rows
        .iter()
        .find(|r| r.name == name)
        .unwrap_or_else(|| panic!("{name} is not published"));
    silo_core::repo::delete_package(&harness.state.publish, row.id, &Actor::system(), None)
        .await
        .unwrap()
        .expect("the row existed");
}

/// The storage keys of every object in a bundle, plus its commit's
/// signature file.
fn keys_of(repo: &str, channel: &str, bundle: &[u8]) -> Vec<String> {
    let bundle = read_bundle(bundle).unwrap();
    let mut keys: Vec<String> = bundle
        .objects
        .iter()
        .map(|o| silo_pkg::flatpak::object_key(repo, channel, o.ty, &o.checksum))
        .collect();
    keys.push(silo_pkg::flatpak::commitmeta_key(
        repo,
        channel,
        &bundle.commit_checksum,
    ));
    keys
}

async fn present(harness: &Harness, key: &str) -> bool {
    harness.state.storage.head(key).await.unwrap()
}

async fn all_present(harness: &Harness, keys: &[String]) -> bool {
    for key in keys {
        if !present(harness, key).await {
            return false;
        }
    }
    true
}

async fn get(harness: &Harness, uri: &str) -> StatusCode {
    silo_server::http::router(harness.state.clone())
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

async fn sweep(harness: &Harness, repo: &str, channel: &str, grace: Duration) -> GcReport {
    gc_channel(&harness.state.publish, repo, channel, grace, false)
        .await
        .expect("sweep")
}

#[tokio::test]
async fn objects_no_ref_reaches_are_removed_and_what_refs_share_is_kept() {
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("gc-shared");
    harness.db.ensure_repo(&repo).await.unwrap();
    harness.db.set_repo_public(&repo, true).await.unwrap();

    publish(&harness, &repo, "stable", RUNTIME).await;
    publish(&harness, &repo, "stable", APP).await;
    publish(&harness, &repo, "stable", HELLO).await;

    let runtime_keys = keys_of(&repo, "stable", RUNTIME);
    let app_keys = keys_of(&repo, "stable", APP);
    let hello_keys = keys_of(&repo, "stable", HELLO);

    // The premise of the test: the apps have objects in common (the
    // directory metadata of an empty root-owned directory), so removing one
    // ref must not take what the others still need.
    let runtime_set: HashSet<_> = runtime_keys.iter().collect();
    let shared: Vec<&String> = hello_keys
        .iter()
        .filter(|k| runtime_set.contains(k))
        .collect();
    assert!(!shared.is_empty(), "the fixtures share no object");

    // Nothing is unreachable yet.
    let report = sweep(&harness, &repo, "stable", Duration::ZERO).await;
    assert_eq!(report.deleted, 0, "{report:?}");
    assert!(report.backed_off.is_none());

    remove_ref(&harness, &repo, "stable", "app/org.example.Hello").await;
    let report = sweep(&harness, &repo, "stable", Duration::ZERO).await;
    assert!(report.deleted > 0, "{report:?}");
    assert!(report.deleted_bytes > 0);
    assert_eq!(report.deferred, 0);
    assert!(report.backed_off.is_none(), "{report:?}");

    // What only the removed app had is gone, including its signature file…
    let hello_only: Vec<&String> = hello_keys
        .iter()
        .filter(|k| !runtime_keys.contains(k) && !app_keys.contains(k))
        .collect();
    assert!(!hello_only.is_empty());
    for key in &hello_only {
        assert!(!present(&harness, key).await, "{key} survived");
    }
    // …and everything the remaining refs reach, shared objects included, is
    // still there and still served.
    assert!(all_present(&harness, &runtime_keys).await);
    assert!(all_present(&harness, &app_keys).await);
    for key in shared {
        assert!(present(&harness, key).await, "shared {key} was removed");
    }
    for object in read_bundle(APP).unwrap().objects {
        let path = object.ty.archive_path(&object.checksum);
        assert_eq!(
            get(&harness, &format!("/{repo}/stable/ostree/{path}")).await,
            StatusCode::OK,
            "{path}"
        );
    }

    // A second sweep finds nothing left to do.
    let again = sweep(&harness, &repo, "stable", Duration::ZERO).await;
    assert_eq!(again.deleted, 0, "{again:?}");
}

#[tokio::test]
async fn an_object_younger_than_the_grace_period_is_not_removed() {
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("gc-grace");
    publish(&harness, &repo, "stable", APP).await;
    remove_ref(&harness, &repo, "stable", "app/org.example.MiniApp").await;

    let keys = keys_of(&repo, "stable", APP);
    let report = sweep(&harness, &repo, "stable", GC_GRACE).await;
    assert_eq!(report.deleted, 0, "{report:?}");
    assert!(report.too_new > 0, "{report:?}");
    assert!(
        all_present(&harness, &keys).await,
        "a recent object was removed"
    );
}

#[tokio::test]
async fn a_dry_run_reports_what_it_would_remove_and_removes_nothing() {
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("gc-dry");
    publish(&harness, &repo, "stable", APP).await;
    remove_ref(&harness, &repo, "stable", "app/org.example.MiniApp").await;

    let keys = keys_of(&repo, "stable", APP);
    let report = gc_channel(
        &harness.state.publish,
        &repo,
        "stable",
        Duration::ZERO,
        true,
    )
    .await
    .unwrap();
    assert!(report.dry_run);
    assert!(report.deleted > 0, "{report:?}");
    assert!(
        all_present(&harness, &keys).await,
        "a dry run deleted something"
    );

    // The same sweep, for real, removes what the dry run promised.
    let real = sweep(&harness, &repo, "stable", Duration::ZERO).await;
    assert_eq!(real.deleted, report.deleted);
    assert_eq!(real.deleted_bytes, report.deleted_bytes);
}

#[tokio::test]
async fn updating_an_app_leaves_the_old_versions_objects_to_be_collected() {
    // Publishing a ref again moves it. The commit it left stays in storage
    // until a sweep finds nothing reaches it; what the two versions share
    // has to stay.
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("gc-update");
    harness.db.ensure_repo(&repo).await.unwrap();
    harness.db.set_repo_public(&repo, true).await.unwrap();
    publish(&harness, &repo, "stable", HELLO).await;
    let v1_keys = keys_of(&repo, "stable", HELLO);

    publish(&harness, &repo, "stable", HELLO_V2).await;
    let v2_keys = keys_of(&repo, "stable", HELLO_V2);
    let v1: HashSet<&String> = v1_keys.iter().collect();
    let v2: HashSet<&String> = v2_keys.iter().collect();
    assert_ne!(
        read_bundle(HELLO).unwrap().commit_checksum,
        read_bundle(HELLO_V2).unwrap().commit_checksum
    );
    // Both versions are still in storage after the update: nothing has
    // been collected yet.
    assert!(all_present(&harness, &v1_keys).await);
    assert!(all_present(&harness, &v2_keys).await);

    let report = sweep(&harness, &repo, "stable", Duration::ZERO).await;
    assert!(report.deleted > 0, "{report:?}");
    assert!(report.backed_off.is_none(), "{report:?}");

    // The old version's own objects (its commit, its script) are gone…
    let only_v1: Vec<&&String> = v1.difference(&v2).collect();
    assert!(!only_v1.is_empty());
    for key in &only_v1 {
        assert!(!present(&harness, key).await, "{key} survived");
    }
    // …everything the current version reaches, shared objects included,
    // remains, and is served.
    assert!(all_present(&harness, &v2_keys).await);
    for object in read_bundle(HELLO_V2).unwrap().objects {
        let path = object.ty.archive_path(&object.checksum);
        assert_eq!(
            get(&harness, &format!("/{repo}/stable/ostree/{path}")).await,
            StatusCode::OK,
            "{path}"
        );
    }
}

#[tokio::test]
async fn the_sweep_backs_off_when_a_live_refs_commit_is_missing() {
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("gc-missing-commit");
    publish(&harness, &repo, "stable", HELLO).await;
    publish(&harness, &repo, "stable", APP).await;
    remove_ref(&harness, &repo, "stable", "app/org.example.MiniApp").await;

    // The commit a live ref points at has gone from storage, so what is
    // reachable cannot be known — and the dead app's objects, which a
    // working sweep would remove, must be left alone.
    let hello = read_bundle(HELLO).unwrap();
    harness
        .state
        .storage
        .delete(&silo_pkg::flatpak::object_key(
            &repo,
            "stable",
            ObjType::Commit,
            &hello.commit_checksum,
        ))
        .await
        .unwrap();

    let app_keys = keys_of(&repo, "stable", APP);
    let report = sweep(&harness, &repo, "stable", Duration::ZERO).await;
    assert_eq!(report.deleted, 0, "{report:?}");
    assert!(
        report
            .backed_off
            .as_deref()
            .unwrap_or("")
            .contains("missing"),
        "{report:?}"
    );
    assert!(
        all_present(&harness, &app_keys).await,
        "it deleted despite not knowing"
    );
}

#[tokio::test]
async fn the_sweep_backs_off_when_a_tree_is_incomplete() {
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("gc-incomplete");
    publish(&harness, &repo, "stable", HELLO).await;
    publish(&harness, &repo, "stable", APP).await;
    remove_ref(&harness, &repo, "stable", "app/org.example.MiniApp").await;

    // A file the live app needs is gone.
    let hello = read_bundle(HELLO).unwrap();
    let file = hello
        .objects
        .iter()
        .find(|o| o.ty == ObjType::File)
        .unwrap();
    harness
        .state
        .storage
        .delete(&silo_pkg::flatpak::object_key(
            &repo,
            "stable",
            file.ty,
            &file.checksum,
        ))
        .await
        .unwrap();

    let app_keys = keys_of(&repo, "stable", APP);
    let report = sweep(&harness, &repo, "stable", Duration::ZERO).await;
    assert_eq!(report.deleted, 0, "{report:?}");
    assert!(report.backed_off.is_some(), "{report:?}");
    assert!(all_present(&harness, &app_keys).await);
}

#[tokio::test]
async fn deletes_are_withheld_if_the_refs_changed_since_they_were_marked() {
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("gc-moved-refs");
    publish(&harness, &repo, "stable", APP).await;
    let keys = keys_of(&repo, "stable", APP);

    // What the marking saw no longer matches the channel: a ref was
    // published after it. The candidates may now be reachable.
    let stale: BTreeMap<String, String> = BTreeMap::new();
    let doomed: Vec<(String, u64)> = keys.iter().map(|k| (k.clone(), 1)).collect();
    let mut report = GcReport {
        deleted: doomed.len(),
        deleted_bytes: 99,
        ..GcReport::default()
    };
    sweep_if_unchanged(
        &harness.state.publish,
        &repo,
        "stable",
        &stale,
        doomed,
        &mut report,
    )
    .await
    .unwrap();

    assert_eq!(report.deleted, 0);
    assert_eq!(report.deleted_bytes, 0);
    assert!(
        report
            .backed_off
            .as_deref()
            .unwrap_or("")
            .contains("changed"),
        "{report:?}"
    );
    assert!(
        all_present(&harness, &keys).await,
        "it deleted despite the change"
    );

    // With refs that match, the same call goes ahead.
    let rows = harness
        .db
        .list_packages(&repo, "stable", Some(PackageFormat::Flatpak))
        .await
        .unwrap();
    let current = silo_core::ostree::live_refs(&rows);
    assert_eq!(current.len(), 1);
    let victim = keys[0].clone();
    let mut report = GcReport::default();
    sweep_if_unchanged(
        &harness.state.publish,
        &repo,
        "stable",
        &current,
        vec![(victim.clone(), 1)],
        &mut report,
    )
    .await
    .unwrap();
    assert!(report.backed_off.is_none());
    assert!(!present(&harness, &victim).await);
}

#[tokio::test]
async fn publishing_again_restores_an_object_a_sweep_removed() {
    // A publish that finds an object already stored does not upload it. If
    // a sweep removed it in between, the publish has to put it back before
    // its ref becomes visible.
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("gc-restore");
    publish(&harness, &repo, "stable", HELLO).await;

    let hello = read_bundle(HELLO).unwrap();
    let file = hello
        .objects
        .iter()
        .find(|o| o.ty == ObjType::File)
        .unwrap();
    let key = silo_pkg::flatpak::object_key(&repo, "stable", file.ty, &file.checksum);
    harness.state.storage.delete(&key).await.unwrap();
    assert!(!present(&harness, &key).await);

    publish(&harness, &repo, "stable", HELLO).await;
    assert!(present(&harness, &key).await, "the object was not restored");
    assert!(all_present(&harness, &keys_of(&repo, "stable", HELLO)).await);
}

#[tokio::test]
async fn a_channel_whose_last_ref_was_removed_is_still_collected() {
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("gc-emptied");
    publish(&harness, &repo, "stable", HELLO).await;
    let keys = keys_of(&repo, "stable", HELLO);
    remove_ref(&harness, &repo, "stable", "app/org.example.Hello").await;

    let reports = gc_all(&harness.state.publish, Duration::ZERO, false)
        .await
        .unwrap();
    let report = reports
        .iter()
        .find(|r| r.repo == repo && r.channel == "stable")
        .expect("the emptied channel is swept");
    assert!(report.deleted > 0, "{report:?}");
    for key in &keys {
        // The index files the channel keeps are not objects and stay; every
        // object is gone.
        if key.contains("/objects/") {
            assert!(!present(&harness, key).await, "{key} survived");
        }
    }
}

#[tokio::test]
async fn objects_under_a_repo_the_database_has_never_heard_of_are_left_alone() {
    // A fresh database pointed at an old bucket knows nothing of what is in
    // it; sweeping on that basis would delete everything.
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let ghost = unique_repo("gc-ghost");
    let hex = "ab".to_string() + &"cd".repeat(31);
    let key = format!("{ghost}/stable/ostree/objects/ab/{}.filez", &hex[2..]);
    harness
        .state
        .storage
        .put(&key, b"orphan".to_vec())
        .await
        .unwrap();

    let reports = gc_all(&harness.state.publish, Duration::ZERO, false)
        .await
        .unwrap();
    assert!(reports.iter().all(|r| r.repo != ghost), "{reports:?}");
    assert!(present(&harness, &key).await);
}

#[tokio::test]
async fn files_the_server_would_not_serve_are_never_removed() {
    // Only an object's own filenames are the sweep's to delete; anything
    // else under the objects directory is somebody's, not garbage.
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("gc-foreign");
    publish(&harness, &repo, "stable", APP).await;
    remove_ref(&harness, &repo, "stable", "app/org.example.MiniApp").await;

    let stray = format!("{repo}/stable/ostree/objects/README.txt");
    harness
        .state
        .storage
        .put(&stray, b"keep me".to_vec())
        .await
        .unwrap();
    sweep(&harness, &repo, "stable", Duration::ZERO).await;
    assert!(present(&harness, &stray).await);
}

#[tokio::test]
async fn a_large_backlog_is_cleared_in_bounded_runs() {
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    let repo = unique_repo("gc-backlog");
    publish(&harness, &repo, "stable", APP).await;
    remove_ref(&harness, &repo, "stable", "app/org.example.MiniApp").await;

    // Pile up more garbage than one run will take.
    let extra = silo_core::ostree::GC_MAX_DELETES + 25;
    for i in 0..extra {
        let hex = format!("{:064x}", i + 1);
        let key = format!(
            "{repo}/stable/ostree/objects/{}/{}.filez",
            &hex[..2],
            &hex[2..]
        );
        harness.state.storage.put(&key, vec![0]).await.unwrap();
    }

    let first = sweep(&harness, &repo, "stable", Duration::ZERO).await;
    assert_eq!(first.deleted, silo_core::ostree::GC_MAX_DELETES);
    assert!(first.deferred > 0, "{first:?}");

    let second = sweep(&harness, &repo, "stable", Duration::ZERO).await;
    assert_eq!(second.deferred, 0, "{second:?}");
    assert_eq!(
        first.deleted + second.deleted,
        extra + keys_of(&repo, "stable", APP).len()
    );
}

/// A harness whose scheduled sweep takes objects of any age, since
/// in-memory objects are only ever as old as the test.
async fn harness_sweeping_immediately(url: &str) -> Harness {
    Harness::with_config(url, |c| {
        signed(c);
        c.jobs.flatpak_gc_min_age_hours = 0;
    })
    .await
}

#[tokio::test]
async fn the_scheduled_job_sweeps_and_records_what_it_did() {
    let url = require_db!();
    let harness = harness_sweeping_immediately(&url).await;
    let repo = unique_repo("gc-job");
    publish(&harness, &repo, "stable", APP).await;
    remove_ref(&harness, &repo, "stable", "app/org.example.MiniApp").await;
    let before = harness.state.metrics.flatpak_gc_objects.get();

    silo_server::maintenance::run_flatpak_gc(&harness.state).await;

    let removed = harness.state.metrics.flatpak_gc_objects.get() - before;
    assert!(removed > 0, "the metric did not move");
    let entries = harness
        .db
        .query_audit(&AuditQuery {
            repo: Some(repo.clone()),
            action: Some("object.gc".into()),
            limit: 10,
            ..Default::default()
        })
        .await
        .unwrap();
    let entry = entries.first().expect("the sweep was audited");
    assert!(entry.success);
    assert_eq!(entry.actor_kind, "system");
    assert_eq!(entry.detail["format"], "flatpak");
    assert_eq!(entry.detail["deleted"].as_u64().unwrap(), removed);
    assert!(entry.detail["bytes"].as_u64().unwrap() > 0);

    // Nothing left to do means nothing is recorded.
    let before = harness.state.metrics.flatpak_gc_objects.get();
    silo_server::maintenance::run_flatpak_gc(&harness.state).await;
    assert_eq!(harness.state.metrics.flatpak_gc_objects.get(), before);
}

#[tokio::test]
async fn the_scheduled_job_honours_the_configured_minimum_age() {
    // The default is a day, and nothing in storage here is anywhere near
    // that old: the job runs and removes nothing.
    let url = require_db!();
    let harness = Harness::with_config(&url, signed).await;
    assert_eq!(harness.state.config.jobs.flatpak_gc_min_age_hours, 24);
    let repo = unique_repo("gc-job-default");
    publish(&harness, &repo, "stable", APP).await;
    remove_ref(&harness, &repo, "stable", "app/org.example.MiniApp").await;
    let keys = keys_of(&repo, "stable", APP);

    silo_server::maintenance::run_flatpak_gc(&harness.state).await;
    assert!(
        all_present(&harness, &keys).await,
        "a fresh object was swept"
    );
}
