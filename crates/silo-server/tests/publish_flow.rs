//! End-to-end publish tests for every format, plus the concurrency
//! behaviour the distributed lock exists to provide.
//!
//! See `tests/common/mod.rs` for how to point these at a database.

mod common;

use std::io::Read;

use common::{unique_repo, Harness};
use silo_db::audit::{Actor, ActorKind, AuditQuery};
use silo_db::tokens::{Permission, Scope};
use silo_pkg::testutil::{
    build_test_apk, build_test_deb, build_test_npm, build_test_pacman, build_test_rpm,
};
use silo_pkg::PackageFormat;

/// Reads one architecture's APKINDEX back out of storage as text.
async fn apkindex(harness: &Harness, repo: &str, channel: &str, arch: &str) -> String {
    let bytes = harness
        .state
        .storage
        .get(&format!("{repo}/{channel}/apk/{arch}/APKINDEX.tar.gz"))
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("no APKINDEX for {arch}"));
    let mut inflated = Vec::new();
    flate2::bufread::MultiGzDecoder::new(bytes.as_slice())
        .read_to_end(&mut inflated)
        .unwrap();
    String::from_utf8_lossy(&inflated).into_owned()
}

fn actor() -> Actor {
    Actor {
        kind: ActorKind::Token,
        name: "test-publisher".into(),
        token_id: None,
        user_id: None,
        remote_addr: Some("10.0.0.1".into()),
    }
}

#[tokio::test]
async fn apk_publish_records_the_package_and_builds_an_index() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("apk");

    let outcome = silo_core::repo::publish(
        &harness.state.publish,
        &repo,
        "edge",
        PackageFormat::Apk,
        build_test_apk("hello", "1.0-r0", "x86_64"),
        &actor(),
    )
    .await
    .expect("publish apk");

    assert_eq!(
        outcome.storage_path,
        format!("{repo}/edge/apk/x86_64/hello-1.0-r0.apk")
    );
    assert_eq!(outcome.index_group, "x86_64");
    assert_eq!(outcome.sha256.len(), 64);
    assert!(!outcome.signed, "apk packages are not signed by silo");

    // The package row is the thing that makes a later index rebuild
    // possible without reading the bucket.
    let rows = harness
        .db
        .list_packages(&repo, "edge", Some(PackageFormat::Apk))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name, "hello");
    assert_eq!(rows[0].index_group, "x86_64");
    assert!(rows[0].metadata["checksum"]
        .as_str()
        .unwrap()
        .starts_with("Q1"));

    // And the index itself lists it.
    let index = harness
        .state
        .storage
        .get(&format!("{repo}/edge/apk/x86_64/APKINDEX.tar.gz"))
        .await
        .unwrap()
        .expect("APKINDEX was written");
    let mut inflated = Vec::new();
    flate2::bufread::MultiGzDecoder::new(index.as_slice())
        .read_to_end(&mut inflated)
        .unwrap();
    let text = String::from_utf8_lossy(&inflated);
    assert!(text.contains("P:hello"), "APKINDEX missing the package");
    assert!(text.contains("V:1.0-r0"));
}

/// Index pruning must not touch the package files beside the index.
///
/// For apk and npm the packages live *under* the index prefix — an apk
/// sits beside its APKINDEX, an npm tarball sits under the same package
/// directory as its packument — so a sweep that spared only the index
/// objects it had just written would remove the packages along with the
/// stale metadata. Nothing fails loudly when that happens: the index
/// still lists packages whose
/// bytes were gone, and every download 404'd.
#[tokio::test]
async fn regenerating_an_index_does_not_delete_the_packages_beside_it() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("prune");

    let apk = silo_core::repo::publish(
        &harness.state.publish,
        &repo,
        "edge",
        PackageFormat::Apk,
        build_test_apk("hello", "1.0-r0", "x86_64"),
        &actor(),
    )
    .await
    .expect("publish apk");

    let npm = silo_core::repo::publish(
        &harness.state.publish,
        &repo,
        "stable",
        PackageFormat::Npm,
        build_test_npm("widget", "1.0.0"),
        &actor(),
    )
    .await
    .expect("publish npm");

    // A second publish into each group forces a full index regeneration,
    // which is when the sweep runs.
    silo_core::repo::publish(
        &harness.state.publish,
        &repo,
        "edge",
        PackageFormat::Apk,
        build_test_apk("second", "1.0-r0", "x86_64"),
        &actor(),
    )
    .await
    .expect("publish a second apk");
    silo_core::repo::publish(
        &harness.state.publish,
        &repo,
        "stable",
        PackageFormat::Npm,
        build_test_npm("widget", "2.0.0"),
        &actor(),
    )
    .await
    .expect("publish a second npm version");

    for outcome in [&apk, &npm] {
        assert!(
            harness
                .state
                .storage
                .get(&outcome.storage_path)
                .await
                .unwrap()
                .is_some(),
            "index regeneration deleted the package at {}",
            outcome.storage_path
        );
    }

    // And the indexes themselves are still present.
    assert!(harness
        .state
        .storage
        .get(&format!("{repo}/edge/apk/x86_64/APKINDEX.tar.gz"))
        .await
        .unwrap()
        .is_some());
    assert!(harness
        .state
        .storage
        .get(&format!("{repo}/stable/npm/widget/packument.json"))
        .await
        .unwrap()
        .is_some());
}

/// `list_repos` aggregates with `sum()`, which Postgres returns as NUMERIC
/// rather than BIGINT — a mismatch that only surfaces against a real
/// database.
#[tokio::test]
async fn repo_summaries_decode_their_aggregate_columns() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("summary");

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

    let summaries = harness.db.list_repos().await.expect("list repos");
    let mine = summaries
        .iter()
        .find(|s| s.repo == repo)
        .expect("the repo just published to is missing");
    assert_eq!(mine.packages, 1);
    assert!(mine.total_bytes > 0);
}

#[tokio::test]
async fn apk_arches_get_independent_indexes() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("apk-multiarch");

    for arch in ["x86_64", "aarch64"] {
        silo_core::repo::publish(
            &harness.state.publish,
            &repo,
            "edge",
            PackageFormat::Apk,
            build_test_apk("hello", "1.0-r0", arch),
            &actor(),
        )
        .await
        .expect("publish apk");
    }

    // Publishing aarch64 must not have rewritten the x86_64 index into
    // something that omits its own package.
    for arch in ["x86_64", "aarch64"] {
        let index = harness
            .state
            .storage
            .get(&format!("{repo}/edge/apk/{arch}/APKINDEX.tar.gz"))
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("no index for {arch}"));
        let mut inflated = Vec::new();
        flate2::bufread::MultiGzDecoder::new(index.as_slice())
            .read_to_end(&mut inflated)
            .unwrap();
        let text = String::from_utf8_lossy(&inflated);
        assert!(text.contains(&format!("A:{arch}")), "{arch} index is wrong");
    }
}

#[tokio::test]
async fn noarch_apk_packages_appear_in_every_architecture_index() {
    // apk-tools only ever fetches $repo/$hostarch/APKINDEX.tar.gz, so a
    // noarch package that lives only in a noarch index is invisible to
    // every client.
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("apk-noarch");

    // Two architectures already exist in the channel...
    for arch in ["x86_64", "aarch64"] {
        silo_core::repo::publish(
            &harness.state.publish,
            &repo,
            "edge",
            PackageFormat::Apk,
            build_test_apk(&format!("native-{arch}"), "1.0-r0", arch),
            &actor(),
        )
        .await
        .expect("publish an arch-specific apk");
    }

    // ...and then a noarch package arrives.
    let outcome = silo_core::repo::publish(
        &harness.state.publish,
        &repo,
        "edge",
        PackageFormat::Apk,
        build_test_apk("portable", "2.0-r0", "noarch"),
        &actor(),
    )
    .await
    .expect("publish a noarch apk");
    assert_eq!(outcome.index_group, "noarch");

    // It has to be in all three: the two that existed before it, and its
    // own.
    for arch in ["x86_64", "aarch64", "noarch"] {
        let index = apkindex(&harness, &repo, "edge", arch).await;
        assert!(
            index.contains("P:portable"),
            "the noarch package is missing from the {arch} index"
        );
    }

    // ...without the architectures bleeding into each other.
    let x86 = apkindex(&harness, &repo, "edge", "x86_64").await;
    assert!(x86.contains("P:native-x86_64"));
    assert!(
        !x86.contains("P:native-aarch64"),
        "an arch index must not list another architecture's packages"
    );
}

#[tokio::test]
async fn an_architecture_published_after_a_noarch_package_still_lists_it() {
    // The other ordering: the noarch package is already there when a new
    // architecture appears, so the fan-out on publish cannot be what puts
    // it in the new index — reading the shared group must.
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("apk-noarch-first");

    silo_core::repo::publish(
        &harness.state.publish,
        &repo,
        "edge",
        PackageFormat::Apk,
        build_test_apk("portable", "2.0-r0", "noarch"),
        &actor(),
    )
    .await
    .expect("publish a noarch apk");

    silo_core::repo::publish(
        &harness.state.publish,
        &repo,
        "edge",
        PackageFormat::Apk,
        build_test_apk("native", "1.0-r0", "riscv64"),
        &actor(),
    )
    .await
    .expect("publish into a brand new arch");

    let index = apkindex(&harness, &repo, "edge", "riscv64").await;
    assert!(index.contains("P:native"));
    assert!(
        index.contains("P:portable"),
        "a new architecture's first index must already include noarch"
    );
}

#[tokio::test]
async fn pacman_publish_records_the_package_and_builds_a_database() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("pacman");

    let outcome = silo_core::repo::publish(
        &harness.state.publish,
        &repo,
        "edge",
        PackageFormat::Pacman,
        build_test_pacman("hello", "1.0-1", "x86_64", "zst"),
        &actor(),
    )
    .await
    .expect("publish pacman package");

    assert_eq!(
        outcome.storage_path,
        format!("{repo}/edge/pacman/x86_64/hello-1.0-1-x86_64.pkg.tar.zst")
    );
    assert_eq!(outcome.index_group, "x86_64");
    assert!(
        !outcome.signed,
        "pacman packages themselves are not signed by silo, only the database"
    );

    let rows = harness
        .db
        .list_packages(&repo, "edge", Some(PackageFormat::Pacman))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name, "hello");
    assert_eq!(rows[0].index_group, "x86_64");

    let db = harness
        .state
        .storage
        .get(&format!("{repo}/edge/pacman/x86_64/db.tar.gz"))
        .await
        .unwrap()
        .expect("db.tar.gz was written");
    let mut inflated = Vec::new();
    flate2::bufread::GzDecoder::new(db.as_slice())
        .read_to_end(&mut inflated)
        .unwrap();
    let mut archive = tar::Archive::new(inflated.as_slice());
    let names: Vec<String> = archive
        .entries()
        .unwrap()
        .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["hello-1.0-1/desc"]);
}

#[tokio::test]
async fn pacman_arches_get_independent_databases() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("pacman-multiarch");

    for arch in ["x86_64", "aarch64"] {
        silo_core::repo::publish(
            &harness.state.publish,
            &repo,
            "edge",
            PackageFormat::Pacman,
            build_test_pacman("hello", "1.0-1", arch, "zst"),
            &actor(),
        )
        .await
        .expect("publish pacman package");
    }

    // Publishing aarch64 must not have rewritten the x86_64 database into
    // something that omits its own package.
    for arch in ["x86_64", "aarch64"] {
        let db = harness
            .state
            .storage
            .get(&format!("{repo}/edge/pacman/{arch}/db.tar.gz"))
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("no database for {arch}"));
        let mut inflated = Vec::new();
        flate2::bufread::GzDecoder::new(db.as_slice())
            .read_to_end(&mut inflated)
            .unwrap();
        let text = String::from_utf8_lossy(&inflated);
        assert!(
            text.contains(&format!("%ARCH%\n{arch}\n")),
            "{arch} database is wrong"
        );
    }
}

#[tokio::test]
async fn any_pacman_packages_appear_in_every_architecture_database() {
    // pacman only ever fetches its own architecture's database, so an
    // `any` package that lived only in an `any` database would be
    // invisible to every client — same reasoning as apk's `noarch`.
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("pacman-any");

    for arch in ["x86_64", "aarch64"] {
        silo_core::repo::publish(
            &harness.state.publish,
            &repo,
            "edge",
            PackageFormat::Pacman,
            build_test_pacman(&format!("native-{arch}"), "1.0-1", arch, "zst"),
            &actor(),
        )
        .await
        .expect("publish an arch-specific pacman package");
    }

    let outcome = silo_core::repo::publish(
        &harness.state.publish,
        &repo,
        "edge",
        PackageFormat::Pacman,
        build_test_pacman("portable", "2.0-1", "any", "zst"),
        &actor(),
    )
    .await
    .expect("publish an any pacman package");
    assert_eq!(outcome.index_group, "any");

    for arch in ["x86_64", "aarch64", "any"] {
        let db = harness
            .state
            .storage
            .get(&format!("{repo}/edge/pacman/{arch}/db.tar.gz"))
            .await
            .unwrap()
            .unwrap();
        let mut inflated = Vec::new();
        flate2::bufread::GzDecoder::new(db.as_slice())
            .read_to_end(&mut inflated)
            .unwrap();
        let mut archive = tar::Archive::new(inflated.as_slice());
        let names: Vec<String> = archive
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(
            names.contains(&"portable-2.0-1/desc".to_string()),
            "the any package is missing from the {arch} database"
        );
    }
}

#[tokio::test]
async fn deleting_a_noarch_apk_removes_it_from_every_architecture() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("apk-noarch-delete");

    silo_core::repo::publish(
        &harness.state.publish,
        &repo,
        "edge",
        PackageFormat::Apk,
        build_test_apk("native", "1.0-r0", "x86_64"),
        &actor(),
    )
    .await
    .unwrap();
    silo_core::repo::publish(
        &harness.state.publish,
        &repo,
        "edge",
        PackageFormat::Apk,
        build_test_apk("portable", "2.0-r0", "noarch"),
        &actor(),
    )
    .await
    .unwrap();
    assert!(apkindex(&harness, &repo, "edge", "x86_64")
        .await
        .contains("P:portable"));

    let id = harness
        .db
        .list_packages(&repo, "edge", Some(PackageFormat::Apk))
        .await
        .unwrap()
        .into_iter()
        .find(|p| p.name == "portable")
        .expect("the noarch row")
        .id;
    silo_core::repo::delete_package(&harness.state.publish, id, &actor(), None)
        .await
        .unwrap();

    let index = apkindex(&harness, &repo, "edge", "x86_64").await;
    assert!(
        !index.contains("P:portable"),
        "a deleted noarch package is still listed in the x86_64 index"
    );
    assert!(
        index.contains("P:native"),
        "the arch's own package survived"
    );
}

#[tokio::test]
async fn npm_publish_produces_a_packument_with_all_versions() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("npm");

    for version in ["1.0.0", "1.1.0", "2.0.0-rc.1"] {
        silo_core::repo::publish(
            &harness.state.publish,
            &repo,
            "stable",
            PackageFormat::Npm,
            build_test_npm("widget", version),
            &actor(),
        )
        .await
        .expect("publish npm tarball");
    }

    let packument = harness
        .state
        .storage
        .get(&format!("{repo}/stable/npm/widget/packument.json"))
        .await
        .unwrap()
        .expect("packument was written");
    let doc: serde_json::Value = serde_json::from_slice(&packument).unwrap();

    assert_eq!(doc["versions"].as_object().unwrap().len(), 3);
    // The prerelease must not win `latest` over a stable release.
    assert_eq!(doc["dist-tags"]["latest"], "1.1.0");
    assert_eq!(
        doc["versions"]["1.0.0"]["dist"]["tarball"],
        format!("https://silo.test/{repo}/stable/npm/widget/-/widget-1.0.0.tgz")
    );
    assert!(doc["versions"]["1.0.0"]["dist"]["integrity"]
        .as_str()
        .unwrap()
        .starts_with("sha512-"));
}

#[tokio::test]
async fn npm_scoped_packages_are_separate_index_groups() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("npm-scoped");

    let outcome = silo_core::repo::publish(
        &harness.state.publish,
        &repo,
        "stable",
        PackageFormat::Npm,
        build_test_npm("@acme/widget", "1.0.0"),
        &actor(),
    )
    .await
    .expect("publish scoped npm tarball");

    assert_eq!(outcome.index_group, "@acme/widget");
    assert_eq!(
        outcome.storage_path,
        format!("{repo}/stable/npm/@acme/widget/-/widget-1.0.0.tgz")
    );
    assert!(harness
        .state
        .storage
        .get(&format!("{repo}/stable/npm/@acme/widget/packument.json"))
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn republishing_the_same_version_replaces_rather_than_duplicates() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("npm-republish");

    for _ in 0..2 {
        silo_core::repo::publish(
            &harness.state.publish,
            &repo,
            "stable",
            PackageFormat::Npm,
            build_test_npm("widget", "1.0.0"),
            &actor(),
        )
        .await
        .expect("publish npm tarball");
    }

    let rows = harness
        .db
        .list_packages(&repo, "stable", Some(PackageFormat::Npm))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "republish must not create a second row");
}

#[tokio::test]
async fn rpm_publish_writes_repodata() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("rpm");

    let outcome = silo_core::repo::publish(
        &harness.state.publish,
        &repo,
        "stable",
        PackageFormat::Rpm,
        build_test_rpm("silo-itest", "1.0.0", "1", "x86_64"),
        &actor(),
    )
    .await
    .expect("publish rpm");

    assert_eq!(
        outcome.storage_path,
        format!("{repo}/stable/Packages/silo-itest-1.0.0-1.x86_64.rpm")
    );
    assert_eq!(
        outcome.index_group, "",
        "rpm has a single index per channel"
    );

    let repomd = harness
        .state
        .storage
        .get(&format!("{repo}/stable/repodata/repomd.xml"))
        .await
        .unwrap()
        .expect("repomd.xml was written");
    let repomd = String::from_utf8_lossy(&repomd).into_owned();
    assert!(repomd.contains("<repomd"));

    // Every file repomd.xml points at must actually be in the bucket,
    // under the name the checksum-derived href gives it — that is the
    // whole contract dnf resolves the repo through.
    for kind in ["primary", "filelists", "other"] {
        assert!(repomd.contains(&format!("type=\"{kind}\"")), "{repomd}");
    }

    let hrefs: Vec<&str> = repomd
        .lines()
        .filter(|l| l.contains("<location href="))
        .filter_map(|l| l.split('"').nth(1))
        .collect();
    assert_eq!(hrefs.len(), 3, "{repomd}");
    for href in hrefs {
        assert!(
            harness
                .state
                .storage
                .get(&format!("{repo}/stable/{href}"))
                .await
                .unwrap()
                .is_some(),
            "{href} is referenced by repomd.xml but missing from storage"
        );
    }
}

#[tokio::test]
async fn deb_publish_writes_release_and_packages() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("deb");

    let outcome = silo_core::repo::publish(
        &harness.state.publish,
        &repo,
        "stable",
        PackageFormat::Deb,
        build_test_deb("hello", "1.0-1", "amd64"),
        &actor(),
    )
    .await
    .expect("publish deb");

    assert_eq!(
        outcome.storage_path,
        format!("{repo}/stable/pool/hello_1.0-1_amd64.deb")
    );
    assert_eq!(
        outcome.index_group, "",
        "apt's Release covers every architecture at once"
    );
    assert!(
        !outcome.signed,
        "no signing key is configured in this harness"
    );

    let rows = harness
        .db
        .list_packages(&repo, "stable", Some(PackageFormat::Deb))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name, "hello");

    let release = harness
        .state
        .storage
        .get(&format!("{repo}/stable/dists/stable/Release"))
        .await
        .unwrap()
        .expect("Release was written");
    let release = String::from_utf8_lossy(&release).into_owned();
    assert!(release.contains("Suite: stable"));
    assert!(release.contains("Architectures: amd64"));
    assert!(
        harness
            .state
            .storage
            .get(&format!("{repo}/stable/dists/stable/InRelease"))
            .await
            .unwrap()
            .is_none(),
        "InRelease must not exist without a configured signing key"
    );

    // Every file Release's SHA256 section points at must actually be in
    // the bucket — the same contract repomd.xml's hrefs give dnf.
    let paths: Vec<&str> = release
        .lines()
        .skip_while(|l| *l != "SHA256:")
        .skip(1)
        .filter_map(|l| l.split_whitespace().nth(2))
        .collect();
    assert_eq!(paths.len(), 3, "{release}");
    for path in paths {
        assert!(
            harness
                .state
                .storage
                .get(&format!("{repo}/stable/dists/stable/{path}"))
                .await
                .unwrap()
                .is_some(),
            "{path} is referenced by Release but missing from storage"
        );
    }

    let packages = harness
        .state
        .storage
        .get(&format!(
            "{repo}/stable/dists/stable/main/binary-amd64/Packages"
        ))
        .await
        .unwrap()
        .expect("Packages was written");
    let packages = String::from_utf8_lossy(&packages).into_owned();
    assert!(packages.contains("Package: hello\n"));
    assert!(packages.contains("Version: 1.0-1\n"));
    assert!(packages.contains("Filename: pool/hello_1.0-1_amd64.deb\n"));
}

#[tokio::test]
async fn concurrent_publishes_to_one_index_all_survive() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("apk-concurrent");

    // This is the regression test for the race the lock exists to close:
    // before it, each of these would rebuild the index from its own view
    // and the last writer's index would omit the others' packages.
    let mut handles = Vec::new();
    for i in 0..6 {
        let state = harness.state.clone();
        let repo = repo.clone();
        handles.push(tokio::spawn(async move {
            silo_core::repo::publish(
                &state.publish,
                &repo,
                "edge",
                PackageFormat::Apk,
                build_test_apk(&format!("pkg{i}"), "1.0-r0", "x86_64"),
                &actor(),
            )
            .await
        }));
    }
    for handle in handles {
        handle
            .await
            .expect("task panicked")
            .expect("publish failed");
    }

    let rows = harness
        .db
        .list_packages(&repo, "edge", Some(PackageFormat::Apk))
        .await
        .unwrap();
    assert_eq!(rows.len(), 6);

    let index = harness
        .state
        .storage
        .get(&format!("{repo}/edge/apk/x86_64/APKINDEX.tar.gz"))
        .await
        .unwrap()
        .expect("APKINDEX was written");
    let mut inflated = Vec::new();
    flate2::bufread::MultiGzDecoder::new(index.as_slice())
        .read_to_end(&mut inflated)
        .unwrap();
    let text = String::from_utf8_lossy(&inflated);

    for i in 0..6 {
        assert!(
            text.contains(&format!("P:pkg{i}")),
            "the final index lost pkg{i} — the publish lock is not holding"
        );
    }
}

#[tokio::test]
async fn a_failed_publish_leaves_no_package_row() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("apk-invalid");

    let err = silo_core::repo::publish(
        &harness.state.publish,
        &repo,
        "edge",
        PackageFormat::Apk,
        b"this is not an apk".to_vec(),
        &actor(),
    )
    .await
    .expect_err("garbage bytes must be rejected");
    assert!(err.to_string().contains("invalid apk"), "got: {err}");

    let rows = harness.db.list_packages(&repo, "edge", None).await.unwrap();
    assert!(rows.is_empty());
}

#[tokio::test]
async fn publishes_are_written_to_the_audit_log() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("audit");

    silo_core::repo::publish(
        &harness.state.publish,
        &repo,
        "edge",
        PackageFormat::Apk,
        build_test_apk("audited", "2.0-r1", "x86_64"),
        &actor(),
    )
    .await
    .expect("publish apk");

    let entries = harness
        .db
        .query_audit(&AuditQuery {
            repo: Some(repo.clone()),
            limit: 10,
            ..Default::default()
        })
        .await
        .unwrap();

    let publish = entries
        .iter()
        .find(|e| e.action == "package.publish")
        .expect("publish was not audited");
    assert!(publish.success);
    assert_eq!(publish.actor_name.as_deref(), Some("test-publisher"));
    assert_eq!(publish.target.as_deref(), Some("audited-2.0-r1.x86_64"));
    assert_eq!(publish.remote_addr.as_deref(), Some("10.0.0.1"));
    assert_eq!(publish.detail["format"], "apk");
}

#[tokio::test]
async fn rebuilding_an_index_restores_it_from_the_database_alone() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("rebuild");

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

    // Simulate a lost index — a restored bucket, a botched deploy.
    let index_key = format!("{repo}/edge/apk/x86_64/APKINDEX.tar.gz");
    harness.state.storage.delete(&index_key).await.unwrap();
    assert!(harness
        .state
        .storage
        .get(&index_key)
        .await
        .unwrap()
        .is_none());

    silo_core::repo::regenerate_index(
        &harness.state.publish,
        &repo,
        "edge",
        PackageFormat::Apk,
        "x86_64",
        &Actor::system(),
    )
    .await
    .expect("rebuild the index");

    assert!(
        harness
            .state
            .storage
            .get(&index_key)
            .await
            .unwrap()
            .is_some(),
        "the index was not rebuilt from the package rows"
    );
}

#[tokio::test]
async fn deleting_a_package_removes_it_from_storage_and_the_index() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("delete");

    for name in ["keeper", "goner"] {
        silo_core::repo::publish(
            &harness.state.publish,
            &repo,
            "edge",
            PackageFormat::Apk,
            build_test_apk(name, "1.0-r0", "x86_64"),
            &actor(),
        )
        .await
        .expect("publish apk");
    }

    let rows = harness.db.list_packages(&repo, "edge", None).await.unwrap();
    let goner = rows.iter().find(|r| r.name == "goner").unwrap();

    let deleted = silo_core::repo::delete_package(&harness.state.publish, goner.id, &actor(), None)
        .await
        .expect("delete the package");
    assert_eq!(deleted.as_deref(), Some(goner.storage_key.as_str()));
    assert!(harness
        .state
        .storage
        .get(&goner.storage_key)
        .await
        .unwrap()
        .is_none());

    let index = harness
        .state
        .storage
        .get(&format!("{repo}/edge/apk/x86_64/APKINDEX.tar.gz"))
        .await
        .unwrap()
        .unwrap();
    let mut inflated = Vec::new();
    flate2::bufread::MultiGzDecoder::new(index.as_slice())
        .read_to_end(&mut inflated)
        .unwrap();
    let text = String::from_utf8_lossy(&inflated);
    assert!(text.contains("P:keeper"));
    assert!(
        !text.contains("P:goner"),
        "deleted package is still indexed"
    );
}

#[tokio::test]
async fn tokens_verify_and_enforce_their_scope_end_to_end() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("scope");

    let issued = harness.publisher_token(&repo).await;
    let verified = harness
        .db
        .verify_token(&issued.secret, None)
        .await
        .expect("the freshly issued token must verify");

    assert!(verified.allows(&repo, Permission::Write));
    assert!(!verified.allows("some-other-repo", Permission::Read));
    assert!(!verified.allows(&repo, Permission::Admin));

    // A tampered secret must not verify, even though its prefix is real.
    let tampered = format!("{}x", issued.secret);
    assert!(harness.db.verify_token(&tampered, None).await.is_err());

    // Revocation takes effect immediately.
    assert!(harness.db.revoke_token(verified.id).await.unwrap());
    assert!(harness.db.verify_token(&issued.secret, None).await.is_err());
}

#[tokio::test]
async fn a_wrong_pepper_invalidates_every_token() {
    let url = require_db!();
    let harness = Harness::new(&url).await;

    let issued = harness
        .token("peppered", Permission::Read, Scope::All)
        .await;
    assert!(harness.db.verify_token(&issued.secret, None).await.is_ok());
    assert!(
        harness
            .db
            .verify_token(&issued.secret, Some("a-pepper"))
            .await
            .is_err(),
        "changing the pepper must invalidate tokens hashed without it"
    );
}
