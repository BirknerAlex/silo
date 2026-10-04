//! The OSTree remote operations that don't arrive as one `.flatpak`
//! bundle: a client pushing the objects of a local repository and then
//! moving a ref.
//!
//! The protocol is the shape that makes a push cheap to repeat and safe
//! to interrupt:
//!
//! 1. The client asks which of its objects the server lacks
//!    ([`missing_objects`]) and uploads only those ([`stage_object`]).
//! 2. Every object is verified where it lands: its checksum is recomputed
//!    from its bytes and compared with the name it was uploaded under, so
//!    storage never holds an object that isn't what its key says.
//! 3. The client then moves a ref ([`publish_ref`]). Only now does
//!    anything become visible, and only once every object under the
//!    commit is present — a push that dies halfway leaves unreferenced
//!    objects behind and no half-published ref.
//!
//! The ref update ends in the same place a bundle publish does — one row,
//! one regenerated `summary` under the channel's lock — so there is one
//! path that makes a ref visible, however its objects got here.
//!
//! Objects are shared between commits, so removing a ref leaves its objects
//! behind. [`gc_channel`] collects the ones no ref reaches; see its
//! documentation for what keeps that safe next to a publish in flight.

use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use futures::{StreamExt, TryStreamExt};
use silo_db::{lock, packages};
use silo_pkg::flatpak;
use silo_pkg::ostree::archive;
use silo_pkg::ostree::delta::{check_ref_binding, verify_metadata};
use silo_pkg::ostree::object::{Checksum, Commit, ObjType};
use silo_pkg::ostree::tree::TreeWalk;
use silo_pkg::{ExtraObject, PackageFormat};

use crate::config::validate_repo_name;
use crate::repo::{store_parsed, PublishContext, PublishOutcome, MAX_PACKAGE_BYTES};
use silo_db::audit::Actor;

/// Directory objects fetched from storage at once while a commit's tree
/// is checked.
const TREE_FETCH_CONCURRENCY: usize = 32;

/// An error the client caused. The `invalid ` prefix is what
/// [`crate::repo::classify_publish_error`] turns into a 4xx.
fn invalid(msg: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("invalid ostree request: {msg}")
}

/// Reads `objects/ab/cdef….ext` into the object it names.
///
/// `commitmeta` is deliberately not accepted: signatures over commits are
/// the server's to make, with its own key.
pub fn object_from_path(path: &str) -> Option<(ObjType, Checksum)> {
    let rest = path.strip_prefix("objects/")?;
    let (prefix, file) = rest.split_once('/')?;
    let (stem, ext) = file.split_once('.')?;
    let ty = ObjType::from_extension(ext)?;
    if prefix.len() != 2 || stem.len() != 62 {
        return None;
    }
    let checksum = Checksum::from_hex(&format!("{prefix}{stem}")).ok()?;
    // `from_hex` accepts uppercase; object paths are lowercase, and two
    // spellings of one object would be two objects in storage.
    (checksum.hex() == format!("{prefix}{stem}")).then_some((ty, checksum))
}

/// Whether `path` names an object a client may download: any object
/// [`object_from_path`] accepts, or the signature file beside a commit.
///
/// The server decides what it serves from the *shape* of the path rather
/// than passing arbitrary keys under the remote's prefix through to
/// storage, so nothing it keeps there for its own purposes is reachable by
/// guessing a name.
pub fn is_served_object(path: &str) -> bool {
    match path.strip_suffix(".commitmeta") {
        Some(stem) => object_from_path(&format!("{stem}.commit")).is_some(),
        None => object_from_path(path).is_some(),
    }
}

/// Verifies an uploaded object against the name it was sent under, and
/// stores it. Returns whether it was written — `false` means the server
/// already had it.
pub async fn stage_object(
    ctx: &PublishContext,
    repo: &str,
    channel: &str,
    ty: ObjType,
    checksum: Checksum,
    bytes: Vec<u8>,
) -> anyhow::Result<bool> {
    validate_repo_name("repo", repo)?;
    validate_repo_name("channel", channel)?;

    if bytes.len() > MAX_PACKAGE_BYTES {
        return Err(invalid("the object exceeds the upload limit"));
    }
    if ty.is_metadata() {
        verify_metadata(ty, &bytes, checksum).map_err(invalid)?;
    } else {
        let actual = archive::checksum_of(ty, &bytes, MAX_PACKAGE_BYTES as u64).map_err(invalid)?;
        if actual != checksum {
            return Err(invalid(format!(
                "file object {checksum} does not match its content"
            )));
        }
    }

    ctx.db.ensure_repo(repo).await?;
    let key = flatpak::object_key(repo, channel, ty, &checksum);
    if ctx.storage.head(&key).await? {
        return Ok(false);
    }
    ctx.storage.put(&key, bytes).await?;
    Ok(true)
}

/// The subset of `objects` the server does not hold.
pub async fn missing_objects(
    ctx: &PublishContext,
    repo: &str,
    channel: &str,
    objects: Vec<(ObjType, Checksum)>,
) -> anyhow::Result<Vec<(ObjType, Checksum)>> {
    validate_repo_name("repo", repo)?;
    validate_repo_name("channel", channel)?;

    // Everything the stream touches is owned. A closure or async block
    // that borrows `repo` or `channel` across an await makes the returned
    // future fail to prove it is `Send` for every lifetime, which an axum
    // handler requires.
    let storage = ctx.storage.clone();
    let keyed: Vec<(ObjType, Checksum, String)> = objects
        .into_iter()
        .map(|(ty, checksum)| {
            (
                ty,
                checksum,
                flatpak::object_key(repo, channel, ty, &checksum),
            )
        })
        .collect();
    let checked: Vec<Option<(ObjType, Checksum)>> = futures::stream::iter(keyed)
        .map(|(ty, checksum, key)| {
            let storage = storage.clone();
            async move {
                Ok::<_, anyhow::Error>(if storage.head(&key).await? {
                    None
                } else {
                    Some((ty, checksum))
                })
            }
        })
        .buffered(TREE_FETCH_CONCURRENCY)
        .try_collect()
        .await?;
    Ok(checked.into_iter().flatten().collect())
}

/// Points `reference` at `commit` once everything under the commit is in
/// storage.
pub async fn publish_ref(
    ctx: &PublishContext,
    repo: &str,
    channel: &str,
    reference: &str,
    commit: &str,
    actor: &Actor,
) -> anyhow::Result<PublishOutcome> {
    validate_repo_name("repo", repo)?;
    validate_repo_name("channel", channel)?;
    ctx.db.ensure_repo(repo).await?;

    let checksum = Checksum::from_hex(commit).map_err(invalid)?;
    let commit_key = flatpak::object_key(repo, channel, ObjType::Commit, &checksum);
    let commit_bytes = ctx
        .storage
        .get(&commit_key)
        .await?
        .ok_or_else(|| invalid(format!("commit {checksum} has not been uploaded")))?;
    verify_metadata(ObjType::Commit, &commit_bytes, checksum).map_err(invalid)?;
    check_ref_binding(&commit_bytes, reference).map_err(invalid)?;

    let parsed_commit = Commit::parse(&commit_bytes).map_err(invalid)?;
    walk_tree_in_storage(ctx, repo, channel, &parsed_commit).await?;

    // The commit rides along so its signature is made the same way as for
    // a bundle; it is already stored, so nothing is uploaded twice.
    let parsed = flatpak::ref_package(
        reference,
        checksum,
        &commit_bytes,
        vec![ExtraObject {
            key: format!("ostree/{}", ObjType::Commit.archive_path(&checksum)),
            bytes: commit_bytes.clone(),
            replace: false,
        }],
    )
    .map_err(invalid)?;

    let signed = ctx.signers.for_format(PackageFormat::Flatpak).is_some();
    let payload = parsed.payload.clone();
    let metadata = parsed.metadata.clone();
    store_parsed(
        ctx,
        repo,
        channel,
        PackageFormat::Flatpak,
        parsed,
        payload,
        metadata,
        signed,
        actor,
        None,
        // The tree was checked above, before the lock; `store_parsed`
        // checks it again once it holds the lock.
        Some(&parsed_commit),
    )
    .await
}

/// Walks a commit's tree through object storage, failing on the first
/// object that is missing or malformed, and returns every object it
/// reached.
pub(crate) async fn walk_tree_in_storage(
    ctx: &PublishContext,
    repo: &str,
    channel: &str,
    commit: &Commit,
) -> anyhow::Result<Vec<(ObjType, Checksum)>> {
    let mut walk = TreeWalk::new(commit);
    let mut visited = Vec::new();
    loop {
        let mut batch = Vec::new();
        while batch.len() < TREE_FETCH_CONCURRENCY {
            match walk.next_wanted() {
                Some(want) => batch.push(want),
                None => break,
            }
        }
        if batch.is_empty() {
            return Ok(visited);
        }
        visited.extend(batch.iter().map(|w| (w.ty, w.checksum)));

        let storage = ctx.storage.clone();
        let keyed: Vec<(ObjType, String)> = batch
            .iter()
            .map(|want| {
                (
                    want.ty,
                    flatpak::object_key(repo, channel, want.ty, &want.checksum),
                )
            })
            .collect();
        let fetched: Vec<Option<Vec<u8>>> = futures::stream::iter(keyed)
            .map(|(ty, key)| {
                let storage = storage.clone();
                async move {
                    if ty == ObjType::File {
                        // Files are verified when staged; presence is enough.
                        Ok::<_, anyhow::Error>(storage.head(&key).await?.then(Vec::new))
                    } else {
                        storage.get(&key).await
                    }
                }
            })
            .buffered(TREE_FETCH_CONCURRENCY)
            .try_collect()
            .await?;

        for (want, bytes) in batch.iter().zip(fetched) {
            let Some(bytes) = bytes else {
                return Err(invalid(format!(
                    "the commit needs {:?} object {} which has not been uploaded",
                    want.ty, want.checksum
                )));
            };
            if want.ty != ObjType::File {
                verify_metadata(want.ty, &bytes, want.checksum).map_err(invalid)?;
                walk.provide(want, &bytes).map_err(invalid)?;
            }
        }
    }
}

/// How long an object must have sat in storage before a sweep may remove
/// it, unless `jobs.flatpak_gc_min_age_hours` says otherwise. A publish
/// uploads its objects before it makes any ref point at them, so for that
/// stretch they are unreachable and indistinguishable from garbage by
/// reachability alone; their age is what tells them apart.
pub const GC_GRACE: Duration = Duration::from_secs(24 * 60 * 60);

/// The most objects one sweep of one channel deletes. The deletes happen
/// while the channel's lock is held, which publishers wait on for at most
/// two minutes, so a very large backlog is cleared over several runs
/// rather than in one long stall.
pub const GC_MAX_DELETES: usize = 10_000;

/// Objects deleted at once.
const GC_DELETE_CONCURRENCY: usize = 32;

/// What a sweep of one channel found and did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GcReport {
    pub repo: String,
    pub channel: String,
    /// Objects the refs reach, which are never touched.
    pub live: usize,
    /// Unreachable objects too recent to remove.
    pub too_new: usize,
    /// Objects removed — or, in a dry run, that would be.
    pub deleted: usize,
    pub deleted_bytes: u64,
    /// Eligible objects left for the next run by [`GC_MAX_DELETES`].
    pub deferred: usize,
    pub dry_run: bool,
    /// Why nothing was deleted, when the sweep backed off.
    pub backed_off: Option<String>,
}

/// Removes the objects of one channel that no ref reaches and that are
/// older than `grace`.
///
/// What an object needs to survive is being reachable from a ref's commit,
/// so the sweep marks everything the channel's refs reach and removes only
/// what is left. Three things keep that from hurting a publish that is
/// happening at the same time:
///
/// - **Age.** An object younger than `grace` is never removed, which covers
///   a push still uploading ahead of its ref update.
/// - **The refs must not move.** The marking and the listing happen without
///   the channel's lock, so a long walk does not stall publishers; the
///   deletes happen under it, and only after the refs are confirmed to be
///   exactly what was marked. If they changed, the sweep backs off and the
///   next run starts over.
/// - **The publisher re-checks.** A publish that skipped uploading an object
///   because it already existed confirms, under the same lock, that it still
///   does (and restores it if not) before its ref becomes visible.
///
/// A commit the refs name whose tree is incomplete, or whose commit object
/// is missing, makes the sweep back off without deleting anything: it cannot
/// know what is reachable, and guessing wrong costs a working install.
///
/// The database is the source of truth for what is live, as it is for every
/// index silo renders.
pub async fn gc_channel(
    ctx: &PublishContext,
    repo: &str,
    channel: &str,
    grace: Duration,
    dry_run: bool,
) -> anyhow::Result<GcReport> {
    validate_repo_name("repo", repo)?;
    validate_repo_name("channel", channel)?;

    let mut report = GcReport {
        repo: repo.to_string(),
        channel: channel.to_string(),
        dry_run,
        ..GcReport::default()
    };

    // Mark: every object the channel's refs reach.
    let rows = ctx
        .db
        .list_packages(repo, channel, Some(PackageFormat::Flatpak))
        .await?;
    let marked = live_refs(&rows);

    let mut live: HashSet<String> = HashSet::new();
    let commits: HashSet<&String> = marked.values().collect();
    for hex in commits {
        let checksum = Checksum::from_hex(hex)?;
        let commit_key = flatpak::object_key(repo, channel, ObjType::Commit, &checksum);
        let Some(commit_bytes) = ctx.storage.get(&commit_key).await? else {
            report.backed_off = Some(format!("a live ref's commit {hex} is missing from storage"));
            return Ok(report);
        };
        let commit = Commit::parse(&commit_bytes)?;
        let reached = match walk_tree_in_storage(ctx, repo, channel, &commit).await {
            Ok(reached) => reached,
            Err(e) => {
                report.backed_off = Some(format!("could not walk the tree of commit {hex}: {e}"));
                return Ok(report);
            }
        };
        live.insert(ObjType::Commit.archive_path(&checksum));
        live.insert(flatpak::commitmeta_path(&checksum));
        for (ty, sum) in reached {
            live.insert(ty.archive_path(&sum));
        }
    }
    report.live = live.len();

    // What is in storage, and which of it is both unreachable and old.
    let prefix = flatpak::ostree_prefix(repo, channel);
    let now = chrono::Utc::now();
    let grace = chrono::Duration::from_std(grace)?;
    let mut doomed: Vec<(String, u64)> = Vec::new();
    for (key, size, modified) in ctx.storage.list_aged(&format!("{prefix}/objects/")).await? {
        let Some(relative) = key.strip_prefix(&format!("{prefix}/")) else {
            continue;
        };
        // Only what the server would serve is the server's to remove.
        if !is_served_object(relative) || live.contains(relative) {
            continue;
        }
        if now - modified < grace {
            report.too_new += 1;
        } else {
            doomed.push((key, size));
        }
    }

    if doomed.len() > GC_MAX_DELETES {
        report.deferred = doomed.len() - GC_MAX_DELETES;
        doomed.truncate(GC_MAX_DELETES);
    }
    report.deleted = doomed.len();
    report.deleted_bytes = doomed.iter().map(|(_, size)| size).sum();
    if dry_run || doomed.is_empty() {
        return Ok(report);
    }

    sweep_if_unchanged(ctx, repo, channel, &marked, doomed, &mut report).await?;
    Ok(report)
}

/// The second half of [`gc_channel`]: deletes `doomed` under the channel's
/// lock, but only if the refs are still exactly `marked`.
///
/// Separate so the check that guards the deletes can be tested against refs
/// that have moved, which a sweep racing a real publish cannot do on
/// demand.
pub async fn sweep_if_unchanged(
    ctx: &PublishContext,
    repo: &str,
    channel: &str,
    marked: &BTreeMap<String, String>,
    doomed: Vec<(String, u64)>,
    report: &mut GcReport,
) -> anyhow::Result<()> {
    let scope = lock::index_scope(repo, channel, PackageFormat::Flatpak.as_str(), "");
    let mut locked = ctx.db.lock(scope).await?;
    let rows_now = packages::list_groups(
        locked.conn(),
        repo,
        channel,
        PackageFormat::Flatpak,
        &[String::new()],
    )
    .await?;
    if &live_refs(&rows_now) != marked {
        report.deleted = 0;
        report.deleted_bytes = 0;
        report.backed_off = Some("the channel's refs changed while it was being marked".into());
        return Ok(());
    }

    let storage = ctx.storage.clone();
    futures::stream::iter(doomed.into_iter().map(|(key, _)| key))
        .map(|key| {
            let storage = storage.clone();
            async move { storage.delete(&key).await }
        })
        .buffer_unordered(GC_DELETE_CONCURRENCY)
        .try_collect::<Vec<()>>()
        .await?;
    locked.commit().await?;
    Ok(())
}

/// The refs a channel serves and the commit each points at.
pub fn live_refs(rows: &[silo_db::packages::PackageRow]) -> BTreeMap<String, String> {
    rows.iter()
        .filter_map(|r| {
            Some((
                flatpak::join_ref(&r.name, &r.arch, &r.version),
                r.metadata["commit"].as_str()?.to_string(),
            ))
        })
        .collect()
}

/// Sweeps every Flatpak remote the server holds objects for.
///
/// A channel is swept when it still has a ref or when its repo is still
/// known to the database, so a channel whose last ref was removed gets its
/// objects collected, while objects under a repo the database has never
/// heard of — a fresh database pointed at an old bucket — are left alone.
pub async fn gc_all(
    ctx: &PublishContext,
    grace: Duration,
    dry_run: bool,
) -> anyhow::Result<Vec<GcReport>> {
    let mut reports = Vec::new();
    for repo in ctx.storage.list_dirs("").await? {
        if validate_repo_name("repo", &repo).is_err() || !ctx.db.repo_exists(&repo).await? {
            continue;
        }
        for channel in ctx.storage.list_dirs(&repo).await? {
            if validate_repo_name("channel", &channel).is_err() {
                continue;
            }
            let has_remote = ctx
                .storage
                .list_dirs(&format!("{repo}/{channel}"))
                .await?
                .iter()
                .any(|d| d == "ostree");
            if !has_remote {
                continue;
            }
            match gc_channel(ctx, &repo, &channel, grace, dry_run).await {
                Ok(report) => reports.push(report),
                Err(e) => {
                    // One channel's trouble must not stop the others.
                    tracing::warn!(repo, channel, error = %e, "flatpak object sweep failed");
                }
            }
        }
    }
    Ok(reports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_paths_name_exactly_one_object() {
        let hex = "930fc25874c26c343a792858523e747af11db9709ee14af708b8ff3fd81f9fc6";
        let path = format!("objects/{}/{}.filez", &hex[..2], &hex[2..]);
        let (ty, sum) = object_from_path(&path).unwrap();
        assert_eq!(ty, ObjType::File);
        assert_eq!(sum.hex(), hex);

        for bad in [
            "objects/93/0fc2.filez".to_string(),
            format!("objects/{}/{}.commitmeta", &hex[..2], &hex[2..]),
            format!("objects/{}/{}.exe", &hex[..2], &hex[2..]),
            format!("objects/{}/{}", &hex[..2], &hex[2..]),
            format!("objects/{}/{}.filez", &hex[..3], &hex[3..]),
            format!(
                "objects/{}/{}.filez",
                hex[..2].to_uppercase(),
                hex[2..].to_uppercase()
            ),
            format!("refs/heads/{}", hex),
            String::new(),
        ] {
            assert!(object_from_path(&bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn a_commit_signature_is_served_but_never_accepted() {
        let hex = "6bff8a2710a3eb3d2124d3804230e388836e089e9e4761293f6c0d160e38151e";
        let meta = format!("objects/{}/{}.commitmeta", &hex[..2], &hex[2..]);
        assert!(is_served_object(&meta));
        assert!(object_from_path(&meta).is_none());
        assert!(!is_served_object("objects/6b/short.commitmeta"));
        assert!(!is_served_object("summary"));
    }

    #[test]
    fn a_traversing_object_path_is_not_an_object() {
        assert!(object_from_path("objects/../../etc/passwd.filez").is_none());
        assert!(object_from_path("objects/ab/../../x.dirtree").is_none());
    }
}
