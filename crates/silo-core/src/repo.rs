//! The publish flow and index regeneration.
//!
//! ## How a publish is made safe
//!
//! Two concurrent publishes to one repo/channel would otherwise each
//! regenerate the index from their own view of object storage, and the
//! loser's package would silently vanish from the index that won. Ruling
//! that out has two halves, and both live in this module:
//!
//! 1. **A Postgres advisory lock**, scoped to the *index group* rather
//!    than the whole server — so two apk arches, or two npm packages, or
//!    two different repos, still publish concurrently. Only publishes that
//!    would write the same index file serialize against each other.
//! 2. **The database as the source of truth for what's in a repo.** The
//!    index is rendered from rows read inside the locked transaction, not
//!    from a bucket listing. There is no window in which a package exists
//!    but isn't visible to the renderer.
//!
//! Both halves live in the same transaction, so the lock covers exactly
//! the interval in which the index could be computed from stale data.
//!
//! ## Ordering, and the one failure mode left
//!
//! Bytes are written to object storage before the row is committed, so a
//! reader following a freshly published index never 404s. The cost is that
//! a crash between the upload and the commit leaves orphaned bytes in the
//! bucket that no row references. They're invisible (nothing links to
//! them) and the next publish of the same file overwrites them. The
//! opposite ordering would trade that for a committed row pointing at
//! bytes that aren't there yet — a 404 for real clients — which is worse.

use serde_json::json;
use sha2::{Digest, Sha256};
use silo_db::audit::{self, Actor, AuditEntry};
use silo_db::packages::{self, NewPackage};
use silo_db::{lock, Db};
use silo_pkg::{IndexContext, PackageFormat};

use crate::config::validate_repo_name;
use crate::signing::{maybe_sign_rpm, Signers};
use crate::storage::Storage;

/// Ceiling on a single upload, shared by every transport. Without one, a
/// client can drive the server out of memory by streaming forever — the
/// bytes are reassembled in RAM because every format's parser needs the
/// whole archive to validate it.
pub const MAX_PACKAGE_BYTES: usize = 2 * 1024 * 1024 * 1024;

/// Coarse classification of a [`publish`] error, shared by every transport
/// so their status codes stay in sync without each re-deriving "you sent
/// us something invalid" from the error message independently.
pub enum PublishErrorKind {
    InvalidArgument,
    Timeout,
    Internal,
}

/// Distinguishes "you sent us something invalid" from "we failed".
/// Everything the parsers reject is the client's fault, and reporting it
/// as an internal error would make a bad upload look like a server outage.
pub fn classify_publish_error(error: &anyhow::Error) -> PublishErrorKind {
    let message = error.to_string();
    if message.starts_with("invalid ")
        || message.contains("is not a valid")
        || message.contains("name must be")
        || message.contains("may only contain")
    {
        return PublishErrorKind::InvalidArgument;
    }
    if message.contains("timed out waiting for the lock") {
        return PublishErrorKind::Timeout;
    }
    PublishErrorKind::Internal
}

/// Everything the publish flow needs, assembled once at startup.
#[derive(Clone)]
pub struct PublishContext {
    pub storage: Storage,
    pub db: Db,
    pub signers: Signers,
    pub public_base_url: Option<String>,
    /// The opt-in in-memory accelerator for upstreams with
    /// `cache_index_in_memory` set. Always present (empty until an
    /// upstream actually opts in) so every `PublishContext` constructor
    /// doesn't need its own decision about whether to build one.
    pub upstream_index_cache: std::sync::Arc<crate::upstream_index_cache::UpstreamIndexCache>,
}

#[derive(Debug, Clone)]
pub struct PublishOutcome {
    pub format: PackageFormat,
    pub name: String,
    pub epoch: u32,
    pub version: String,
    pub release: String,
    pub arch: String,
    pub storage_path: String,
    pub signed: bool,
    pub size_bytes: i64,
    pub sha256: String,
    pub index_group: String,
    /// Index objects written as part of this publish, e.g.
    /// `myrepo/stable/repodata/repomd.xml`.
    pub index_objects: Vec<String>,
}

/// Publishes one package: validate, sign, upload, record, reindex.
///
/// `actor` identifies the publisher for the audit log and for the
/// `published_by_*` columns.
pub async fn publish(
    ctx: &PublishContext,
    repo: &str,
    channel: &str,
    format: PackageFormat,
    bytes: Vec<u8>,
    actor: &Actor,
) -> anyhow::Result<PublishOutcome> {
    publish_with_origin(ctx, repo, channel, format, bytes, actor, None).await
}

/// Identical to [`publish`], except the resulting `packages` row is tagged
/// with the upstream it was pulled through from.
///
/// This is the pull-through cache's only way to persist a fetched
/// artifact — it is deliberately not a separate "just drop the bytes in
/// storage" path, so a cache-mode pull-through inherits the exact same
/// advisory-lock-scoped, DB-driven index regeneration a real publish gets
/// (see the module doc). That's what makes it safe against racing a
/// concurrent real publish, or another concurrent pull-through, to the
/// same index group: both go through one lock, the same way two real
/// publishes already do.
pub async fn publish_with_origin(
    ctx: &PublishContext,
    repo: &str,
    channel: &str,
    format: PackageFormat,
    bytes: Vec<u8>,
    actor: &Actor,
    origin_upstream_id: Option<silo_db::Uuid>,
) -> anyhow::Result<PublishOutcome> {
    validate_repo_name("repo", repo)?;
    validate_repo_name("channel", channel)?;

    // Gives the repo a row (private by default) the moment it's first
    // published to, so its mode has somewhere to live even though nothing
    // else about a repo is stored outside of `packages`.
    ctx.db.ensure_repo(repo).await?;

    let handler = format.handler();
    let parsed = handler
        .parse(&bytes)
        .map_err(|e| anyhow::anyhow!("invalid {format} package: {e}"))?;

    // RPM is signed per-package; apk and npm are not (see `signing`).
    let (payload, signed) = match format {
        PackageFormat::Rpm => maybe_sign_rpm(parsed.payload.clone(), &ctx.signers)?,
        _ => (parsed.payload.clone(), false),
    };

    // Index metadata describes the bytes in the bucket, not the bytes that
    // were uploaded. For a signed RPM those differ — signing rewrites the
    // signature header, moving the header byte range dnf uses for ranged
    // header fetches — so the metadata is re-derived from `payload`.
    let metadata = handler
        .index_metadata(&payload)
        .map_err(|e| anyhow::anyhow!("could not index {format} package: {e}"))?
        .unwrap_or_else(|| parsed.metadata.clone());

    let storage_key = handler.storage_key(repo, channel, &parsed);
    let index_group = handler.index_group(&parsed);
    let sha256 = hex_sha256(&payload);
    let size_bytes = payload.len() as i64;

    let scope = lock::index_scope(repo, channel, format.as_str(), &index_group);
    let mut locked = ctx.db.lock(scope).await?;

    ctx.storage.put(&storage_key, payload).await?;

    let new_package = NewPackage {
        repo: repo.to_string(),
        channel: channel.to_string(),
        format,
        index_group: index_group.clone(),
        name: parsed.name.clone(),
        epoch: parsed.epoch,
        version: parsed.version.clone(),
        release: parsed.release.clone(),
        arch: parsed.arch.clone(),
        filename: parsed.filename.clone(),
        storage_key: storage_key.clone(),
        size_bytes,
        sha256: sha256.clone(),
        metadata,
        published_by_token: actor.token_id,
        published_by_user: actor.user_id,
        origin_upstream_id,
    };
    packages::upsert(locked.conn(), &new_package).await?;

    let mut index_objects =
        regenerate_index_locked(ctx, &mut locked, repo, channel, format, &index_group).await?;

    locked.commit().await?;

    // Publishing into a shared group invalidates every group that borrows
    // from it, so those are rewritten too. Deliberately after the commit
    // rather than inside it: each sibling needs its own advisory lock, and
    // holding several at once across one transaction is how two publishers
    // taking them in different orders deadlock.
    //
    // The cost of doing it afterwards is that a crash in the middle leaves
    // some siblings stale. They are repairable with `silo index rebuild`,
    // and the alternative risks wedging the repo rather than lagging it.
    index_objects.extend(regenerate_sharing_groups(ctx, repo, channel, format, &index_group).await);

    ctx.db
        .record_audit(
            AuditEntry::new(audit::action::PACKAGE_PUBLISH, actor)
                .repo(repo)
                .channel(channel)
                .target(parsed.nevra())
                .detail(json!({
                    "format": format.as_str(),
                    "storage_key": storage_key,
                    "size_bytes": size_bytes,
                    "sha256": sha256,
                    "signed": signed,
                })),
        )
        .await;

    tracing::info!(
        repo, channel, format = %format, package = %parsed.nevra(),
        signed, "published package"
    );

    Ok(PublishOutcome {
        format,
        name: parsed.name,
        epoch: parsed.epoch,
        version: parsed.version,
        release: parsed.release,
        arch: parsed.arch,
        storage_path: storage_key,
        signed,
        size_bytes,
        sha256,
        index_group,
        index_objects,
    })
}

/// Rebuilds one index group from the database, without publishing
/// anything. Used by `silo index rebuild` to repair an index after a
/// bucket restore or a crash mid-publish.
pub async fn regenerate_index(
    ctx: &PublishContext,
    repo: &str,
    channel: &str,
    format: PackageFormat,
    index_group: &str,
    actor: &Actor,
) -> anyhow::Result<Vec<String>> {
    validate_repo_name("repo", repo)?;
    validate_repo_name("channel", channel)?;

    let scope = lock::index_scope(repo, channel, format.as_str(), index_group);
    let mut locked = ctx.db.lock(scope).await?;
    let objects =
        regenerate_index_locked(ctx, &mut locked, repo, channel, format, index_group).await?;
    locked.commit().await?;

    ctx.db
        .record_audit(
            AuditEntry::new(audit::action::INDEX_REGENERATE, actor)
                .repo(repo)
                .channel(channel)
                .target(if index_group.is_empty() {
                    format.as_str().to_string()
                } else {
                    format!("{format}/{index_group}")
                })
                .detail(json!({ "objects": objects.len() })),
        )
        .await;

    Ok(objects)
}

/// The shared body of both entry points. The caller owns the lock, which
/// is what makes reading the group and writing the index atomic with
/// respect to other publishers.
async fn regenerate_index_locked(
    ctx: &PublishContext,
    locked: &mut lock::LockedTx<'_>,
    repo: &str,
    channel: &str,
    format: PackageFormat,
    index_group: &str,
) -> anyhow::Result<Vec<String>> {
    let handler = format.handler();

    // An index group's contents are its own rows plus any it shares with
    // another group. Only apk has any: every architecture's APKINDEX also
    // lists the channel's `noarch` packages.
    let mut groups = vec![index_group.to_string()];
    groups.extend(handler.shared_groups(index_group));
    let rows = packages::list_groups(locked.conn(), repo, channel, format, &groups).await?;
    let mut records: Vec<silo_pkg::PackageRecord> = rows.iter().map(|r| r.to_record()).collect();
    merge_upstream_records(ctx, repo, channel, format, index_group, &mut records).await?;

    let prefix = handler.index_prefix(repo, channel, index_group);

    let objects = handler
        .build_index(&IndexContext {
            repo,
            channel,
            group: index_group,
            records: &records,
            public_base_url: ctx.public_base_url.as_deref(),
            signer: ctx.signers.for_format(format),
        })
        .await?;

    let mut written = Vec::with_capacity(objects.len());
    for object in &objects {
        let key = format!("{prefix}/{}", object.name);
        ctx.storage
            .put_typed(&key, object.bytes.clone(), object.content_type)
            .await?;
        written.push(key);
    }

    // RPM metadata files are named after their own checksums, so every
    // regeneration that changes anything leaves the previous generation
    // behind. Without this sweep an active repo accumulates them
    // indefinitely.
    //
    // The package files are passed in as protected because for apk and npm
    // they live *under the index prefix* — an apk sits next to its
    // APKINDEX, an npm tarball sits under the same package directory as
    // its packument. A sweep that only knew which index objects it had
    // just written would delete the packages themselves.
    let protected: std::collections::HashSet<&str> =
        records.iter().map(|r| r.storage_key.as_str()).collect();
    prune_stale_index_objects(ctx, &prefix, &written, &protected).await;

    Ok(written)
}

/// Rebuilds whichever index group(s) an upstream sync just changed the
/// availability of, so a repo/channel that has *never* had a local
/// publish still gets a real index a client can fetch.
///
/// Without this, [`merge_upstream_records`] would only ever run as a side
/// effect of some *other* publish landing in the same group — a
/// pure-mirror repo, published to only through pull-through, would have
/// no `repodata`/`APKINDEX`/`Release`/`db.tar.gz` at all until then, and
/// `dnf`/`apk`/`apt`/`pacman` all fetch that whole-index file before ever
/// asking for one artifact by name. Called after `add-upstream`,
/// `sync-upstream`, and the periodic sync job.
///
/// npm is excluded: it has no eager index to rebuild (see the `silo-pkg`
/// `npm` module doc) — its packument is rebuilt lazily, per name, on the
/// first request for it (see `silo-server`'s `get_npm`).
pub async fn rebuild_index_for_upstream(
    ctx: &PublishContext,
    repo: &str,
    channel: &str,
    format: PackageFormat,
    arches: &[String],
    actor: &Actor,
) -> anyhow::Result<()> {
    let groups: Vec<String> = match format {
        PackageFormat::Rpm | PackageFormat::Deb => vec![String::new()],
        PackageFormat::Apk | PackageFormat::Pacman => arches.to_vec(),
        PackageFormat::Npm => Vec::new(),
    };
    for group in groups {
        regenerate_index(ctx, repo, channel, format, &group, actor).await?;
    }
    Ok(())
}

/// Folds every configured upstream's synced index into `records` for
/// packages this repo/channel/format doesn't already have locally.
///
/// This is what makes pull-through visible to a client at all: `dnf`/
/// `apk`/`apt`/`pacman`/`npm` only ever request a file their already-
/// downloaded index told them about, so an upstream package has to appear
/// in the rendered index — pointing at the same storage key a real
/// publish of it would use — before a request for it can ever reach the
/// storage-miss path `pull_through` handles. A local row always wins over
/// an upstream one with the same filename (a cached copy is the same
/// bytes either way, so there's nothing to prefer).
async fn merge_upstream_records(
    ctx: &PublishContext,
    repo: &str,
    channel: &str,
    format: PackageFormat,
    index_group: &str,
    records: &mut Vec<silo_pkg::PackageRecord>,
) -> anyhow::Result<()> {
    let upstreams = ctx.db.list_upstreams(repo, channel).await?;
    if upstreams.iter().all(|u| u.format != format.as_str()) {
        return Ok(());
    }
    let handler = format.handler();

    // Tracks every filename already emitted — local rows up front, then
    // each synthetic upstream row as it's pushed — so a repo/channel with
    // several upstreams of the same format (two mirrors of the same
    // distribution, say) can't advertise the same filename twice.
    let mut seen_filenames: std::collections::HashSet<String> =
        records.iter().map(|r| r.filename.clone()).collect();

    // RPM is the one format whose bytes change on capture: signing
    // rewrites the header, which moves the byte range primary.xml points
    // at and changes the file's size/checksum (see `index_metadata`'s own
    // doc). A synthetic entry's checksum is copied from the upstream's
    // *unsigned* index, so if it were merged in and a client fetched the
    // index in that window, the checksum dnf just cached would stop
    // matching the instant a `cache`-mode fetch signs and re-publishes
    // the real file — a checksum-mismatch dnf reports as corruption, not
    // staleness. `no_cache` never mutates bytes (nothing is ever
    // captured), so it isn't affected and keeps merging normally.
    let rpm_signing_would_invalidate_the_checksum =
        format == PackageFormat::Rpm && ctx.signers.gpg.is_some();

    for upstream in upstreams.iter().filter(|u| u.format == format.as_str()) {
        if rpm_signing_would_invalidate_the_checksum && upstream.cache_mode == "cache" {
            continue;
        }
        let synced = upstream_packages_for(ctx, upstream).await?;
        for row in synced.iter() {
            if seen_filenames.contains(&row.filename) {
                continue;
            }
            // Every format but rpm/deb partitions its index by
            // architecture (apk/pacman) or by package name (npm); an
            // upstream entry only belongs in *this* group's index.
            // rpm/deb render every architecture into one group (`""`),
            // so nothing to filter there.
            //
            // A noarch/any upstream package has to fold into every
            // *concrete* architecture's group too, not just its own —
            // apk-tools and pacman each only ever fetch their own host
            // architecture's index and never look in a noarch/any tree of
            // their own accord (see `apk.rs`'s module doc). Local rows
            // get this for free via `Format::shared_groups` when their
            // own group is regenerated; a synthetic upstream row needs
            // the same check applied explicitly, since it never goes
            // through that regeneration path itself.
            let belongs = match format {
                PackageFormat::Apk | PackageFormat::Pacman => {
                    row.arch == index_group
                        || handler.shared_groups(index_group).contains(&row.arch)
                }
                PackageFormat::Npm => row.name == index_group,
                PackageFormat::Rpm | PackageFormat::Deb => true,
            };
            if !belongs {
                continue;
            }
            seen_filenames.insert(row.filename.clone());
            records.push(synthetic_record(format, repo, channel, row));
        }
    }
    Ok(())
}

/// Every synced entry for one upstream, via the opt-in in-memory cache
/// when the upstream has it enabled, falling through to (and repopulating
/// from) the database otherwise. Public so `silo-server`'s pull-through
/// artifact-fetch path reads through the identical cache rather than
/// keeping a second one.
pub async fn upstream_packages_for(
    ctx: &PublishContext,
    upstream: &silo_db::upstreams::UpstreamRow,
) -> anyhow::Result<std::sync::Arc<Vec<silo_db::upstreams::UpstreamPackageRow>>> {
    if upstream.cache_index_in_memory {
        if let Some(cached) = ctx.upstream_index_cache.get(upstream.id) {
            return Ok(cached);
        }
    }
    let rows = std::sync::Arc::new(ctx.db.list_all_upstream_packages(upstream.id).await?);
    if upstream.cache_index_in_memory {
        ctx.upstream_index_cache.put(upstream.id, rows.clone());
    }
    Ok(rows)
}

/// Builds a [`silo_pkg::PackageRecord`] for an unfetched upstream package,
/// with a `storage_key` computed the same way a real publish of it would
/// (via [`Format::storage_key`]) so a client's request for it lands on
/// exactly the object key [`publish_with_origin`] will eventually write.
fn synthetic_record(
    format: PackageFormat,
    repo: &str,
    channel: &str,
    row: &silo_db::upstreams::UpstreamPackageRow,
) -> silo_pkg::PackageRecord {
    let pseudo = silo_pkg::ParsedPackage {
        format,
        name: row.name.clone(),
        epoch: row.epoch.max(0) as u32,
        version: row.version.clone(),
        release: row.release.clone(),
        arch: row.arch.clone(),
        filename: row.filename.clone(),
        metadata: serde_json::Value::Null,
        payload: Vec::new(),
    };
    let storage_key = format.handler().storage_key(repo, channel, &pseudo);

    silo_pkg::PackageRecord {
        format,
        name: row.name.clone(),
        epoch: row.epoch.max(0) as u32,
        version: row.version.clone(),
        release: row.release.clone(),
        arch: row.arch.clone(),
        filename: row.filename.clone(),
        storage_key,
        size_bytes: row.size_bytes.unwrap_or(0),
        sha256: row.sha256.clone().unwrap_or_default(),
        metadata: synthetic_metadata(format, row),
        published_at: row.synced_at.timestamp(),
    }
}

/// Every format's `build_index` reads `record.metadata` for whatever the
/// index needs beyond the common columns. For a package silo hasn't
/// fetched yet, only what the upstream's own index stated is known — real
/// rpm dependency/file-list data, for instance, only exists once the
/// actual package has been parsed. rpm's `build_index` additionally
/// *requires* its metadata to deserialize into a full `RepodataEntry`
/// (see `rpm.rs`), so this fills every field the schema needs with an
/// empty/zero default rather than the specifics only a real fetch would
/// reveal — a synthesized rpm entry renders with no dependencies or file
/// list until it's actually pulled through once.
fn synthetic_metadata(
    format: PackageFormat,
    row: &silo_db::upstreams::UpstreamPackageRow,
) -> serde_json::Value {
    match format {
        PackageFormat::Rpm => serde_json::json!({
            "name": row.name,
            "arch": row.arch,
            "epoch": row.epoch.max(0) as u32,
            "version": row.version,
            "release": row.release,
            "summary": "",
            "description": "",
            "packager": "",
            "url": "",
            "license": "",
            "vendor": "",
            "group": "",
            "build_host": "",
            "source_rpm": "",
            "build_time": 0,
            "installed_size": 0,
            "archive_size": row.size_bytes.unwrap_or(0).max(0),
            "header_start": 0,
            "header_end": 0,
            "files": [],
            "provides": [],
            "requires": [],
            "conflicts": [],
            "obsoletes": [],
            "recommends": [],
            "suggests": [],
            "supplements": [],
            "enhances": [],
            "changelogs": [],
        }),
        _ => row.metadata.clone(),
    }
}

/// Rewrites every group that borrows from `changed`, if `changed` is a
/// group other groups borrow from at all.
///
/// Failures are logged rather than propagated. The publish that triggered
/// this has already committed and its own index is correct; failing it now
/// would report an error for work that succeeded, and the repair is the
/// same either way (`silo index rebuild`).
async fn regenerate_sharing_groups(
    ctx: &PublishContext,
    repo: &str,
    channel: &str,
    format: PackageFormat,
    changed: &str,
) -> Vec<String> {
    if !format.handler().is_shared_group(changed) {
        return Vec::new();
    }

    let groups = match packages::list_index_groups(ctx.db.pool(), repo, channel, format).await {
        Ok(groups) => groups,
        Err(e) => {
            tracing::warn!(
                error = %e, repo, channel, %format,
                "could not list index groups; groups sharing {changed} may be stale"
            );
            return Vec::new();
        }
    };

    let mut written = Vec::new();
    for group in groups.iter().filter(|g| g.as_str() != changed) {
        match regenerate_index(ctx, repo, channel, format, group, &Actor::system()).await {
            Ok(objects) => written.extend(objects),
            Err(e) => tracing::warn!(
                error = %e, repo, channel, %format, group,
                "failed to refresh an index sharing {changed}; run `silo index rebuild`"
            ),
        }
    }
    written
}

/// Deletes superseded index objects under an index prefix.
///
/// Two guards keep this from eating live data, because for apk and npm the
/// package files share the index's prefix:
///
/// 1. `protected` holds every package key the group currently has, so a
///    package sitting beside its index is never a deletion candidate.
/// 2. Only *immediate* children of the prefix are considered. Index
///    renderers only ever write immediate children, so anything nested
///    deeper (an npm tarball under `.../{name}/-/`) belongs to something
///    else.
///
/// Failures are logged, not propagated: leaving a stale object behind is
/// untidy, but failing a publish that already succeeded is worse.
async fn prune_stale_index_objects(
    ctx: &PublishContext,
    prefix: &str,
    keep: &[String],
    protected: &std::collections::HashSet<&str>,
) {
    let existing = match ctx.storage.list(prefix).await {
        Ok(keys) => keys,
        Err(e) => {
            tracing::warn!(error = %e, prefix, "could not list index prefix to prune stale objects");
            return;
        }
    };
    for key in existing {
        if keep.iter().any(|k| k == &key) || protected.contains(key.as_str()) {
            continue;
        }
        if !is_immediate_child(prefix, &key) {
            continue;
        }
        if let Err(e) = ctx.storage.delete(&key).await {
            tracing::warn!(error = %e, key, "failed to delete stale index object");
        }
    }
}

/// Removes a package and rebuilds the index without it.
///
/// `reason` is merged into the audit entry's `detail` (e.g.
/// `Some(json!({"reason": "prune", "rule": "keep_last_n"}))` for a
/// prune-triggered delete) so `package.delete` stays the one action name
/// for "a package row is gone," with `detail` carrying why. `None` for an
/// ordinary manual delete.
pub async fn delete_package(
    ctx: &PublishContext,
    id: i64,
    actor: &Actor,
    reason: Option<serde_json::Value>,
) -> anyhow::Result<Option<String>> {
    let Some(row) = ctx.db.delete_package(id).await? else {
        return Ok(None);
    };
    let format: PackageFormat = row.format.parse().unwrap_or(PackageFormat::Rpm);

    ctx.storage.delete(&row.storage_key).await?;
    regenerate_index(
        ctx,
        &row.repo,
        &row.channel,
        format,
        &row.index_group,
        &Actor::system(),
    )
    .await?;
    // Removing a noarch apk has to take it out of every architecture's
    // index too, not just the noarch one.
    regenerate_sharing_groups(ctx, &row.repo, &row.channel, format, &row.index_group).await;

    let mut detail = json!({ "storage_key": row.storage_key });
    if let Some(reason) = reason {
        if let (Some(detail), Some(reason)) = (detail.as_object_mut(), reason.as_object()) {
            detail.extend(reason.clone());
        }
    }

    ctx.db
        .record_audit(
            AuditEntry::new(audit::action::PACKAGE_DELETE, actor)
                .repo(&row.repo)
                .channel(&row.channel)
                .target(&row.filename)
                .detail(detail),
        )
        .await;

    Ok(Some(row.storage_key))
}

/// True when `key` sits directly under `prefix` with no further nesting.
fn is_immediate_child(prefix: &str, key: &str) -> bool {
    let prefix = prefix.trim_end_matches('/');
    match key
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('/'))
    {
        Some(rest) => !rest.is_empty() && !rest.contains('/'),
        None => false,
    }
}

fn hex_sha256(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The single place the RPM object-storage paths are spelled out for
/// callers that don't have a `ParsedPackage` in hand — the HTTP surface
/// builds its keys from URL segments.
pub use silo_pkg::rpm::{packages_prefix, repodata_prefix};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_is_lowercase_hex_of_the_expected_length() {
        let digest = hex_sha256(b"hello");
        assert_eq!(digest.len(), 64);
        assert_eq!(
            digest,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert!(digest
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    #[test]
    fn empty_input_hashes_to_the_known_empty_digest() {
        assert_eq!(
            hex_sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn rpm_layout_helpers_stay_namespaced_by_repo_and_channel() {
        assert_eq!(
            packages_prefix("myrepo", "stable"),
            "myrepo/stable/Packages"
        );
        assert_eq!(
            repodata_prefix("myrepo", "stable"),
            "myrepo/stable/repodata"
        );
    }

    #[test]
    fn immediate_children_are_distinguished_from_nested_keys() {
        let prefix = "r/c/npm/widget";
        assert!(is_immediate_child(prefix, "r/c/npm/widget/packument.json"));
        // An npm tarball lives one level deeper and must survive pruning.
        assert!(!is_immediate_child(
            prefix,
            "r/c/npm/widget/-/widget-1.0.0.tgz"
        ));
        // A sibling package sharing a name prefix is not a child at all.
        assert!(!is_immediate_child(prefix, "r/c/npm/widget-other/x.json"));
        assert!(!is_immediate_child(prefix, "r/c/npm/widget"));
        assert!(!is_immediate_child(prefix, "somewhere/else"));
        // A trailing slash on the prefix must not change the answer.
        assert!(is_immediate_child(
            "r/c/npm/widget/",
            "r/c/npm/widget/packument.json"
        ));
    }

    #[test]
    fn apk_packages_sit_beside_their_index_so_they_need_protecting() {
        // This is the shape that made pruning delete live packages: an apk
        // is an immediate child of the same prefix its APKINDEX is written
        // to, so `keep` alone would not have spared it.
        let prefix = "r/edge/apk/x86_64";
        assert!(is_immediate_child(
            prefix,
            "r/edge/apk/x86_64/APKINDEX.tar.gz"
        ));
        assert!(is_immediate_child(
            prefix,
            "r/edge/apk/x86_64/hello-1.0-r0.apk"
        ));
    }

    #[test]
    fn publish_rejects_names_that_would_escape_their_prefix() {
        // These are checked before anything touches storage or the
        // database, so the assertion is on the validator the flow calls.
        assert!(validate_repo_name("repo", "../etc").is_err());
        assert!(validate_repo_name("channel", "stable/../../x").is_err());
        assert!(validate_repo_name("repo", "ok-name").is_ok());
    }
}
