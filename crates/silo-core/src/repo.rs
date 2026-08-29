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
    let records: Vec<silo_pkg::PackageRecord> = rows.iter().map(|r| r.to_record()).collect();

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
pub async fn delete_package(
    ctx: &PublishContext,
    id: i64,
    actor: &Actor,
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

    ctx.db
        .record_audit(
            AuditEntry::new(audit::action::PACKAGE_DELETE, actor)
                .repo(&row.repo)
                .channel(&row.channel)
                .target(&row.filename)
                .detail(json!({ "storage_key": row.storage_key })),
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
