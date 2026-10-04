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

use futures::{StreamExt, TryStreamExt};
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
    verify_tree_in_storage(ctx, repo, channel, &parsed_commit).await?;

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
    )
    .await
}

/// Walks a commit's tree through object storage, failing on the first
/// object that is missing or malformed.
async fn verify_tree_in_storage(
    ctx: &PublishContext,
    repo: &str,
    channel: &str,
    commit: &Commit,
) -> anyhow::Result<()> {
    let mut walk = TreeWalk::new(commit);
    loop {
        let mut batch = Vec::new();
        while batch.len() < TREE_FETCH_CONCURRENCY {
            match walk.next_wanted() {
                Some(want) => batch.push(want),
                None => break,
            }
        }
        if batch.is_empty() {
            return Ok(());
        }

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
