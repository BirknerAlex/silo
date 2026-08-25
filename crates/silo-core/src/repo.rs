//! Repo/channel layout and the publish orchestration flow.
//!
//! Storage layout (RPM only for now — a future format gets its own layout
//! function, since deb's dists/pool structure has nothing in common with
//! this one; there's no shared abstraction worth forcing here):
//!   {repo}/{channel}/Packages/{filename}
//!   {repo}/{channel}/repodata/...

use std::path::Path;

use silo_rpm::ParsedPackage;

use crate::config::GpgConfig;
use crate::repodata;
use crate::signing;
use crate::storage::Storage;

pub fn packages_prefix(repo: &str, channel: &str) -> String {
    format!("{repo}/{channel}/Packages")
}

pub fn repodata_prefix(repo: &str, channel: &str) -> String {
    format!("{repo}/{channel}/repodata")
}

pub struct PublishOutcome {
    pub storage_path: String,
    pub signed: bool,
}

/// Publishes one already-validated package: sign (if configured), upload
/// to S3, then regenerate and re-upload repodata for the whole repo/channel.
///
/// No locking: concurrent publishes to the same repo/channel can race on
/// the repodata regeneration step (last write to `repodata/` wins). This
/// is an accepted MVP limitation — see README — not something this
/// function tries to work around.
pub async fn publish(
    storage: &Storage,
    repo: &str,
    channel: &str,
    parsed: ParsedPackage,
    gpg: Option<&GpgConfig>,
) -> anyhow::Result<PublishOutcome> {
    let (bytes, signed) = signing::maybe_sign(parsed.payload, gpg)?;

    let storage_path = format!("{}/{}", packages_prefix(repo, channel), parsed.filename);
    storage.put(&storage_path, bytes).await?;

    regenerate_repodata(storage, repo, channel).await?;

    Ok(PublishOutcome {
        storage_path,
        signed,
    })
}

/// Downloads every package + any existing repodata for a repo/channel into
/// a scratch dir, runs `createrepo_c`, then uploads the resulting
/// `repodata/` tree back to S3.
async fn regenerate_repodata(storage: &Storage, repo: &str, channel: &str) -> anyhow::Result<()> {
    let scratch = tempfile::tempdir()?;
    let pkg_dir = scratch.path().join("Packages");
    std::fs::create_dir_all(&pkg_dir)?;

    for key in storage.list(&packages_prefix(repo, channel)).await? {
        if let Some(bytes) = storage.get(&key).await? {
            let filename = Path::new(&key).file_name().unwrap();
            std::fs::write(pkg_dir.join(filename), bytes)?;
        }
    }

    let repodata_dir = scratch.path().join("repodata");
    for key in storage.list(&repodata_prefix(repo, channel)).await? {
        if let Some(bytes) = storage.get(&key).await? {
            std::fs::create_dir_all(&repodata_dir)?;
            let filename = Path::new(&key).file_name().unwrap();
            std::fs::write(repodata_dir.join(filename), bytes)?;
        }
    }

    repodata::generate(scratch.path()).await?;

    let regenerated_dir = scratch.path().join("repodata");
    let prefix = repodata_prefix(repo, channel);
    for entry in std::fs::read_dir(&regenerated_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let bytes = std::fs::read(entry.path())?;
        let key = format!("{prefix}/{}", entry.file_name().to_string_lossy());
        storage.put(&key, bytes).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use silo_rpm::PackageFormat;

    fn fake_package(filename: &str) -> ParsedPackage {
        ParsedPackage {
            format: PackageFormat::Rpm,
            name: "foo".into(),
            epoch: 0,
            version: "1.0".into(),
            release: "1".into(),
            arch: "x86_64".into(),
            filename: filename.into(),
            payload: b"fake rpm bytes".to_vec(),
        }
    }

    #[test]
    fn layout_paths_are_namespaced_by_repo_and_channel() {
        assert_eq!(
            packages_prefix("myrepo", "stable"),
            "myrepo/stable/Packages"
        );
        assert_eq!(
            repodata_prefix("myrepo", "stable"),
            "myrepo/stable/repodata"
        );
    }

    #[tokio::test]
    async fn publish_uploads_package_and_attempts_repodata_regen() {
        let storage = Storage::in_memory();
        let pkg = fake_package("foo-1.0-1.x86_64.rpm");

        if !repodata::is_available() {
            eprintln!("skipping: createrepo_c not installed on this machine");
            return;
        }

        let outcome = publish(&storage, "myrepo", "stable", pkg, None)
            .await
            .unwrap();
        assert_eq!(
            outcome.storage_path,
            "myrepo/stable/Packages/foo-1.0-1.x86_64.rpm"
        );
        assert!(!outcome.signed);

        let uploaded = storage.get(&outcome.storage_path).await.unwrap();
        assert_eq!(uploaded, Some(b"fake rpm bytes".to_vec()));

        let repomd = storage
            .get("myrepo/stable/repodata/repomd.xml")
            .await
            .unwrap();
        assert!(repomd.is_some());
    }
}
