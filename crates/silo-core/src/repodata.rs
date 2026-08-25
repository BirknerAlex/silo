//! Shells out to the `createrepo_c` CLI to (re)generate RPM repodata.
//!
//! We deliberately don't reimplement repomd.xml/primary/filelists/other —
//! it's a fiddly, well-specified format already owned by a battle-tested
//! tool. The runtime image is expected to ship `createrepo_c`.

use std::path::Path;
use std::process::Stdio;

use thiserror::Error;
use tokio::process::Command;

#[derive(Debug, Error)]
pub enum RepodataError {
    #[error("failed to spawn createrepo_c: {0}")]
    Spawn(#[source] std::io::Error),
    #[error("createrepo_c exited with status {status}: {stderr}")]
    NonZeroExit { status: i32, stderr: String },
}

/// Runs `createrepo_c --update <dir>` (falling back to a full run if no
/// prior repodata exists) against a local directory. The caller is
/// responsible for syncing packages/repodata to and from S3 around this call.
pub async fn generate(dir: &Path) -> Result<(), RepodataError> {
    let has_existing_repodata = dir.join("repodata").join("repomd.xml").exists();

    let mut cmd = Command::new("createrepo_c");
    if has_existing_repodata {
        cmd.arg("--update");
    }
    cmd.arg(dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = cmd.output().await.map_err(RepodataError::Spawn)?;
    if !output.status.success() {
        return Err(RepodataError::NonZeroExit {
            status: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(())
}

/// True if the `createrepo_c` binary is on PATH. Integration tests that
/// need a real repodata run gate on this rather than failing outright,
/// since the tool isn't packaged for every dev machine (e.g. macOS).
pub fn is_available() -> bool {
    std::process::Command::new("createrepo_c")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[tokio::test]
    async fn generates_repodata_for_a_directory_of_packages() {
        if !is_available() {
            eprintln!("skipping: createrepo_c not installed on this machine");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        // createrepo_c works fine against an empty package dir.
        generate(dir.path()).await.unwrap();
        assert!(dir.path().join("repodata").join("repomd.xml").exists());
    }

    #[tokio::test]
    async fn update_mode_used_when_repodata_already_exists() {
        if !is_available() {
            eprintln!("skipping: createrepo_c not installed on this machine");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        generate(dir.path()).await.unwrap();
        // second run should hit the --update path without erroring
        fs::write(dir.path().join("stray.txt"), b"not a package").unwrap();
        generate(dir.path()).await.unwrap();
        assert!(dir.path().join("repodata").join("repomd.xml").exists());
    }

    #[tokio::test]
    async fn missing_binary_surfaces_as_error() {
        // Only meaningful when createrepo_c truly isn't on PATH; skip on
        // machines that have it installed since we can't shadow PATH safely
        // for a single command in a shared test binary.
        if is_available() {
            eprintln!("skipping: createrepo_c is installed on this machine");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let err = generate(dir.path()).await.unwrap_err();
        assert!(matches!(err, RepodataError::Spawn(_)));
    }
}
