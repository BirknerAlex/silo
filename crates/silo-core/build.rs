//! Stamps build provenance into the binary.
//!
//! The version itself comes from Cargo, so it needs no help. What Cargo
//! can't tell us is *which* build of a given version is running — the
//! thing you actually want when a bug reproduces on one replica and not
//! another, or when a `latest` tag has drifted from the commit you think
//! you deployed.
//!
//! Everything here degrades to `"unknown"` rather than failing the build:
//! source tarballs and container builds that copy in a `.git`-less tree
//! are normal, and refusing to compile in that case would be worse than
//! not knowing the commit.

use std::process::Command;

fn main() {
    // A commit is only meaningful if the tree matches it, so a dirty
    // worktree is marked rather than quietly reported as the commit it
    // no longer is.
    let sha = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    let dirty = git(&["status", "--porcelain"]).is_some_and(|out| !out.is_empty());
    let commit = if dirty { format!("{sha}-dirty") } else { sha };
    println!("cargo:rustc-env=SILO_GIT_COMMIT={commit}");

    // `SOURCE_DATE_EPOCH` is the cross-ecosystem convention for
    // reproducible builds; honouring it lets a release pipeline produce
    // byte-identical binaries. Falling back to the commit date rather than
    // to "now" keeps rebuilds of the same source stable by default.
    let built_at = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| git(&["log", "-1", "--format=%cI"]))
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=SILO_BUILT_AT={built_at}");

    // Rebuild when HEAD moves, but do not try to track the worktree's
    // cleanliness — that would mean rebuilding this crate on every edit
    // anywhere in the repo.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
}

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8(output.stdout).ok()?.trim().to_string())
}
