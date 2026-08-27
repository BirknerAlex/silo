//! The one place silo's version is defined.
//!
//! Every binary and every surface that reports a version reads it from
//! here: the server's startup log, the `/version` HTTP endpoint, the
//! `GetVersion` RPC, and `silo version` in the CLI. The value itself comes
//! from the workspace's `Cargo.toml` through Cargo, so a release is a
//! single version bump rather than a hunt for string literals.
//!
//! `commit` and `built_at` are stamped by this crate's `build.rs`; see
//! there for why they can be `"unknown"`.

use serde::{Deserialize, Serialize};

/// The crate version, which is the workspace version, which is silo's
/// version. `silo-core` is a dependency of every binary in the workspace,
/// so this is the same number everywhere.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Short git commit the binary was built from, with a `-dirty` suffix when
/// the worktree had uncommitted changes. `"unknown"` when built outside a
/// git checkout.
pub const GIT_COMMIT: &str = env!("SILO_GIT_COMMIT");

/// RFC 3339 timestamp, or a `SOURCE_DATE_EPOCH` value when one was set.
pub const BUILT_AT: &str = env!("SILO_BUILT_AT");

/// Version and provenance of a running silo, as reported over the wire.
///
/// Used for both ends of `silo version`, which is why it round-trips
/// through serde: the client renders its own and the server's with the
/// same code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildInfo {
    pub version: String,
    pub commit: String,
    pub built_at: String,
}

impl BuildInfo {
    /// This binary's own build info.
    pub fn current() -> Self {
        Self {
            version: VERSION.to_string(),
            commit: GIT_COMMIT.to_string(),
            built_at: BUILT_AT.to_string(),
        }
    }

    /// One-line form for logs and terse CLI output, e.g.
    /// `0.2.0 (a1b2c3d4e5f6)`. The commit is omitted when unknown rather
    /// than printed as the word "unknown", which reads like a value.
    pub fn short(&self) -> String {
        if self.commit.is_empty() || self.commit == "unknown" {
            self.version.clone()
        } else {
            format!("{} ({})", self.version, self.commit)
        }
    }
}

impl Default for BuildInfo {
    fn default() -> Self {
        Self::current()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_version_is_the_crate_version() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert!(!VERSION.is_empty());
        // Reported over the wire and compared by clients, so it has to be
        // a plain semver-shaped string, not a description.
        assert!(VERSION.split('.').count() >= 3, "got: {VERSION}");
    }

    #[test]
    fn build_stamps_are_always_present() {
        // They may say "unknown", but they are never empty — a client
        // rendering them should not have to handle a blank field.
        assert!(!GIT_COMMIT.is_empty());
        assert!(!BUILT_AT.is_empty());
    }

    #[test]
    fn short_form_drops_an_unknown_commit() {
        let info = BuildInfo {
            version: "1.2.3".into(),
            commit: "unknown".into(),
            built_at: "unknown".into(),
        };
        assert_eq!(info.short(), "1.2.3");

        let info = BuildInfo {
            commit: "abc123def456".into(),
            ..info
        };
        assert_eq!(info.short(), "1.2.3 (abc123def456)");
    }

    #[test]
    fn build_info_round_trips_through_json() {
        let info = BuildInfo::current();
        let json = serde_json::to_string(&info).unwrap();
        assert_eq!(serde_json::from_str::<BuildInfo>(&json).unwrap(), info);
    }
}
