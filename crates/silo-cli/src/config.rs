//! Client configuration and credential storage.
//!
//! The CLI's config is deliberately tiny: where the server is, and the one
//! token to present. It never holds object-storage credentials, signing
//! keys, or the database URL — those exist only in the server's config,
//! and keeping the two files disjoint is what makes it safe to hand this
//! one to anybody who needs to publish.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ClientConfig {
    pub server_addr: String,

    /// The token presented on every call. Written here by `silo login`;
    /// can also be supplied out-of-band via `SILO_TOKEN`, which is what CI
    /// should do rather than materializing a config file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,

    /// Set when the token came from `silo login`, so the CLI can say
    /// "your session expired, run silo login" instead of "unauthenticated".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_expires_at: Option<i64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// Pre-database configs put a token per operation here. Kept only so
    /// loading one produces an explanation rather than a puzzling
    /// "missing token" error.
    #[serde(default, skip_serializing)]
    pub publish_token: Option<String>,
    #[serde(default, skip_serializing)]
    pub read_token: Option<String>,
}

impl ClientConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path).map_err(|e| {
            anyhow::anyhow!(
                "failed to read client config at {path}: {e}\n\
                 Run `silo login --server <addr>` to create one."
            )
        })?;
        let config: ClientConfig = serde_yaml::from_str(&raw)?;
        config.check_deprecated()?;
        Ok(config)
    }

    /// Loads if present, otherwise returns an empty config. Used by
    /// `login`, which has to work before a config exists.
    pub fn load_or_default(path: &str) -> anyhow::Result<Self> {
        if !Path::new(path).exists() {
            return Ok(Self::default());
        }
        Self::load(path)
    }

    fn check_deprecated(&self) -> anyhow::Result<()> {
        if self.publish_token.is_some() || self.read_token.is_some() {
            anyhow::bail!(
                "`publish_token`/`read_token` are no longer used — silo now issues a single \
                 scoped token per credential. Replace them with `token:`, or run `silo login`."
            );
        }
        Ok(())
    }

    /// Writes the config with owner-only permissions.
    ///
    /// The file holds a bearer token, so the permission bits are part of
    /// the contract, not a nicety — and they're set *before* the token is
    /// written, so there's no window where a fresh file is world-readable.
    pub fn save(&self, path: &str) -> anyhow::Result<()> {
        let path = PathBuf::from(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| anyhow::anyhow!("failed to create {}: {e}", parent.display()))?;
        }

        let yaml = serde_yaml::to_string(self)?;
        write_private(&path, yaml.as_bytes())
            .map_err(|e| anyhow::anyhow!("failed to write {}: {e}", path.display()))?;
        Ok(())
    }

    /// Resolves the token to use: `SILO_TOKEN` wins, so CI can override a
    /// developer's logged-in credential without editing files.
    pub fn resolve_token(&self) -> anyhow::Result<String> {
        if let Ok(token) = std::env::var("SILO_TOKEN") {
            if !token.trim().is_empty() {
                return Ok(token.trim().to_string());
            }
        }
        self.token.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "no token configured — run `silo login`, or set SILO_TOKEN in the environment"
            )
        })
    }

    /// A human-readable warning when a saved session is past its expiry.
    /// Checked client-side purely so the error names the fix; the server
    /// is what actually enforces it.
    pub fn expiry_warning(&self) -> Option<String> {
        let expires_at = self.token_expires_at?;
        if expires_at == 0 {
            return None;
        }
        let now = chrono::Utc::now().timestamp();
        if expires_at <= now {
            return Some("your saved session has expired — run `silo login` again".to_string());
        }
        None
    }
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    // No mode bits to set; on Windows the file inherits the user profile
    // directory's ACL, which is already owner-scoped.
    std::fs::write(path, bytes)
}

/// Expands `~` and resolves the default location.
pub fn resolve_path(path: &str) -> String {
    shellexpand::tilde(path).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_minimal_config() {
        let cfg: ClientConfig = serde_yaml::from_str(
            "server_addr: \"http://localhost:9090\"\ntoken: \"silo_abc_def\"\n",
        )
        .unwrap();
        assert_eq!(cfg.server_addr, "http://localhost:9090");
        assert_eq!(cfg.token.as_deref(), Some("silo_abc_def"));
    }

    #[test]
    fn rejects_the_pre_database_two_token_config() {
        let cfg: ClientConfig = serde_yaml::from_str(
            "server_addr: \"http://localhost:9090\"\npublish_token: \"x\"\nread_token: \"y\"\n",
        )
        .unwrap();
        let err = cfg.check_deprecated().unwrap_err().to_string();
        assert!(err.contains("silo login"), "got: {err}");
    }

    /// Every assertion that touches `SILO_TOKEN` lives in this one test.
    /// The variable is process-global and Rust runs tests in parallel, so
    /// splitting them across several tests makes them race each other.
    #[test]
    fn silo_token_is_the_credential_a_pipeline_uses() {
        struct Restore;
        impl Drop for Restore {
            fn drop(&mut self) {
                std::env::remove_var("SILO_TOKEN");
            }
        }
        let _restore = Restore;

        let cfg = ClientConfig {
            token: Some("from-file".into()),
            ..Default::default()
        };

        std::env::remove_var("SILO_TOKEN");
        assert_eq!(cfg.resolve_token().unwrap(), "from-file");

        // The env var wins, so CI can override a developer's logged-in
        // credential without editing files.
        std::env::set_var("SILO_TOKEN", "from-env");
        assert_eq!(cfg.resolve_token().unwrap(), "from-env");

        std::env::set_var("SILO_TOKEN", "   ");
        assert_eq!(
            cfg.resolve_token().unwrap(),
            "from-file",
            "a blank env var must not shadow the config"
        );

        // A pipeline needs no config file at all: the env var plus a
        // server address is a complete credential.
        std::env::set_var("SILO_TOKEN", "silo_ci_token");
        let empty = ClientConfig::load_or_default("/nonexistent/silo/client.yaml").unwrap();
        assert_eq!(empty.resolve_token().unwrap(), "silo_ci_token");

        // ...and with neither, the error names both ways to fix it.
        std::env::remove_var("SILO_TOKEN");
        let err = empty.resolve_token().unwrap_err().to_string();
        assert!(err.contains("silo login"), "got: {err}");
        assert!(err.contains("SILO_TOKEN"), "got: {err}");
    }

    #[test]
    fn expiry_warning_only_fires_after_the_expiry() {
        let mut cfg = ClientConfig::default();
        assert!(cfg.expiry_warning().is_none(), "no expiry recorded");

        cfg.token_expires_at = Some(chrono::Utc::now().timestamp() + 3600);
        assert!(cfg.expiry_warning().is_none());

        cfg.token_expires_at = Some(chrono::Utc::now().timestamp() - 1);
        assert!(cfg.expiry_warning().unwrap().contains("silo login"));

        // 0 is the wire sentinel for "never expires".
        cfg.token_expires_at = Some(0);
        assert!(cfg.expiry_warning().is_none());
    }

    #[test]
    fn saved_configs_round_trip_without_the_deprecated_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("client.yaml");
        let path = path.to_str().unwrap();

        let cfg = ClientConfig {
            server_addr: "http://silo:9090".into(),
            token: Some("silo_a_b".into()),
            token_expires_at: Some(123),
            username: Some("alice".into()),
            publish_token: Some("should not be written".into()),
            read_token: None,
        };
        cfg.save(path).unwrap();

        let loaded = ClientConfig::load(path).unwrap();
        assert_eq!(loaded.token.as_deref(), Some("silo_a_b"));
        assert_eq!(loaded.username.as_deref(), Some("alice"));
        assert_eq!(loaded.token_expires_at, Some(123));
        assert!(
            loaded.publish_token.is_none(),
            "deprecated keys must not be persisted back out"
        );
    }

    #[cfg(unix)]
    #[test]
    fn saved_configs_are_not_readable_by_other_users() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.yaml");
        let path_str = path.to_str().unwrap();

        ClientConfig {
            server_addr: "http://silo:9090".into(),
            token: Some("secret".into()),
            ..Default::default()
        }
        .save(path_str)
        .unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "config holds a bearer token");
    }

    #[test]
    fn load_or_default_tolerates_a_missing_file() {
        let cfg = ClientConfig::load_or_default("/nonexistent/silo/client.yaml").unwrap();
        assert!(cfg.server_addr.is_empty());
        assert!(cfg.token.is_none());
    }

    #[test]
    fn tilde_is_expanded_in_config_paths() {
        let expanded = resolve_path("~/.config/silo/client.yaml");
        assert!(!expanded.starts_with('~'));
        assert!(expanded.ends_with(".config/silo/client.yaml"));
    }
}
