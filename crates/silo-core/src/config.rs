use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub grpc_addr: String,
    pub http_addr: String,
    pub storage: StorageConfig,
    pub auth: AuthConfig,
    #[serde(default)]
    pub gpg: Option<GpgConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StorageConfig {
    pub bucket: String,
    /// S3-compatible endpoint (e.g. MinIO). Omit for real AWS S3.
    #[serde(default)]
    pub endpoint: Option<String>,
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    /// Required when pointing at a non-TLS endpoint (e.g. local MinIO).
    #[serde(default)]
    pub allow_http: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    pub publish_token: String,
    pub read_token: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GpgConfig {
    /// Inline armored secret key. Mutually exclusive with `key_path`.
    #[serde(default)]
    pub key: Option<String>,
    /// Path to an armored secret key file. Mutually exclusive with `key`.
    #[serde(default)]
    pub key_path: Option<String>,
    #[serde(default)]
    pub passphrase: Option<String>,
}

impl GpgConfig {
    pub fn resolve_key(&self) -> anyhow::Result<String> {
        match (&self.key, &self.key_path) {
            (Some(k), None) => Ok(k.clone()),
            (None, Some(path)) => Ok(std::fs::read_to_string(path)?),
            (Some(_), Some(_)) => {
                anyhow::bail!("gpg config must set exactly one of `key` or `key_path`, not both")
            }
            (None, None) => anyhow::bail!("gpg config requires `key` or `key_path`"),
        }
    }
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        let cfg: Config = serde_yaml::from_str(&raw)?;
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_config() {
        let yaml = r#"
grpc_addr: "0.0.0.0:9090"
http_addr: "0.0.0.0:8080"
storage:
  bucket: "silo"
  region: "us-east-1"
  access_key_id: "key"
  secret_access_key: "secret"
auth:
  publish_token: "pub-token"
  read_token: "read-token"
"#;
        let cfg: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.storage.bucket, "silo");
        assert!(cfg.gpg.is_none());
        assert!(!cfg.storage.allow_http);
    }

    #[test]
    fn gpg_key_and_key_path_are_mutually_exclusive() {
        let gpg = GpgConfig {
            key: Some("abc".into()),
            key_path: Some("/tmp/key.asc".into()),
            passphrase: None,
        };
        assert!(gpg.resolve_key().is_err());
    }

    #[test]
    fn gpg_requires_a_key_source() {
        let gpg = GpgConfig {
            key: None,
            key_path: None,
            passphrase: None,
        };
        assert!(gpg.resolve_key().is_err());
    }
}
