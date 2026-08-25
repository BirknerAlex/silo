use serde::Deserialize;

/// Client-side config: just where the server is and which tokens to use.
/// The CLI never sees S3 credentials or the GPG key — those live only in
/// the server's config.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    pub server_addr: String,
    #[serde(default)]
    pub publish_token: Option<String>,
    #[serde(default)]
    pub read_token: Option<String>,
}

impl ClientConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read client config at {path}: {e}"))?;
        Ok(serde_yaml::from_str(&raw)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_client_config() {
        let yaml = r#"
server_addr: "http://localhost:9090"
publish_token: "tok"
"#;
        let cfg: ClientConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.server_addr, "http://localhost:9090");
        assert_eq!(cfg.publish_token.as_deref(), Some("tok"));
        assert_eq!(cfg.read_token, None);
    }
}
