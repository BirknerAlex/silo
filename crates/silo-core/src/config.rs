//! Server configuration.
//!
//! Everything here is server-only. The CLI has its own, much smaller
//! config — it never sees object-storage credentials, signing keys, the
//! database URL, or the token pepper.

use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// The single address gRPC and HTTP both listen on. Requests are
    /// dispatched by path, not by a separate port: gRPC methods live
    /// under their fully-qualified service name (`/silo.v1.*`), which
    /// never collides with the package-manager routes, and the
    /// underlying connection is protocol-sniffed per request so HTTP/1.1
    /// and h2c share one listener.
    pub addr: String,

    /// Absolute URL clients reach this server on, e.g.
    /// `https://silo.example.com`. Only npm strictly needs it (packuments
    /// must carry absolute tarball URLs); when unset, the URL is derived
    /// per-request from `Host`/`X-Forwarded-*`, which is correct behind a
    /// well-behaved proxy and is why this stays optional.
    #[serde(default)]
    pub public_base_url: Option<String>,

    pub database: DatabaseConfig,
    pub storage: StorageConfig,

    #[serde(default)]
    pub auth: AuthConfig,

    /// Optional single sign-on. Local password accounts keep working
    /// alongside it unless `oidc.exclusive` is set.
    #[serde(default)]
    pub oidc: Option<OidcConfig>,

    #[serde(default)]
    pub signing: SigningConfig,

    #[serde(default)]
    pub audit: AuditConfig,

    #[serde(default)]
    pub metrics: MetricsConfig,

    #[serde(default)]
    pub prune: PruneConfig,

    #[serde(default)]
    pub jobs: JobsConfig,

    /// Required only once an upstream with a credential is configured —
    /// see `silo_core::secret_box`. Absent, `add-upstream`/`update-upstream`
    /// reject any request that sets `auth`.
    #[serde(default)]
    pub upstream_secret: Option<UpstreamSecretConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    /// `postgres://user:password@host:5432/silo`.
    pub url: String,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    /// How long to keep retrying an unreachable database on startup.
    /// Generous by default because silo and its Postgres are routinely
    /// scheduled at the same moment in Kubernetes.
    #[serde(default = "default_connect_timeout_seconds")]
    pub connect_timeout_seconds: u64,
}

fn default_max_connections() -> u32 {
    10
}

fn default_connect_timeout_seconds() -> u64 {
    120
}

impl DatabaseConfig {
    pub fn to_db_config(&self, token_pepper: Option<String>) -> silo_db::DbConfig {
        silo_db::DbConfig {
            url: self.url.clone(),
            max_connections: self.max_connections,
            connect_timeout: Duration::from_secs(self.connect_timeout_seconds),
            token_pepper,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StorageConfig {
    pub bucket: String,
    /// S3-compatible endpoint (e.g. SeaweedFS). Omit for real AWS S3.
    #[serde(default)]
    pub endpoint: Option<String>,
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    /// Required when pointing at a non-TLS endpoint (e.g. a local
    /// SeaweedFS).
    #[serde(default)]
    pub allow_http: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    /// Server-side secret mixed into token hashes. Never stored in the
    /// database, so a database dump alone yields no usable credentials.
    /// Changing it invalidates every existing token.
    #[serde(default)]
    pub token_pepper: Option<String>,

    /// Mint an admin token (and an admin user) on first startup when the
    /// database has none, printing the credentials to stdout exactly once.
    #[serde(default = "default_true")]
    pub bootstrap: bool,

    /// Name given to the bootstrap token, so it's identifiable in
    /// `silo token list`.
    #[serde(default = "default_bootstrap_token_name")]
    pub bootstrap_token_name: String,

    #[serde(default = "default_bootstrap_username")]
    pub bootstrap_username: String,

    /// Lifetime of the tokens `silo login` issues.
    #[serde(default = "default_session_ttl_hours")]
    pub session_ttl_hours: i64,
}

// Written out rather than derived: `#[serde(default)]` on the `auth` field
// fills the *whole struct* from `Default`, so a derived impl would zero
// `session_ttl_hours` and clear `bootstrap` for every config that omits
// the block — exactly the configs that most need the defaults.
impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            token_pepper: None,
            bootstrap: true,
            bootstrap_token_name: default_bootstrap_token_name(),
            bootstrap_username: default_bootstrap_username(),
            session_ttl_hours: default_session_ttl_hours(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_bootstrap_token_name() -> String {
    "bootstrap-admin".to_string()
}

fn default_bootstrap_username() -> String {
    "admin".to_string()
}

fn default_session_ttl_hours() -> i64 {
    720 // 30 days
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OidcConfig {
    /// Issuer URL. Discovery is done against
    /// `{issuer}/.well-known/openid-configuration`.
    pub issuer: String,
    pub client_id: String,
    /// Only needed for confidential clients. The CLI uses the device
    /// authorization grant, which works without one for public clients.
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Claim to take the Silo username from.
    #[serde(default = "default_username_claim")]
    pub username_claim: String,
    /// Scopes the CLI requests during the device flow.
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    /// Users holding this value in `admin_claim` are provisioned as
    /// admins. With no claim configured, OIDC users are never admins.
    #[serde(default)]
    pub admin_claim: Option<String>,
    #[serde(default)]
    pub admin_value: Option<String>,
    /// Disable local password login entirely once SSO is in place.
    #[serde(default)]
    pub exclusive: bool,
    /// Let a first OIDC login bind its subject to a pre-existing local
    /// account with the same username.
    ///
    /// Off by default, and the default is the security-relevant one: the
    /// username comes from a claim the end user can often set themselves,
    /// so automatic linking lets anyone who claims `admin` inherit the
    /// local `admin` account bootstrap creates. Turn it on only while
    /// migrating established local accounts onto a provider whose
    /// usernames you control, and turn it back off afterwards.
    #[serde(default)]
    pub allow_username_linking: bool,
}

fn default_username_claim() -> String {
    "preferred_username".to_string()
}

fn default_scopes() -> Vec<String> {
    vec!["openid".to_string(), "profile".to_string()]
}

/// Signing keys. All are optional and independent: RPM package signatures,
/// apk index signatures, and the pacman database signature use different
/// algorithms and/or different key material, and a registry may reasonably
/// serve some formats signed and others not.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SigningConfig {
    #[serde(default)]
    pub gpg: Option<GpgConfig>,
    #[serde(default)]
    pub apk: Option<ApkSigningConfig>,
    /// Signs the pacman repo database. Deliberately its own `GpgConfig`
    /// rather than reusing `gpg`, so RPM and pacman repos can be signed
    /// with different keys.
    #[serde(default)]
    pub pacman: Option<GpgConfig>,
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

/// RSA key used to sign `APKINDEX.tar.gz`. `apk` looks the public half up
/// in `/etc/apk/keys/<key_name>`, so `key_name` must match the filename
/// deployed to clients.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApkSigningConfig {
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub key_path: Option<String>,
    /// e.g. `silo@example.com-1a2b3c4d.rsa.pub`
    pub key_name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuditConfig {
    /// Record every authenticated package download. Index/repodata fetches
    /// are never audited — `dnf makecache` alone would bury the log.
    #[serde(default = "default_true")]
    pub log_downloads: bool,
    /// Entries older than this are pruned daily. 0 disables pruning.
    #[serde(default = "default_audit_retention_days")]
    pub retention_days: i64,
}

fn default_audit_retention_days() -> i64 {
    90
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            log_downloads: true,
            retention_days: default_audit_retention_days(),
        }
    }
}

/// Global switch for package pruning. Per-(repo, channel) rules — set via
/// `silo repo set-prune-rule` — only take effect while this is `true`;
/// flipping it back to `false` stops both the scheduled job and manual
/// `silo prune` runs without having to unwind any configured rule. Off by
/// default, since pruning deletes packages.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PruneConfig {
    #[serde(default)]
    pub enabled: bool,
}

/// Cron schedules for background jobs, 6 fields with seconds first (e.g.
/// `"0 */5 * * * *"` for every 5 minutes) — see the `cron` crate's
/// `Schedule` format. `session_cleanup` and `audit_prune` have defaults
/// that preserve the housekeeping cadence silo has always run at;
/// `package_prune` has none, since automatic pruning is opt-in even when
/// `prune.enabled` is on — leaving it unset means only `silo prune` runs
/// it, on demand.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JobsConfig {
    #[serde(default = "default_session_cleanup_schedule")]
    pub session_cleanup: String,
    #[serde(default = "default_audit_prune_schedule")]
    pub audit_prune: String,
    #[serde(default)]
    pub package_prune: Option<String>,
    /// Refreshes every configured upstream's synced index. Opt-in like
    /// `package_prune`: hitting third-party registries on a schedule
    /// shouldn't be silently on by default. `add-upstream`/
    /// `sync-upstream` still sync on demand regardless of this setting.
    #[serde(default)]
    pub upstream_sync: Option<String>,
}

fn default_session_cleanup_schedule() -> String {
    "0 */5 * * * *".to_string()
}

fn default_audit_prune_schedule() -> String {
    "0 0 * * * *".to_string()
}

impl Default for JobsConfig {
    fn default() -> Self {
        Self {
            session_cleanup: default_session_cleanup_schedule(),
            audit_prune: default_audit_prune_schedule(),
            package_prune: None,
            upstream_sync: None,
        }
    }
}

/// The key that encrypts upstream credentials at rest. See
/// `silo_core::secret_box` — generate one with `SecretBox::generate_key()`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpstreamSecretConfig {
    /// 32 raw bytes, base64-encoded. Never stored in the database;
    /// rotating it invalidates every stored upstream credential.
    pub key: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetricsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Require an admin token scoped to every repo for `/metrics`.
    ///
    /// On by default. The endpoint carries no package contents, but its
    /// inventory gauges are labelled by repo and channel, so an
    /// unauthenticated scrape enumerates every private repo in the
    /// registry — the disclosure the read path's 404-instead-of-403
    /// handling exists to prevent. Set this to `false` only when the HTTP
    /// port is reachable solely by your monitoring stack.
    #[serde(default = "default_true")]
    pub require_auth: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            require_auth: true,
        }
    }
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

impl ApkSigningConfig {
    pub fn resolve_key(&self) -> anyhow::Result<String> {
        match (&self.key, &self.key_path) {
            (Some(k), None) => Ok(k.clone()),
            (None, Some(path)) => Ok(std::fs::read_to_string(path)?),
            (Some(_), Some(_)) => {
                anyhow::bail!("apk signing config must set exactly one of `key` or `key_path`")
            }
            (None, None) => anyhow::bail!("apk signing config requires `key` or `key_path`"),
        }
    }
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read config at {}: {e}", path.display()))?;
        let raw = expand_env_vars(&raw)?;
        let cfg: Config = serde_yaml::from_str(&raw)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.database.url.trim().is_empty() {
            anyhow::bail!("`database.url` is required");
        }
        if let Some(base) = &self.public_base_url {
            url::Url::parse(base)
                .map_err(|e| anyhow::anyhow!("`public_base_url` is not a valid URL: {e}"))?;
        }
        if let Some(oidc) = &self.oidc {
            url::Url::parse(&oidc.issuer)
                .map_err(|e| anyhow::anyhow!("`oidc.issuer` is not a valid URL: {e}"))?;
            if oidc.client_id.trim().is_empty() {
                anyhow::bail!("`oidc.client_id` is required when oidc is configured");
            }
        }
        if self.auth.session_ttl_hours <= 0 {
            anyhow::bail!("`auth.session_ttl_hours` must be positive");
        }
        validate_schedule("jobs.session_cleanup", &self.jobs.session_cleanup)?;
        validate_schedule("jobs.audit_prune", &self.jobs.audit_prune)?;
        if let Some(schedule) = &self.jobs.package_prune {
            validate_schedule("jobs.package_prune", schedule)?;
        }
        if let Some(schedule) = &self.jobs.upstream_sync {
            validate_schedule("jobs.upstream_sync", schedule)?;
        }
        if let Some(secret) = &self.upstream_secret {
            crate::secret_box::SecretBox::new(&secret.key)
                .map_err(|e| anyhow::anyhow!("`upstream_secret.key` is invalid: {e}"))?;
        }
        Ok(())
    }

    pub fn public_base_url(&self) -> Option<&str> {
        self.public_base_url.as_deref()
    }
}

/// Substitutes `${VAR}` and `${VAR:-default}` from the environment.
///
/// This is what lets credentials stay out of the config file entirely: the
/// Helm chart writes `url: "${SILO_DATABASE_URL}"` into a ConfigMap-shaped
/// Secret and injects the real URL as an environment variable from
/// wherever it actually lives, so a password never has to be templated
/// into a file or into Helm release history.
///
/// An unset variable with no default is a hard error rather than an empty
/// string. Silently expanding a missing password to `""` produces a
/// connection failure three layers away from the actual mistake.
///
/// YAML comments are left alone. Every optional setting in
/// `config.example.yaml` is documented as a commented-out line, and most
/// of them reference a variable — expanding those turned "here is what you
/// could set" into "you must set all of this before the server will
/// start", which is precisely backwards.
pub fn expand_env_vars(input: &str) -> anyhow::Result<String> {
    let mut out = String::with_capacity(input.len());
    for (i, line) in input.split_inclusive('\n').enumerate() {
        let (code, comment) = split_comment(line);
        out.push_str(&expand_line(code).map_err(|e| {
            // Line numbers matter here: the message names a variable, and
            // in a file with several the user still has to find which one.
            anyhow::anyhow!("{e} (line {})", i + 1)
        })?);
        out.push_str(comment);
    }
    Ok(out)
}

/// Splits a line into its YAML content and its trailing comment.
///
/// A `#` only starts a comment at the beginning of a line or after
/// whitespace, and never inside a quoted scalar — the same rule YAML
/// itself uses, so `password: "a#b"` keeps its `#`.
fn split_comment(line: &str) -> (&str, &str) {
    let bytes = line.as_bytes();
    let mut quote: Option<u8> = None;
    for (i, &b) in bytes.iter().enumerate() {
        match quote {
            Some(q) => {
                if b == q {
                    quote = None;
                }
            }
            None => match b {
                b'"' | b'\'' => quote = Some(b),
                b'#' if i == 0 || bytes[i - 1].is_ascii_whitespace() => {
                    return (&line[..i], &line[i..]);
                }
                _ => {}
            },
        }
    }
    (line, "")
}

fn expand_line(input: &str) -> anyhow::Result<String> {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;

    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            // An unterminated `${` is far more likely to be literal text
            // than a typo'd variable, so it passes through untouched.
            out.push_str(&rest[start..]);
            return Ok(out);
        };

        let expression = &after[..end];
        let (name, default) = match expression.split_once(":-") {
            Some((name, default)) => (name, Some(default)),
            None => (expression, None),
        };

        match std::env::var(name) {
            Ok(value) => out.push_str(&value),
            Err(_) => match default {
                Some(default) => out.push_str(default),
                None => anyhow::bail!(
                    "config references ${{{name}}} but that environment variable is not set \
                     (use ${{{name}:-default}} if it is meant to be optional)"
                ),
            },
        }
        rest = &after[end + 1..];
    }

    out.push_str(rest);
    Ok(out)
}

/// Parses a cron schedule at config-load time so a typo (or a 5-field
/// expression missing the leading seconds field the `cron` crate expects)
/// fails startup with a clear message instead of silently never firing.
fn validate_schedule(key: &str, schedule: &str) -> anyhow::Result<()> {
    schedule.parse::<cron::Schedule>().map_err(|e| {
        anyhow::anyhow!(
            "`{key}` is not a valid cron schedule: {e} \
             (6 fields, seconds first, e.g. \"0 */5 * * * *\")"
        )
    })?;
    Ok(())
}

/// Repo and channel names end up in object-storage keys, URLs, and
/// advisory-lock scope strings. Restricting them to a conservative
/// character set keeps all three unambiguous — in particular, no `/`,
/// which would let two different repo/channel pairs address the same
/// prefix.
pub fn validate_repo_name(kind: &str, name: &str) -> anyhow::Result<()> {
    if name.is_empty() || name.len() > 100 {
        anyhow::bail!("{kind} name must be between 1 and 100 characters");
    }
    if name == "." || name == ".." {
        anyhow::bail!("`{name}` is not a valid {kind} name");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        anyhow::bail!(
            "{kind} name `{name}` may only contain letters, digits, and the characters - _ ."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
addr: "0.0.0.0:8080"
database:
  url: "postgres://silo:silo@localhost/silo"
storage:
  bucket: "silo"
  region: "us-east-1"
  access_key_id: "key"
  secret_access_key: "secret"
"#;

    #[test]
    fn parses_minimal_config_with_sensible_defaults() {
        let cfg: Config = serde_yaml::from_str(MINIMAL).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.storage.bucket, "silo");
        assert_eq!(cfg.database.max_connections, 10);
        assert!(cfg.auth.bootstrap);
        assert!(cfg.metrics.enabled);
        assert!(cfg.audit.log_downloads);
        assert_eq!(cfg.audit.retention_days, 90);
        assert!(cfg.signing.gpg.is_none());
        assert!(cfg.oidc.is_none());
        assert!(!cfg.prune.enabled);
        assert_eq!(cfg.jobs.session_cleanup, "0 */5 * * * *");
        assert_eq!(cfg.jobs.audit_prune, "0 0 * * * *");
        assert!(cfg.jobs.package_prune.is_none());
    }

    #[test]
    fn rejects_a_malformed_public_base_url() {
        let yaml = format!("{MINIMAL}\npublic_base_url: \"not a url\"\n");
        let cfg: Config = serde_yaml::from_str(&yaml).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn accepts_a_full_config() {
        let yaml = format!(
            r#"{MINIMAL}
public_base_url: "https://silo.example.com"
auth:
  token_pepper: "pepper"
  session_ttl_hours: 24
oidc:
  issuer: "https://id.example.com"
  client_id: "silo"
  admin_claim: "groups"
  admin_value: "silo-admins"
signing:
  gpg:
    key_path: "/etc/silo/gpg.asc"
  apk:
    key_path: "/etc/silo/apk.rsa"
    key_name: "silo@example.com-1a2b3c4d.rsa.pub"
audit:
  log_downloads: false
  retention_days: 30
metrics:
  enabled: true
  require_auth: true
prune:
  enabled: true
jobs:
  session_cleanup: "0 */10 * * * *"
  audit_prune: "0 30 2 * * *"
  package_prune: "0 0 3 * * *"
"#
        );
        let cfg: Config = serde_yaml::from_str(&yaml).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.auth.session_ttl_hours, 24);
        assert_eq!(
            cfg.oidc.as_ref().unwrap().username_claim,
            "preferred_username"
        );
        assert_eq!(
            cfg.signing.apk.as_ref().unwrap().key_name,
            "silo@example.com-1a2b3c4d.rsa.pub"
        );
        assert!(!cfg.audit.log_downloads);
        assert!(cfg.metrics.require_auth);
        assert!(cfg.prune.enabled);
        assert_eq!(cfg.jobs.session_cleanup, "0 */10 * * * *");
        assert_eq!(cfg.jobs.package_prune.as_deref(), Some("0 0 3 * * *"));
    }

    #[test]
    fn rejects_a_malformed_job_schedule() {
        let yaml = format!("{MINIMAL}\njobs:\n  session_cleanup: \"not a cron\"\n");
        let cfg: Config = serde_yaml::from_str(&yaml).unwrap();
        assert!(cfg.validate().is_err());

        let yaml = format!("{MINIMAL}\njobs:\n  package_prune: \"* * * * *\"\n"); // 5 fields, missing seconds
        let cfg: Config = serde_yaml::from_str(&yaml).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn oidc_requires_a_valid_issuer_and_client_id() {
        let yaml = format!("{MINIMAL}\noidc:\n  issuer: \"nope\"\n  client_id: \"silo\"\n");
        let cfg: Config = serde_yaml::from_str(&yaml).unwrap();
        assert!(cfg.validate().is_err());

        let yaml =
            format!("{MINIMAL}\noidc:\n  issuer: \"https://id.example.com\"\n  client_id: \"\"\n");
        let cfg: Config = serde_yaml::from_str(&yaml).unwrap();
        assert!(cfg.validate().is_err());
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

    #[test]
    fn env_vars_are_expanded_in_config_files() {
        std::env::set_var("SILO_TEST_EXPAND", "postgres://real/url");
        assert_eq!(
            expand_env_vars("url: \"${SILO_TEST_EXPAND}\"").unwrap(),
            "url: \"postgres://real/url\""
        );
        assert_eq!(
            expand_env_vars("a=${SILO_TEST_EXPAND} b=${SILO_TEST_EXPAND}").unwrap(),
            "a=postgres://real/url b=postgres://real/url"
        );
        std::env::remove_var("SILO_TEST_EXPAND");
    }

    #[test]
    fn unset_env_vars_fail_loudly_unless_they_have_a_default() {
        std::env::remove_var("SILO_TEST_MISSING");
        let err = expand_env_vars("url: ${SILO_TEST_MISSING}")
            .unwrap_err()
            .to_string();
        assert!(err.contains("SILO_TEST_MISSING"), "got: {err}");
        assert!(
            err.contains(":-"),
            "the error should suggest the default syntax"
        );

        assert_eq!(
            expand_env_vars("url: ${SILO_TEST_MISSING:-fallback}").unwrap(),
            "url: fallback"
        );
        // An empty default is still a default, not an error.
        assert_eq!(
            expand_env_vars("url: ${SILO_TEST_MISSING:-}").unwrap(),
            "url: "
        );
    }

    #[test]
    fn text_without_placeholders_passes_through_unchanged() {
        let yaml = "addr: \"0.0.0.0:8080\"\npassword: \"has$dollar\"\n";
        assert_eq!(expand_env_vars(yaml).unwrap(), yaml);
        // An unterminated placeholder is literal text, not a parse error.
        assert_eq!(expand_env_vars("cost: ${100").unwrap(), "cost: ${100");
    }

    #[test]
    fn commented_out_settings_are_not_expanded() {
        std::env::remove_var("SILO_TEST_MISSING");
        // The shipped example config documents every optional setting as
        // a commented-out line, and most reference a variable. Expanding
        // those would make an untouched `config.example.yaml` refuse to
        // start, which is exactly what a copy-and-edit template must not
        // do.
        let yaml = "auth:\n  # token_pepper: \"${SILO_TEST_MISSING}\"\n  bootstrap: true\n";
        assert_eq!(expand_env_vars(yaml).unwrap(), yaml);

        // A trailing comment on a live line leaves the value expanded and
        // the comment alone.
        std::env::set_var("SILO_TEST_EXPAND_C", "real");
        assert_eq!(
            expand_env_vars("url: ${SILO_TEST_EXPAND_C} # or ${SILO_TEST_MISSING}\n").unwrap(),
            "url: real # or ${SILO_TEST_MISSING}\n"
        );
        std::env::remove_var("SILO_TEST_EXPAND_C");
    }

    #[test]
    fn a_hash_inside_a_quoted_value_does_not_start_a_comment() {
        std::env::set_var("SILO_TEST_HASH", "s3cr3t");
        assert_eq!(
            expand_env_vars("password: \"a#b ${SILO_TEST_HASH}\"\n").unwrap(),
            "password: \"a#b s3cr3t\"\n"
        );
        // ...and neither does one with no whitespace before it.
        assert_eq!(
            expand_env_vars("tag: v1#${SILO_TEST_HASH}\n").unwrap(),
            "tag: v1#s3cr3t\n"
        );
        std::env::remove_var("SILO_TEST_HASH");
    }

    #[test]
    fn a_missing_variable_error_names_the_line_it_is_on() {
        std::env::remove_var("SILO_TEST_MISSING");
        let err = expand_env_vars("a: 1\nb: 2\nc: ${SILO_TEST_MISSING}\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("line 3"), "got: {err}");
    }

    #[test]
    fn the_shipped_example_config_starts_with_no_environment_at_all() {
        // A regression guard for the whole point of the above: someone
        // following the README copies this file verbatim.
        let example = include_str!("../../../config.example.yaml");
        expand_env_vars(example).expect("config.example.yaml must not require any env vars");
    }

    #[test]
    fn repo_names_reject_path_separators_and_traversal() {
        assert!(validate_repo_name("repo", "myrepo").is_ok());
        assert!(validate_repo_name("repo", "my-repo_1.0").is_ok());
        assert!(validate_repo_name("repo", "a/b").is_err());
        assert!(validate_repo_name("repo", "..").is_err());
        assert!(validate_repo_name("repo", "").is_err());
        assert!(validate_repo_name("channel", "with space").is_err());
        assert!(validate_repo_name("repo", &"x".repeat(101)).is_err());
    }
}
