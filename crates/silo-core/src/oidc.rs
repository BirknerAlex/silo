//! OIDC discovery and ID-token verification.
//!
//! Silo doesn't run an OAuth redirect flow of its own. The CLI drives the
//! **device authorization grant** directly against the identity provider —
//! the only grant that works for a terminal on a machine that may not have
//! a browser — and then presents the resulting ID token here. The server's
//! job is narrow: prove the token came from the configured issuer, is for
//! this client, and hasn't expired; then map it to a local user.
//!
//! That split means the server never handles the user's credentials and
//! never needs a client secret for the CLI to work, which is what makes
//! `oidc.client_secret` optional in the config.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::config::OidcConfig;

/// The subset of the discovery document Silo uses. The full document has
/// dozens of fields; deserializing only these keeps a provider adding new
/// ones from breaking startup.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Discovery {
    pub issuer: String,
    pub jwks_uri: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub device_authorization_endpoint: Option<String>,
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
}

impl Discovery {
    pub async fn fetch(issuer: &str) -> anyhow::Result<Self> {
        let url = discovery_url(issuer);
        let response = reqwest::Client::new()
            .get(&url)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("OIDC discovery request to {url} failed: {e}"))?;
        if !response.status().is_success() {
            anyhow::bail!(
                "OIDC discovery at {url} returned HTTP {}",
                response.status()
            );
        }
        response
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("OIDC discovery document at {url} is malformed: {e}"))
    }
}

/// Builds the well-known URL, tolerating a trailing slash on the issuer.
/// Getting this wrong yields a 404 that looks like a provider outage, so
/// it's worth normalizing rather than documenting.
pub fn discovery_url(issuer: &str) -> String {
    format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    )
}

/// Claims Silo reads out of an ID token. Everything else is retained in
/// `extra` so `username_claim`/`admin_claim` can point at provider-specific
/// claims without this struct needing to know about them.
#[derive(Debug, Clone, Deserialize)]
pub struct IdTokenClaims {
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl IdTokenClaims {
    /// Resolves the configured username claim, falling back through the
    /// conventional ones and finally to `sub` — which is ugly as a
    /// username but is the only claim guaranteed to exist.
    pub fn username(&self, claim: &str) -> String {
        if let Some(value) = self.claim_str(claim) {
            return value;
        }
        self.preferred_username
            .clone()
            .or_else(|| self.email.clone())
            .unwrap_or_else(|| self.sub.clone())
    }

    fn claim_str(&self, claim: &str) -> Option<String> {
        match claim {
            "sub" => return Some(self.sub.clone()),
            "email" => return self.email.clone(),
            "preferred_username" => return self.preferred_username.clone(),
            _ => {}
        }
        match self.extra.get(claim)? {
            serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
            _ => None,
        }
    }

    /// True when the configured admin claim contains the configured value.
    /// Handles both scalar claims (`role: "admin"`) and array claims
    /// (`groups: ["a", "silo-admins"]`), because providers disagree.
    pub fn is_admin(&self, cfg: &OidcConfig) -> bool {
        let (Some(claim), Some(expected)) = (&cfg.admin_claim, &cfg.admin_value) else {
            return false;
        };
        match self.extra.get(claim.as_str()) {
            Some(serde_json::Value::String(s)) => s == expected,
            Some(serde_json::Value::Array(items)) => items
                .iter()
                .any(|v| v.as_str().map(|s| s == expected).unwrap_or(false)),
            Some(serde_json::Value::Bool(b)) => *b && expected == "true",
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    kid: Option<String>,
    kty: String,
    #[serde(default)]
    alg: Option<String>,
    // RSA
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    // EC
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
}

impl Jwk {
    fn decoding_key(&self) -> anyhow::Result<(DecodingKey, Algorithm)> {
        match self.kty.as_str() {
            "RSA" => {
                let (n, e) = self
                    .n
                    .as_ref()
                    .zip(self.e.as_ref())
                    .ok_or_else(|| anyhow::anyhow!("RSA JWK is missing `n`/`e`"))?;
                let alg = match self.alg.as_deref() {
                    Some("RS384") => Algorithm::RS384,
                    Some("RS512") => Algorithm::RS512,
                    _ => Algorithm::RS256,
                };
                Ok((DecodingKey::from_rsa_components(n, e)?, alg))
            }
            "EC" => {
                let (x, y) = self
                    .x
                    .as_ref()
                    .zip(self.y.as_ref())
                    .ok_or_else(|| anyhow::anyhow!("EC JWK is missing `x`/`y`"))?;
                let alg = match self.crv.as_deref() {
                    Some("P-384") => Algorithm::ES384,
                    _ => Algorithm::ES256,
                };
                Ok((DecodingKey::from_ec_components(x, y)?, alg))
            }
            other => anyhow::bail!("unsupported JWK key type `{other}`"),
        }
    }
}

/// How long a fetched JWKS is trusted before being refetched. Providers
/// rotate keys on the order of days; an unknown `kid` forces an immediate
/// refresh regardless, so this only bounds how long a *revoked* key stays
/// usable.
const JWKS_TTL: Duration = Duration::from_secs(15 * 60);

/// Verifies ID tokens against the configured issuer, caching the JWKS.
pub struct Verifier {
    config: OidcConfig,
    discovery: Discovery,
    jwks: RwLock<Option<CachedJwks>>,
    http: reqwest::Client,
}

struct CachedJwks {
    keys: Vec<Jwk>,
    fetched_at: Instant,
}

impl Verifier {
    /// Performs discovery once at startup, so a misconfigured issuer is a
    /// boot failure rather than a confusing error on someone's first login.
    pub async fn new(config: OidcConfig) -> anyhow::Result<Arc<Self>> {
        let discovery = Discovery::fetch(&config.issuer).await?;
        if discovery.issuer.trim_end_matches('/') != config.issuer.trim_end_matches('/') {
            anyhow::bail!(
                "OIDC issuer mismatch: configured `{}` but the discovery document declares `{}`",
                config.issuer,
                discovery.issuer
            );
        }
        Ok(Arc::new(Self {
            config,
            discovery,
            jwks: RwLock::new(None),
            http: reqwest::Client::new(),
        }))
    }

    pub fn config(&self) -> &OidcConfig {
        &self.config
    }

    pub fn discovery(&self) -> &Discovery {
        &self.discovery
    }

    /// Validates signature, issuer, audience, and expiry.
    pub async fn verify(&self, id_token: &str) -> anyhow::Result<IdTokenClaims> {
        let header = decode_header(id_token)
            .map_err(|e| anyhow::anyhow!("ID token header is not valid JWT: {e}"))?;

        let jwk = self
            .find_key(header.kid.as_deref())
            .await?
            .ok_or_else(|| anyhow::anyhow!("no JWKS key matches the ID token's `kid`"))?;
        let (key, alg) = jwk.decoding_key()?;

        // Validate with the *key's* algorithm, not the token header's.
        // Deriving the algorithm from attacker-supplied header data is the
        // classic JWT algorithm-confusion bug — a token claiming `HS256`
        // against an RSA public key would otherwise be verified with that
        // public key as an HMAC secret, and the public key is public.
        if header.alg != alg {
            anyhow::bail!(
                "ID token declares algorithm {:?} but its signing key is {alg:?}",
                header.alg
            );
        }
        let mut validation = Validation::new(alg);
        validation.set_audience(&[self.config.client_id.as_str()]);
        validation.set_issuer(&[self.config.issuer.trim_end_matches('/')]);
        validation.validate_exp = true;

        let data = decode::<IdTokenClaims>(id_token, &key, &validation)
            .map_err(|e| anyhow::anyhow!("ID token rejected: {e}"))?;
        Ok(data.claims)
    }

    /// Returns the JWK for a `kid`, refreshing the cache when the key is
    /// unknown or the cache has aged out.
    async fn find_key(&self, kid: Option<&str>) -> anyhow::Result<Option<Jwk>> {
        if let Some(cached) = self.jwks.read().await.as_ref() {
            if cached.fetched_at.elapsed() < JWKS_TTL {
                if let Some(found) = match_key(&cached.keys, kid) {
                    return Ok(Some(found));
                }
            }
        }

        let keys = self.fetch_jwks().await?;
        let found = match_key(&keys, kid);
        *self.jwks.write().await = Some(CachedJwks {
            keys,
            fetched_at: Instant::now(),
        });
        Ok(found)
    }

    async fn fetch_jwks(&self) -> anyhow::Result<Vec<Jwk>> {
        let response = self
            .http
            .get(&self.discovery.jwks_uri)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("failed to fetch JWKS: {e}"))?;
        if !response.status().is_success() {
            anyhow::bail!("JWKS endpoint returned HTTP {}", response.status());
        }
        let jwks: Jwks = response
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("JWKS document is malformed: {e}"))?;
        Ok(jwks.keys)
    }
}

/// Matches by `kid`, falling back to the sole key when the token carries
/// no `kid` and the provider publishes exactly one.
fn match_key(keys: &[Jwk], kid: Option<&str>) -> Option<Jwk> {
    match kid {
        Some(kid) => keys.iter().find(|k| k.kid.as_deref() == Some(kid)).cloned(),
        None if keys.len() == 1 => keys.first().cloned(),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Base64url modulus of a throwaway RSA key, used only to build a
    /// structurally valid JWK.
    const TEST_MODULUS: &str = "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw";

    fn config() -> OidcConfig {
        OidcConfig {
            issuer: "https://id.example.com".into(),
            client_id: "silo".into(),
            client_secret: None,
            username_claim: "preferred_username".into(),
            scopes: vec!["openid".into()],
            admin_claim: Some("groups".into()),
            admin_value: Some("silo-admins".into()),
            exclusive: false,
        }
    }

    fn claims(extra: serde_json::Value) -> IdTokenClaims {
        serde_json::from_value(extra).unwrap()
    }

    #[test]
    fn discovery_url_tolerates_a_trailing_slash() {
        assert_eq!(
            discovery_url("https://id.example.com/"),
            "https://id.example.com/.well-known/openid-configuration"
        );
        assert_eq!(
            discovery_url("https://id.example.com"),
            "https://id.example.com/.well-known/openid-configuration"
        );
    }

    #[test]
    fn username_prefers_the_configured_claim() {
        let c = claims(json!({
            "sub": "abc",
            "preferred_username": "alice",
            "email": "alice@example.com",
            "nickname": "al",
        }));
        assert_eq!(c.username("preferred_username"), "alice");
        assert_eq!(c.username("email"), "alice@example.com");
        assert_eq!(c.username("nickname"), "al");
        assert_eq!(c.username("sub"), "abc");
    }

    #[test]
    fn username_falls_back_when_the_configured_claim_is_absent() {
        let c = claims(json!({ "sub": "abc", "email": "alice@example.com" }));
        assert_eq!(c.username("preferred_username"), "alice@example.com");

        let bare = claims(json!({ "sub": "abc" }));
        assert_eq!(bare.username("preferred_username"), "abc");
    }

    #[test]
    fn admin_claim_matches_scalar_and_array_shapes() {
        let cfg = config();
        assert!(claims(json!({"sub": "s", "groups": "silo-admins"})).is_admin(&cfg));
        assert!(claims(json!({"sub": "s", "groups": ["other", "silo-admins"]})).is_admin(&cfg));
        assert!(!claims(json!({"sub": "s", "groups": ["other"]})).is_admin(&cfg));
        assert!(!claims(json!({"sub": "s"})).is_admin(&cfg));
    }

    #[test]
    fn no_admin_claim_configured_means_nobody_is_an_admin() {
        let mut cfg = config();
        cfg.admin_claim = None;
        assert!(!claims(json!({"sub": "s", "groups": ["silo-admins"]})).is_admin(&cfg));

        cfg = config();
        cfg.admin_value = None;
        assert!(!claims(json!({"sub": "s", "groups": ["silo-admins"]})).is_admin(&cfg));
    }

    #[test]
    fn key_matching_uses_kid_and_falls_back_only_for_a_single_key() {
        let a = Jwk {
            kid: Some("a".into()),
            kty: "RSA".into(),
            alg: None,
            n: None,
            e: None,
            crv: None,
            x: None,
            y: None,
        };
        let mut b = a.clone();
        b.kid = Some("b".into());

        assert_eq!(
            match_key(&[a.clone(), b.clone()], Some("b")).unwrap().kid,
            Some("b".into())
        );
        assert!(match_key(&[a.clone(), b.clone()], Some("z")).is_none());
        // Ambiguous: two keys and no kid to choose between them.
        assert!(match_key(&[a.clone(), b], None).is_none());
        assert!(match_key(&[a], None).is_some());
    }

    #[test]
    fn rsa_jwks_pick_their_algorithm_from_the_alg_field() {
        // `n`/`e` are a real (throwaway) 2048-bit modulus and exponent;
        // `decoding_key` rejects malformed base64url, so they can't be
        // placeholders.
        let base = Jwk {
            kid: Some("k".into()),
            kty: "RSA".into(),
            alg: None,
            n: Some(TEST_MODULUS.into()),
            e: Some("AQAB".into()),
            crv: None,
            x: None,
            y: None,
        };
        assert_eq!(base.decoding_key().unwrap().1, Algorithm::RS256);

        let mut rs512 = base.clone();
        rs512.alg = Some("RS512".into());
        assert_eq!(rs512.decoding_key().unwrap().1, Algorithm::RS512);

        // An unknown `alg` must not fail open onto something weaker.
        let mut unknown = base.clone();
        unknown.alg = Some("PS999".into());
        assert_eq!(unknown.decoding_key().unwrap().1, Algorithm::RS256);
    }

    #[test]
    fn rsa_jwks_missing_their_components_are_rejected() {
        let jwk = Jwk {
            kid: None,
            kty: "RSA".into(),
            alg: None,
            n: Some(TEST_MODULUS.into()),
            e: None,
            crv: None,
            x: None,
            y: None,
        };
        assert!(jwk.decoding_key().is_err());
    }

    #[test]
    fn unsupported_key_types_are_rejected() {
        let jwk = Jwk {
            kid: None,
            kty: "oct".into(),
            alg: None,
            n: None,
            e: None,
            crv: None,
            x: None,
            y: None,
        };
        assert!(jwk.decoding_key().is_err());
    }

    #[test]
    fn discovery_documents_ignore_unknown_fields() {
        let doc: Discovery = serde_json::from_value(json!({
            "issuer": "https://id.example.com",
            "jwks_uri": "https://id.example.com/keys",
            "token_endpoint": "https://id.example.com/token",
            "device_authorization_endpoint": "https://id.example.com/device",
            "something_new_in_2027": true,
        }))
        .unwrap();
        assert_eq!(
            doc.device_authorization_endpoint.as_deref(),
            Some("https://id.example.com/device")
        );
    }
}
