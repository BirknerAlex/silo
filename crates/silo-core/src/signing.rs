//! Signing key material and the two things Silo signs.
//!
//! - **RPM packages** are signed in place with an OpenPGP key, and the
//!   repodata's `repomd.xml` gets a detached armored signature so
//!   `gpgcheck=1` and `repo_gpgcheck=1` both work.
//! - **APKINDEX** is signed with an RSA key, PKCS#1 v1.5 over SHA-1. That
//!   is not a modern choice, but it is what `.SIGN.RSA.<name>` means to
//!   apk-tools 2.x, which is what's on every Alpine image in the wild.
//!   The signature covers a fresh index every time and is verified against
//!   a pinned public key, so SHA-1 collision resistance isn't what's
//!   protecting it — key possession is.
//!
//! npm has no signing story here: npm clients verify `integrity` hashes
//! from the packument, which the registry serves over TLS, and there is no
//! widely-deployed equivalent to `/etc/apk/keys`.

use std::sync::Arc;

use pgp::composed::{ArmorOptions, Deserializable, DetachedSignature, SignedSecretKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::types::Password;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer as _};
use rsa::RsaPrivateKey;
use sha1::Sha1;
use silo_pkg::IndexSigner;

use crate::config::{ApkSigningConfig, GpgConfig, SigningConfig};

/// Resolved key material, loaded once at startup so a malformed key is a
/// startup failure rather than a failure on the first publish.
#[derive(Clone, Default)]
pub struct Signers {
    pub gpg: Option<Arc<GpgSigner>>,
    pub apk: Option<Arc<ApkSigner>>,
}

impl Signers {
    pub fn from_config(cfg: &SigningConfig) -> anyhow::Result<Self> {
        let gpg = cfg
            .gpg
            .as_ref()
            .map(GpgSigner::from_config)
            .transpose()?
            .map(Arc::new);
        let apk = cfg
            .apk
            .as_ref()
            .map(ApkSigner::from_config)
            .transpose()?
            .map(Arc::new);
        Ok(Self { gpg, apk })
    }

    /// The index signer for a format, if one is configured. RPM's repomd
    /// signature and apk's index signature use different keys, so the
    /// lookup is per-format rather than a single "the" signer.
    pub fn for_format(&self, format: silo_pkg::PackageFormat) -> Option<&dyn IndexSigner> {
        match format {
            silo_pkg::PackageFormat::Rpm => self.gpg.as_deref().map(|s| s as &dyn IndexSigner),
            silo_pkg::PackageFormat::Apk => self.apk.as_deref().map(|s| s as &dyn IndexSigner),
            silo_pkg::PackageFormat::Npm => None,
        }
    }
}

/// A throwaway armored OpenPGP secret key with no passphrase.
///
/// Exposed rather than kept private to this module because `silo-server`
/// needs a real key to test the endpoint that serves the public half, and
/// generating one per test run costs seconds for no extra coverage. It
/// signs nothing real; see `testdata/README.md`.
#[cfg(any(test, feature = "test-util"))]
pub const TEST_GPG_SECRET_KEY: &str = include_str!("../testdata/gpg-signing-key.asc");

pub struct GpgSigner {
    armored_key: String,
    /// The public half of `armored_key`, derived once at load time.
    ///
    /// Served over HTTP so a `.repo` file can point `gpgkey=` at this
    /// server instead of the key having to be distributed out of band.
    /// Derived rather than configured separately: one key is configured,
    /// and the public half of it can never then disagree with the half
    /// that actually signs.
    armored_public_key: String,
    passphrase: Option<String>,
}

// Hand-written so an accidental `{:?}` — in a log line, in a test failure
// — can never print secret key material.
impl std::fmt::Debug for GpgSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GpgSigner").finish_non_exhaustive()
    }
}

impl GpgSigner {
    pub fn from_config(cfg: &GpgConfig) -> anyhow::Result<Self> {
        let armored_key = cfg.resolve_key()?;
        // Parse eagerly: a bad key should stop the server from starting,
        // not surface as a confusing failure on somebody's first publish.
        let (key, _) = SignedSecretKey::from_string(&armored_key)
            .map_err(|e| anyhow::anyhow!("failed to parse the gpg secret key: {e}"))?;
        // Likewise derived eagerly, so the endpoint that serves it is
        // infallible and a key that cannot be exported is a boot failure.
        let armored_public_key = key
            .to_public_key()
            .to_armored_string(ArmorOptions::default())
            .map_err(|e| anyhow::anyhow!("failed to armor the gpg public key: {e}"))?;
        Ok(Self {
            armored_key,
            armored_public_key,
            passphrase: cfg.passphrase.clone(),
        })
    }

    /// The armored **public** key, for clients that have to import it
    /// before they will trust anything this key signed.
    pub fn armored_public_key(&self) -> &str {
        &self.armored_public_key
    }

    /// Signs RPM bytes in place, returning the re-serialized package.
    pub fn sign_rpm(&self, bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(silo_pkg::rpm::sign_rpm(
            bytes,
            &self.armored_key,
            self.passphrase.as_deref(),
        )?)
    }

    /// Detached, armored signature over arbitrary bytes — used for
    /// `repomd.xml.asc`, which is what `repo_gpgcheck=1` verifies.
    fn detached_armored_signature(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let (key, _) = SignedSecretKey::from_string(&self.armored_key)
            .map_err(|e| anyhow::anyhow!("failed to parse the gpg secret key: {e}"))?;

        let password = match &self.passphrase {
            Some(p) => Password::from(p.clone()),
            None => Password::empty(),
        };

        // `&*key` derefs the signed key down to the primary secret key,
        // which is what implements the signing trait.
        let signature = DetachedSignature::sign_binary_data(
            rand::thread_rng(),
            &*key,
            &password,
            HashAlgorithm::Sha256,
            data,
        )
        .map_err(|e| anyhow::anyhow!("failed to sign data: {e}"))?;

        signature
            .to_armored_bytes(Default::default())
            .map_err(|e| anyhow::anyhow!("failed to armor the signature: {e}"))
    }
}

impl IndexSigner for GpgSigner {
    fn key_name(&self) -> &str {
        "gpg"
    }

    fn sign(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.detached_armored_signature(data)
    }
}

pub struct ApkSigner {
    key: RsaPrivateKey,
    key_name: String,
}

impl std::fmt::Debug for ApkSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApkSigner")
            .field("key_name", &self.key_name)
            .finish_non_exhaustive()
    }
}

impl ApkSigner {
    pub fn from_config(cfg: &ApkSigningConfig) -> anyhow::Result<Self> {
        let pem = cfg.resolve_key()?;
        let key = parse_rsa_private_key(&pem)?;
        if cfg.key_name.trim().is_empty() {
            anyhow::bail!("`signing.apk.key_name` is required — it must match the filename the public key is deployed to under /etc/apk/keys");
        }
        Ok(Self {
            key,
            key_name: cfg.key_name.clone(),
        })
    }
}

impl IndexSigner for ApkSigner {
    fn key_name(&self) -> &str {
        &self.key_name
    }

    fn sign(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let signing_key = SigningKey::<Sha1>::new(self.key.clone());
        Ok(signing_key.sign(data).to_vec())
    }
}

/// Accepts both PKCS#1 (`BEGIN RSA PRIVATE KEY`, what `openssl genrsa`
/// and `abuild-keygen` produce) and PKCS#8 (`BEGIN PRIVATE KEY`).
fn parse_rsa_private_key(pem: &str) -> anyhow::Result<RsaPrivateKey> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;

    if let Ok(key) = RsaPrivateKey::from_pkcs1_pem(pem.trim()) {
        return Ok(key);
    }
    RsaPrivateKey::from_pkcs8_pem(pem.trim())
        .map_err(|e| anyhow::anyhow!("failed to parse the apk signing key (expected a PKCS#1 or PKCS#8 RSA private key): {e}"))
}

/// Signs RPM bytes when a key is configured, otherwise passes them
/// through. Returns whether a signature was applied so the caller can
/// report it back to the publisher.
pub fn maybe_sign_rpm(bytes: Vec<u8>, signers: &Signers) -> anyhow::Result<(Vec<u8>, bool)> {
    let Some(gpg) = &signers.gpg else {
        return Ok((bytes, false));
    };
    Ok((gpg.sign_rpm(&bytes)?, true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgp::composed::SignedPublicKey;
    use pgp::types::KeyDetails as _;
    use silo_pkg::PackageFormat;

    /// A throwaway 2048-bit RSA key. Generating one per test run would add
    /// seconds to the suite for no extra coverage.
    const TEST_RSA_PKCS8: &str = include_str!("../testdata/apk-signing-key.pem");

    fn test_gpg_signer() -> GpgSigner {
        GpgSigner::from_config(&GpgConfig {
            key: Some(TEST_GPG_SECRET_KEY.to_string()),
            key_path: None,
            passphrase: None,
        })
        .unwrap()
    }

    #[test]
    fn no_signers_configured_leaves_rpm_bytes_untouched() {
        let bytes = b"raw package bytes".to_vec();
        let (out, signed) = maybe_sign_rpm(bytes.clone(), &Signers::default()).unwrap();
        assert_eq!(out, bytes);
        assert!(!signed);
    }

    #[test]
    fn no_signers_means_no_index_signer_for_any_format() {
        let signers = Signers::default();
        for format in PackageFormat::ALL {
            assert!(signers.for_format(format).is_none());
        }
    }

    #[test]
    fn apk_signer_loads_a_pkcs8_key_and_produces_a_signature() {
        let signer = ApkSigner::from_config(&ApkSigningConfig {
            key: Some(TEST_RSA_PKCS8.to_string()),
            key_path: None,
            key_name: "silo@example.com-deadbeef.rsa.pub".to_string(),
        })
        .unwrap();

        assert_eq!(signer.key_name(), "silo@example.com-deadbeef.rsa.pub");
        let sig = signer.sign(b"APKINDEX bytes").unwrap();
        // PKCS#1 v1.5 signatures are exactly the modulus size.
        assert_eq!(sig.len(), 256);
        // Deterministic scheme: the same input must sign identically.
        assert_eq!(sig, signer.sign(b"APKINDEX bytes").unwrap());
        assert_ne!(sig, signer.sign(b"different bytes").unwrap());
    }

    #[test]
    fn apk_signer_rejects_a_missing_key_name() {
        let err = ApkSigner::from_config(&ApkSigningConfig {
            key: Some(TEST_RSA_PKCS8.to_string()),
            key_path: None,
            key_name: "  ".to_string(),
        })
        .unwrap_err();
        assert!(err.to_string().contains("key_name"));
    }

    #[test]
    fn apk_signer_rejects_garbage_key_material() {
        let err = ApkSigner::from_config(&ApkSigningConfig {
            key: Some("-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----".to_string()),
            key_path: None,
            key_name: "k".to_string(),
        })
        .unwrap_err();
        assert!(err.to_string().contains("apk signing key"));
    }

    #[test]
    fn apk_signer_is_wired_up_for_the_apk_format_only() {
        let signers = Signers::from_config(&SigningConfig {
            gpg: None,
            apk: Some(ApkSigningConfig {
                key: Some(TEST_RSA_PKCS8.to_string()),
                key_path: None,
                key_name: "k.rsa.pub".to_string(),
            }),
        })
        .unwrap();
        assert!(signers.for_format(PackageFormat::Apk).is_some());
        assert!(signers.for_format(PackageFormat::Rpm).is_none());
        assert!(signers.for_format(PackageFormat::Npm).is_none());
    }

    #[test]
    fn the_public_key_is_derived_from_the_configured_private_key() {
        let signer = test_gpg_signer();
        let armored = signer.armored_public_key();

        assert!(armored.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        // The whole point of deriving rather than configuring a second
        // key: what is served must never contain secret key material.
        assert!(!armored.contains("PRIVATE KEY"));

        // Same fingerprint on both halves — a public key that identified a
        // different key would import cleanly and then fail every
        // signature check, which is the failure this guards against.
        let (secret, _) = SignedSecretKey::from_string(TEST_GPG_SECRET_KEY).unwrap();
        let (public, _) = SignedPublicKey::from_string(armored).unwrap();
        assert_eq!(
            public.fingerprint(),
            secret.fingerprint(),
            "the served public key is not the public half of the signing key"
        );

        // User IDs and their self-signatures have to survive the export:
        // gpg and rpm both reject a key with no valid user ID.
        assert!(
            public.verify_bindings().is_ok(),
            "the exported key does not verify"
        );
        assert!(!public.details.users.is_empty(), "no user id was exported");
    }

    #[test]
    fn the_derived_public_key_verifies_what_the_private_half_signed() {
        let signer = test_gpg_signer();
        let armored_signature = signer.sign(b"repomd.xml bytes").unwrap();

        let (public, _) = SignedPublicKey::from_string(signer.armored_public_key()).unwrap();
        let (signature, _) =
            DetachedSignature::from_armor_single(std::io::Cursor::new(&armored_signature)).unwrap();

        signature
            .verify(&public, &b"repomd.xml bytes"[..])
            .expect("the served key must verify a signature made by the configured key");
        assert!(
            signature.verify(&public, &b"tampered"[..]).is_err(),
            "verification must actually be checking the data"
        );
    }

    #[test]
    fn malformed_gpg_keys_fail_at_load_time() {
        let err = GpgSigner::from_config(&GpgConfig {
            key: Some("-----BEGIN PGP PRIVATE KEY BLOCK-----\ngarbage\n-----END PGP PRIVATE KEY BLOCK-----".into()),
            key_path: None,
            passphrase: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("gpg secret key"));
    }
}
