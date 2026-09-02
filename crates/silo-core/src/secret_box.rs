//! Reversible encryption for upstream credentials.
//!
//! Every other secret in this codebase is either one-way (tokens are
//! hashed with a pepper, never recovered — see `silo-db::tokens`) or
//! loaded straight from config and never round-tripped through the
//! database (signing keys — see [`crate::signing`]). Pull-through cache
//! breaks that pattern: silo has to authenticate *outbound* to an
//! upstream registry on a client's behalf, which means storing a real
//! username/password or bearer token somewhere it can be read back.
//!
//! The key itself follows the same convention as `AuthConfig.token_pepper`
//! and the signing keys: it lives in server config (env-expanded, never in
//! the database), and rotating it invalidates every secret encrypted under
//! the old one — an accepted, documented failure mode rather than
//! something this module tries to work around with key versioning.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::Engine;
use rand::Rng;

/// A 256-bit AES-GCM key, loaded once at startup so a malformed key is a
/// startup failure rather than a failure on the first `add-upstream`.
#[derive(Clone)]
pub struct SecretBox {
    cipher: Aes256Gcm,
}

// Hand-written so an accidental `{:?}` can never print key material —
// same convention as `GpgSigner`/`ApkSigner` in `signing.rs`.
impl std::fmt::Debug for SecretBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretBox").finish_non_exhaustive()
    }
}

/// Ciphertext and nonce, the shape stored in `upstreams.auth_secret_*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

impl SecretBox {
    /// `key` is 32 raw bytes, base64-encoded in config (`UpstreamSecretConfig.key`).
    pub fn new(key_base64: &str) -> anyhow::Result<Self> {
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(key_base64.trim())
            .map_err(|e| anyhow::anyhow!("upstream secret key is not valid base64: {e}"))?;
        if key_bytes.len() != 32 {
            anyhow::bail!(
                "upstream secret key must decode to 32 bytes, got {}",
                key_bytes.len()
            );
        }
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        Ok(Self {
            cipher: Aes256Gcm::new(key),
        })
    }

    /// Encrypts `plaintext` under a freshly generated random nonce.
    pub fn seal(&self, plaintext: &str) -> anyhow::Result<Sealed> {
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|_| anyhow::anyhow!("failed to encrypt upstream secret"))?;
        Ok(Sealed {
            ciphertext,
            nonce: nonce_bytes.to_vec(),
        })
    }

    /// Decrypts a value sealed by [`Self::seal`] with the same key.
    /// Fails on a wrong key, a truncated/corrupted nonce, or tampered
    /// ciphertext — AES-GCM's tag makes all three indistinguishable, which
    /// is the point: nothing here needs to (or can) tell them apart.
    pub fn open(&self, sealed: &Sealed) -> anyhow::Result<String> {
        if sealed.nonce.len() != 12 {
            anyhow::bail!(
                "upstream secret nonce must be 12 bytes, got {}",
                sealed.nonce.len()
            );
        }
        let nonce = Nonce::from_slice(&sealed.nonce);
        let plaintext = self
            .cipher
            .decrypt(nonce, sealed.ciphertext.as_slice())
            .map_err(|_| {
                anyhow::anyhow!("failed to decrypt upstream secret (wrong key or corrupted data)")
            })?;
        String::from_utf8(plaintext)
            .map_err(|e| anyhow::anyhow!("decrypted upstream secret is not valid utf-8: {e}"))
    }

    /// Generates a fresh 32-byte key, base64-encoded — what an operator
    /// runs once to populate `upstream_secret.key` in config.
    pub fn generate_key() -> String {
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        base64::engine::general_purpose::STANDARD.encode(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_box() -> SecretBox {
        SecretBox::new(&SecretBox::generate_key()).unwrap()
    }

    #[test]
    fn round_trips_a_secret() {
        let sb = test_box();
        let sealed = sb.seal("hunter2").unwrap();
        assert_eq!(sb.open(&sealed).unwrap(), "hunter2");
    }

    #[test]
    fn two_seals_of_the_same_secret_use_different_nonces_and_ciphertexts() {
        let sb = test_box();
        let a = sb.seal("hunter2").unwrap();
        let b = sb.seal("hunter2").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn the_wrong_key_fails_to_decrypt() {
        let sealed = test_box().seal("hunter2").unwrap();
        let other = test_box();
        assert!(other.open(&sealed).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails_to_decrypt() {
        let sb = test_box();
        let mut sealed = sb.seal("hunter2").unwrap();
        sealed.ciphertext[0] ^= 0xff;
        assert!(sb.open(&sealed).is_err());
    }

    #[test]
    fn tampered_nonce_fails_to_decrypt() {
        let sb = test_box();
        let mut sealed = sb.seal("hunter2").unwrap();
        sealed.nonce[0] ^= 0xff;
        assert!(sb.open(&sealed).is_err());
    }

    #[test]
    fn debug_never_prints_key_material() {
        let sb = test_box();
        let printed = format!("{sb:?}");
        assert_eq!(printed, "SecretBox { .. }");
    }

    #[test]
    fn rejects_a_key_of_the_wrong_length() {
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        assert!(SecretBox::new(&short).is_err());
    }

    #[test]
    fn rejects_non_base64_key_material() {
        assert!(SecretBox::new("not base64 at all !!!").is_err());
    }

    #[test]
    fn generated_keys_are_usable() {
        let key = SecretBox::generate_key();
        assert!(SecretBox::new(&key).is_ok());
    }
}
