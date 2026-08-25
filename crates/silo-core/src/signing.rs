use crate::config::GpgConfig;

/// Signs an RPM's bytes in place using the server's configured GPG key.
/// Returns the original bytes unchanged if no GPG key is configured —
/// signing is optional per the MVP scope.
pub fn maybe_sign(bytes: Vec<u8>, gpg: Option<&GpgConfig>) -> anyhow::Result<(Vec<u8>, bool)> {
    let Some(gpg) = gpg else {
        return Ok((bytes, false));
    };
    let key = gpg.resolve_key()?;
    let signed = silo_rpm::sign_rpm(&bytes, &key, gpg.passphrase.as_deref())?;
    Ok((signed, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_gpg_config_leaves_bytes_untouched() {
        let bytes = b"raw package bytes".to_vec();
        let (out, signed) = maybe_sign(bytes.clone(), None).unwrap();
        assert_eq!(out, bytes);
        assert!(!signed);
    }
}
