//! Package format parsing/validation.
//!
//! RPM is the only implemented format for the MVP. `PackageFormat` and
//! `ParsedPackage` exist as the seam future formats (deb, generic) plug
//! into — the trait boundary lives here, not scattered across callers.

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageFormat {
    Rpm,
}

impl PackageFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            PackageFormat::Rpm => "rpm",
        }
    }
}

/// Format-agnostic metadata extracted from a validated package.
/// Every `PackageParser` impl produces one of these regardless of
/// the underlying binary format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPackage {
    pub format: PackageFormat,
    pub name: String,
    pub epoch: u32,
    pub version: String,
    pub release: String,
    pub arch: String,
    pub filename: String,
    pub payload: Vec<u8>,
}

impl ParsedPackage {
    /// `name-epoch:version-release.arch`-derived path segment used for
    /// layout under a repo/channel prefix in storage.
    pub fn nevra(&self) -> String {
        if self.epoch == 0 {
            format!(
                "{}-{}-{}.{}",
                self.name, self.version, self.release, self.arch
            )
        } else {
            format!(
                "{}-{}:{}-{}.{}",
                self.name, self.epoch, self.version, self.release, self.arch
            )
        }
    }
}

/// Recovers name/version/release/arch from a canonical RPM filename
/// (`name-version-release.arch.rpm`), the form `Package::canonical_filename`
/// produces and the only form Silo ever stores. RPM version/release
/// segments never contain `-` by convention, so splitting from the right
/// is unambiguous even when the package name itself contains hyphens.
pub fn parse_nvra_filename(filename: &str) -> Option<(String, String, String, String)> {
    let stem = filename.strip_suffix(".rpm")?;
    let (rest, arch) = stem.rsplit_once('.')?;
    let (name_version, release) = rest.rsplit_once('-')?;
    let (name, version) = name_version.rsplit_once('-')?;
    if name.is_empty() || version.is_empty() || release.is_empty() || arch.is_empty() {
        return None;
    }
    Some((
        name.to_string(),
        version.to_string(),
        release.to_string(),
        arch.to_string(),
    ))
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("failed to parse rpm package: {0}")]
    Rpm(#[from] rpm::Error),
    #[error("package is not architecture-specific and cannot be indexed: {0}")]
    MissingArch(String),
}

pub trait PackageParser {
    fn format(&self) -> PackageFormat;
    fn parse(&self, bytes: &[u8]) -> Result<ParsedPackage, ParseError>;
}

pub struct RpmParser;

impl PackageParser for RpmParser {
    fn format(&self) -> PackageFormat {
        PackageFormat::Rpm
    }

    fn parse(&self, bytes: &[u8]) -> Result<ParsedPackage, ParseError> {
        let mut reader: &[u8] = bytes;
        let pkg = rpm::Package::parse(&mut reader)?;
        let name = pkg.metadata.get_name()?.to_string();
        let epoch = pkg.metadata.get_epoch().unwrap_or(0);
        let version = pkg.metadata.get_version()?.to_string();
        let release = pkg.metadata.get_release()?.to_string();
        let arch = pkg.metadata.get_arch()?.to_string();
        let filename = pkg.canonical_filename()?;

        Ok(ParsedPackage {
            format: PackageFormat::Rpm,
            name,
            epoch,
            version,
            release,
            arch,
            filename,
            payload: bytes.to_vec(),
        })
    }
}

/// Re-parses an RPM after signing so callers get metadata consistent
/// with what's actually on disk/in S3, and re-serializes it to bytes.
pub fn sign_rpm(
    bytes: &[u8],
    asc_secret_key: &str,
    key_passphrase: Option<&str>,
) -> Result<Vec<u8>, ParseError> {
    let mut reader: &[u8] = bytes;
    let mut pkg = rpm::Package::parse(&mut reader)?;

    let mut signer = rpm::signature::pgp::Signer::from_asc(asc_secret_key)?;
    if let Some(passphrase) = key_passphrase {
        signer = signer.with_key_passphrase(passphrase);
    }
    pkg.sign(signer)?;

    let mut out = Vec::new();
    pkg.write(&mut out)?;
    Ok(out)
}

/// Builds a minimal-but-valid unsigned RPM in memory. Used by this crate's
/// own tests and exported (behind `test-util`) so other crates can build
/// fixtures without needing a real `.rpm` file on disk.
#[cfg(any(test, feature = "test-util"))]
pub fn build_test_rpm(name: &str, version: &str, release: &str, arch: &str) -> Vec<u8> {
    let pkg = rpm::PackageBuilder::new(name, version, "MIT", arch, "a test package")
        .release(release)
        .with_file_contents(
            "hello from silo\n",
            rpm::FileOptions::new(format!("/usr/share/{name}/hello.txt")),
        )
        .expect("add file")
        .build()
        .expect("build rpm");
    let mut buf = Vec::new();
    pkg.write(&mut buf).expect("write rpm");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_rpm() -> Vec<u8> {
        let pkg = rpm::PackageBuilder::new("silo-test", "1.2.3", "MIT", "x86_64", "a test package")
            .epoch(1)
            .release("4")
            .with_file_contents(
                "hello from silo\n",
                rpm::FileOptions::new("/usr/share/silo-test/hello.txt"),
            )
            .expect("add file")
            .build()
            .expect("build rpm");
        let mut buf = Vec::new();
        pkg.write(&mut buf).expect("write rpm");
        buf
    }

    #[test]
    fn parses_valid_rpm_metadata() {
        let bytes = build_test_rpm();
        let parsed = RpmParser.parse(&bytes).expect("parse rpm");
        assert_eq!(parsed.name, "silo-test");
        assert_eq!(parsed.version, "1.2.3");
        assert_eq!(parsed.release, "4");
        assert_eq!(parsed.epoch, 1);
        assert_eq!(parsed.arch, "x86_64");
        assert_eq!(parsed.format, PackageFormat::Rpm);
        assert_eq!(parsed.nevra(), "silo-test-1:1.2.3-4.x86_64");
    }

    #[test]
    fn rejects_garbage_bytes() {
        let err = RpmParser.parse(b"not an rpm file at all").unwrap_err();
        assert!(matches!(err, ParseError::Rpm(_)));
    }

    #[test]
    fn parses_canonical_filename_back_into_nvra() {
        let (name, version, release, arch) =
            parse_nvra_filename("silo-test-1.2.3-4.x86_64.rpm").unwrap();
        assert_eq!(name, "silo-test");
        assert_eq!(version, "1.2.3");
        assert_eq!(release, "4");
        assert_eq!(arch, "x86_64");
    }

    #[test]
    fn parses_filename_with_hyphenated_name() {
        let (name, version, release, arch) =
            parse_nvra_filename("my-cool-daemon-2.0.0-1.noarch.rpm").unwrap();
        assert_eq!(name, "my-cool-daemon");
        assert_eq!(version, "2.0.0");
        assert_eq!(release, "1");
        assert_eq!(arch, "noarch");
    }

    #[test]
    fn rejects_non_rpm_filename() {
        assert!(parse_nvra_filename("not-an-rpm.txt").is_none());
    }

    #[test]
    fn nevra_without_epoch_omits_epoch_segment() {
        let parsed = ParsedPackage {
            format: PackageFormat::Rpm,
            name: "foo".into(),
            epoch: 0,
            version: "1.0".into(),
            release: "1".into(),
            arch: "noarch".into(),
            filename: "foo-1.0-1.noarch.rpm".into(),
            payload: vec![],
        };
        assert_eq!(parsed.nevra(), "foo-1.0-1.noarch");
    }
}
