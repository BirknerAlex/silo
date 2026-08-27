//! Package format parsing, storage layout, and index rendering.
//!
//! Three formats are supported: RPM (`dnf`/`yum`), Alpine APK (`apk`), and
//! npm. Everything format-specific lives behind the [`Format`] trait so the
//! rest of the codebase — publish flow, HTTP surface, database index —
//! never matches on a format enum except to dispatch through
//! [`PackageFormat::handler`].
//!
//! The three formats differ in every dimension that matters, which is why
//! the trait is shaped the way it is:
//!
//! | | storage layout | index unit ("group") |
//! |---|---|---|
//! | rpm | `{repo}/{ch}/Packages/{file}` | the whole channel |
//! | apk | `{repo}/{ch}/apk/{arch}/{file}` | one architecture |
//! | npm | `{repo}/{ch}/npm/{name}/-/{file}` | one package name |
//!
//! All three indexes are pure functions of the database. Whatever a
//! format's index needs that the common columns don't hold is extracted
//! once, at publish, into the row's `metadata` — so regenerating an index
//! never reads a package back out of object storage.
//!
//! `index_group` is the abstraction that makes those the same shape: a
//! publish invalidates exactly one group, and regenerating a group is the
//! unit of work that gets a distributed lock taken out on it.

pub mod apk;
pub mod npm;
pub mod repodata;
pub mod rpm;

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(any(test, feature = "test-util"))]
pub mod testutil;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageFormat {
    Rpm,
    Apk,
    Npm,
}

impl PackageFormat {
    pub const ALL: [PackageFormat; 3] =
        [PackageFormat::Rpm, PackageFormat::Apk, PackageFormat::Npm];

    pub fn as_str(&self) -> &'static str {
        match self {
            PackageFormat::Rpm => "rpm",
            PackageFormat::Apk => "apk",
            PackageFormat::Npm => "npm",
        }
    }

    /// The format-specific behaviour: parsing, layout, index rendering.
    pub fn handler(&self) -> &'static dyn Format {
        match self {
            PackageFormat::Rpm => &rpm::RpmFormat,
            PackageFormat::Apk => &apk::ApkFormat,
            PackageFormat::Npm => &npm::NpmFormat,
        }
    }

    /// Best-effort format detection from a filename, used by the CLI so
    /// `silo publish ./foo.apk` doesn't need an explicit `--format`.
    pub fn from_filename(filename: &str) -> Option<Self> {
        let lower = filename.to_ascii_lowercase();
        if lower.ends_with(".rpm") {
            Some(PackageFormat::Rpm)
        } else if lower.ends_with(".apk") {
            Some(PackageFormat::Apk)
        } else if lower.ends_with(".tgz") || lower.ends_with(".tar.gz") {
            Some(PackageFormat::Npm)
        } else {
            None
        }
    }
}

impl fmt::Display for PackageFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PackageFormat {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "rpm" => Ok(PackageFormat::Rpm),
            "apk" | "alpine" => Ok(PackageFormat::Apk),
            "npm" | "node" => Ok(PackageFormat::Npm),
            other => Err(ParseError::UnknownFormat(other.to_string())),
        }
    }
}

/// Format-agnostic metadata extracted from a validated package upload.
///
/// `metadata` carries whatever the format's index needs that doesn't fit
/// the common fields (APKINDEX records, the npm `package.json`). It's
/// stored verbatim as JSONB so index regeneration never has to re-read
/// package bytes out of object storage for apk/npm.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedPackage {
    pub format: PackageFormat,
    pub name: String,
    pub epoch: u32,
    pub version: String,
    /// RPM release ("1", "2.el9"). Empty for formats without one.
    pub release: String,
    /// RPM/APK architecture. `any` for npm, which is arch-independent.
    pub arch: String,
    pub filename: String,
    pub metadata: serde_json::Value,
    pub payload: Vec<u8>,
}

impl ParsedPackage {
    /// Human-readable identity used in logs, audit entries and CLI output.
    pub fn nevra(&self) -> String {
        match self.format {
            PackageFormat::Rpm => {
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
            PackageFormat::Apk => format!("{}-{}.{}", self.name, self.version, self.arch),
            PackageFormat::Npm => format!("{}@{}", self.name, self.version),
        }
    }
}

/// One row of the package index, as stored in Postgres and handed back to
/// index renderers. This is the reason a publish doesn't need to list S3:
/// everything an apk/npm index needs is already here.
#[derive(Debug, Clone, PartialEq)]
pub struct PackageRecord {
    pub format: PackageFormat,
    pub name: String,
    pub epoch: u32,
    pub version: String,
    pub release: String,
    pub arch: String,
    pub filename: String,
    pub storage_key: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub metadata: serde_json::Value,
    /// Unix seconds.
    pub published_at: i64,
}

/// An object an index renderer wants written to storage.
#[derive(Debug, Clone, PartialEq)]
pub struct IndexObject {
    /// Storage key, relative to the group's index prefix.
    pub name: String,
    pub bytes: Vec<u8>,
    pub content_type: &'static str,
}

/// Everything an index renderer is allowed to depend on. Deliberately does
/// not include object storage: every index is a pure function of the rows
/// in `records`.
pub struct IndexContext<'a> {
    pub repo: &'a str,
    pub channel: &'a str,
    /// The group being regenerated (arch for apk, package name for npm,
    /// empty for rpm).
    pub group: &'a str,
    pub records: &'a [PackageRecord],
    /// Absolute base URL the server is reachable at, when configured.
    /// npm packuments must embed absolute tarball URLs.
    pub public_base_url: Option<&'a str>,
    /// Format-specific signing hook, if the server has a key configured.
    pub signer: Option<&'a dyn IndexSigner>,
}

/// Detached-signature hook for index files. Implemented in `silo-core`,
/// which owns the key material; kept as a trait here so this crate stays
/// free of crypto/key-handling dependencies.
pub trait IndexSigner: Send + Sync {
    /// Key identity embedded in the signature envelope (apk uses this as
    /// the `.SIGN.RSA.<name>` member name).
    fn key_name(&self) -> &str;
    fn sign(&self, data: &[u8]) -> anyhow::Result<Vec<u8>>;
}

/// The per-format seam. One implementation per supported format; adding a
/// format means adding an impl and a `PackageFormat` variant, and nothing
/// else in the codebase needs to learn about it.
pub trait Format: Send + Sync {
    fn format(&self) -> PackageFormat;

    /// Validate an upload and extract everything the index will need.
    fn parse(&self, bytes: &[u8]) -> Result<ParsedPackage, ParseError>;

    /// Where the package bytes live, relative to the bucket root.
    fn storage_key(&self, repo: &str, channel: &str, pkg: &ParsedPackage) -> String;

    /// Which index a package belongs to. A publish invalidates exactly one
    /// group, and the group is what gets locked during regeneration.
    fn index_group(&self, pkg: &ParsedPackage) -> String;

    /// Other groups whose packages also belong in `group`'s index.
    ///
    /// apk is the only format that needs this, and it needs it because
    /// apk-tools only ever fetches `$repo/$hostarch/APKINDEX.tar.gz` and
    /// never looks anywhere else — so a `noarch` package is invisible
    /// unless it appears in every architecture's index. Alpine's own
    /// repositories solve the same problem by copying noarch packages
    /// into each architecture at build time.
    fn shared_groups(&self, _group: &str) -> Vec<String> {
        Vec::new()
    }

    /// True when this group's contents appear in *other* groups' indexes,
    /// so publishing into it invalidates them as well.
    ///
    /// The inverse of [`Format::shared_groups`]: that says what to read,
    /// this says what to rewrite.
    fn is_shared_group(&self, _group: &str) -> bool {
        false
    }

    /// Storage prefix the group's index objects are written under.
    fn index_prefix(&self, repo: &str, channel: &str, group: &str) -> String;

    /// Re-derives the row's `metadata` from the bytes that will actually
    /// be stored, after any server-side rewriting.
    ///
    /// Only RPM needs this, and only because silo signs RPMs: signing
    /// rewrites the signature header, so metadata read from the uploaded
    /// bytes would describe a file that no longer exists. Returning `None`
    /// — the default — means "what `parse` extracted is still true", which
    /// it is for every format silo does not rewrite.
    fn index_metadata(&self, _stored: &[u8]) -> Result<Option<serde_json::Value>, ParseError> {
        Ok(None)
    }

    /// Render the group's index. Async because some renderers do I/O.
    fn build_index<'a>(
        &'a self,
        ctx: &'a IndexContext<'a>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<Vec<IndexObject>>> + Send + 'a>,
    >;
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("failed to parse rpm package: {0}")]
    Rpm(#[from] ::rpm::Error),
    #[error("unknown package format: {0}")]
    UnknownFormat(String),
    #[error("{0}")]
    Invalid(String),
    #[error("io error reading package: {0}")]
    Io(#[from] std::io::Error),
}

impl ParseError {
    pub fn invalid(msg: impl Into<String>) -> Self {
        ParseError::Invalid(msg.into())
    }
}

/// Splits a file made of back-to-back gzip members into its members'
/// *raw compressed* byte ranges.
///
/// Both apk and npm tarballs are gzip, but only apk relies on the
/// multi-member layout (signature ++ control ++ data), and apk's index
/// checksums are taken over the compressed bytes of a single member — so
/// the split has to preserve exact byte boundaries rather than just
/// concatenating the inflated output the way `MultiGzDecoder` would.
pub(crate) fn split_gzip_members(bytes: &[u8]) -> Result<Vec<(usize, usize)>, ParseError> {
    use std::io::Read;

    let mut ranges = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        // Trailing NULs/padding after the last member: not another member.
        if bytes[offset..].len() < 18 || bytes[offset] != 0x1f || bytes[offset + 1] != 0x8b {
            break;
        }
        let remaining = &bytes[offset..];
        let mut decoder = flate2::bufread::GzDecoder::new(remaining);
        let mut sink = Vec::new();
        decoder
            .read_to_end(&mut sink)
            .map_err(|e| ParseError::invalid(format!("corrupt gzip member: {e}")))?;
        // `bufread::GzDecoder` consumes exactly one member and leaves the
        // reader positioned at the next one, which is what lets us recover
        // the member's compressed length.
        let left = decoder.into_inner().len();
        let consumed = remaining.len() - left;
        if consumed == 0 {
            break;
        }
        ranges.push((offset, offset + consumed));
        offset += consumed;
    }
    if ranges.is_empty() {
        return Err(ParseError::invalid("not a gzip file"));
    }
    Ok(ranges)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_round_trips_through_str() {
        for f in PackageFormat::ALL {
            assert_eq!(PackageFormat::from_str(f.as_str()).unwrap(), f);
        }
    }

    #[test]
    fn format_detected_from_filename() {
        assert_eq!(
            PackageFormat::from_filename("foo-1.0-1.x86_64.rpm"),
            Some(PackageFormat::Rpm)
        );
        assert_eq!(
            PackageFormat::from_filename("foo-1.0-r0.apk"),
            Some(PackageFormat::Apk)
        );
        assert_eq!(
            PackageFormat::from_filename("foo-1.0.0.tgz"),
            Some(PackageFormat::Npm)
        );
        assert_eq!(PackageFormat::from_filename("foo.txt"), None);
    }

    #[test]
    fn unknown_format_string_is_an_error() {
        assert!(PackageFormat::from_str("deb").is_err());
    }

    #[test]
    fn splits_concatenated_gzip_members() {
        use std::io::Write;
        let mut combined = Vec::new();
        for payload in [
            b"first".as_slice(),
            b"second".as_slice(),
            b"third".as_slice(),
        ] {
            let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            enc.write_all(payload).unwrap();
            combined.extend(enc.finish().unwrap());
        }
        let ranges = split_gzip_members(&combined).unwrap();
        assert_eq!(ranges.len(), 3);
        assert_eq!(ranges[0].0, 0);
        assert_eq!(ranges[2].1, combined.len());
        // Ranges must be contiguous and non-overlapping.
        assert_eq!(ranges[0].1, ranges[1].0);
        assert_eq!(ranges[1].1, ranges[2].0);
    }

    #[test]
    fn rejects_non_gzip_bytes() {
        assert!(split_gzip_members(b"definitely not gzip").is_err());
    }
}
