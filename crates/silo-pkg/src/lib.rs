//! Package format parsing, storage layout, and index rendering.
//!
//! Five formats are supported: RPM (`dnf`/`yum`), Alpine APK (`apk`), npm,
//! pacman (Arch Linux), and Debian (`apt`). Everything format-specific
//! lives behind the [`Format`] trait so the rest of the codebase — publish
//! flow, HTTP surface, database index — never matches on a format enum
//! except to dispatch through [`PackageFormat::handler`].
//!
//! The formats differ in every dimension that matters, which is why the
//! trait is shaped the way it is:
//!
//! | | storage layout | index unit ("group") |
//! |---|---|---|
//! | rpm | `{repo}/{ch}/Packages/{file}` | the whole channel |
//! | apk | `{repo}/{ch}/apk/{arch}/{file}` | one architecture |
//! | pacman | `{repo}/{ch}/pacman/{arch}/{file}` | one architecture |
//! | npm | `{repo}/{ch}/npm/{name}/-/{file}` | one package name |
//! | deb | `{repo}/{ch}/pool/{file}` | the whole channel |
//!
//! All five indexes are pure functions of the database. Whatever a
//! format's index needs that the common columns don't hold is extracted
//! once, at publish, into the row's `metadata` — so regenerating an index
//! never reads a package back out of object storage.
//!
//! `index_group` is the abstraction that makes those the same shape: a
//! publish invalidates exactly one group, and regenerating a group is the
//! unit of work that gets a distributed lock taken out on it.

pub mod apk;
pub mod deb;
pub mod npm;
pub mod pacman;
pub mod repodata;
pub mod rpm;
pub mod upstream;

pub use upstream::{
    UpstreamError, UpstreamFetchOptions, UpstreamHttp, UpstreamIndex, UpstreamPackage,
};

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
    Pacman,
    Deb,
}

impl PackageFormat {
    pub const ALL: [PackageFormat; 5] = [
        PackageFormat::Rpm,
        PackageFormat::Apk,
        PackageFormat::Npm,
        PackageFormat::Pacman,
        PackageFormat::Deb,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            PackageFormat::Rpm => "rpm",
            PackageFormat::Apk => "apk",
            PackageFormat::Npm => "npm",
            PackageFormat::Pacman => "pacman",
            PackageFormat::Deb => "deb",
        }
    }

    /// The format-specific behaviour: parsing, layout, index rendering.
    pub fn handler(&self) -> &'static dyn Format {
        match self {
            PackageFormat::Rpm => &rpm::RpmFormat,
            PackageFormat::Apk => &apk::ApkFormat,
            PackageFormat::Npm => &npm::NpmFormat,
            PackageFormat::Pacman => &pacman::PacmanFormat,
            PackageFormat::Deb => &deb::DebFormat,
        }
    }

    /// Compares two `(epoch, version, release)` triples in this format's
    /// own version ordering — what decides whether an upstream package is
    /// newer than a locally cached one. Dispatches to each format's own
    /// comparator (`rpm::version_cmp`, `apk::version_cmp`, ...), since the
    /// five ecosystems don't share one: apk/npm have no separate release
    /// field, apk has no epoch at all, and each has its own tie-breaking
    /// rules within the version string itself. See each comparator's own
    /// doc for the specific algorithm and its known limitations.
    pub fn compare_versions(
        &self,
        a: (u32, &str, &str),
        b: (u32, &str, &str),
    ) -> std::cmp::Ordering {
        match self {
            PackageFormat::Rpm => rpm::version_cmp(a.0, a.1, a.2, b.0, b.1, b.2),
            PackageFormat::Apk => apk::version_cmp(a.1, b.1),
            PackageFormat::Npm => npm::version_cmp(a.1, b.1),
            PackageFormat::Pacman => a.0.cmp(&b.0).then_with(|| {
                pacman::version_cmp(
                    &join_version_release(a.1, a.2),
                    &join_version_release(b.1, b.2),
                )
            }),
            PackageFormat::Deb => deb::version_cmp(
                &join_epoch_version_release(a),
                &join_epoch_version_release(b),
            ),
        }
    }

    /// The upstream-index counterpart to [`Self::handler`]: fetching and
    /// parsing a *third party's* index, rather than rendering silo's own.
    pub fn upstream_handler(&self) -> &'static dyn UpstreamIndex {
        match self {
            PackageFormat::Rpm => &rpm::RpmUpstream,
            PackageFormat::Apk => &apk::ApkUpstream,
            PackageFormat::Npm => &npm::NpmUpstream,
            PackageFormat::Pacman => &pacman::PacmanUpstream,
            PackageFormat::Deb => &deb::DebUpstream,
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
        } else if lower.ends_with(".deb") {
            Some(PackageFormat::Deb)
        } else if lower.ends_with(".pkg.tar.zst")
            || lower.ends_with(".pkg.tar.xz")
            || lower.ends_with(".pkg.tar.gz")
        {
            Some(PackageFormat::Pacman)
        } else if lower.ends_with(".tgz") || lower.ends_with(".tar.gz") {
            Some(PackageFormat::Npm)
        } else {
            None
        }
    }
}

fn join_version_release(version: &str, release: &str) -> String {
    if release.is_empty() {
        version.to_string()
    } else {
        format!("{version}-{release}")
    }
}

fn join_epoch_version_release((epoch, version, release): (u32, &str, &str)) -> String {
    let joined = join_version_release(version, release);
    if epoch == 0 {
        joined
    } else {
        format!("{epoch}:{joined}")
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
            "pacman" | "aur" | "arch" => Ok(PackageFormat::Pacman),
            "deb" | "apt" | "debian" => Ok(PackageFormat::Deb),
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
            PackageFormat::Deb => {
                if self.release.is_empty() {
                    format!("{}_{}_{}", self.name, self.version, self.arch)
                } else {
                    format!(
                        "{}_{}-{}_{}",
                        self.name, self.version, self.release, self.arch
                    )
                }
            }
            PackageFormat::Pacman => {
                if self.epoch == 0 {
                    format!(
                        "{}-{}-{}-{}",
                        self.name, self.version, self.release, self.arch
                    )
                } else {
                    format!(
                        "{}-{}:{}-{}-{}",
                        self.name, self.epoch, self.version, self.release, self.arch
                    )
                }
            }
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

    /// OpenPGP cleartext-signs `text`, for apt's `InRelease` — a `Release`
    /// file and its detached signature folded into one document via the
    /// Cleartext Signature Framework, rather than `Release` plus a sibling
    /// `Release.gpg`.
    ///
    /// `Ok(None)` — the default — means this signer has no cleartext-sign
    /// story, true of every signer but the OpenPGP one deb reuses from RPM.
    fn clearsign(&self, _text: &str) -> anyhow::Result<Option<String>> {
        Ok(None)
    }
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

/// Ceiling on how far a single uploaded package may inflate.
///
/// Every parser here has to decompress an archive to reach the one small
/// metadata file it needs, and a compressor will happily turn a few
/// megabytes into terabytes of zeroes. Without a bound, any caller allowed
/// to publish can drive the server out of memory with an upload that
/// passes the `MAX_PACKAGE_BYTES` size check comfortably — xz and zstd
/// both reach ratios well past 1000:1.
///
/// The value is twice the upload ceiling: real packages compress, so
/// nothing legitimate inflates past it, and it keeps the worst case
/// (compressed upload plus inflated copy) to a size a server can survive.
pub const MAX_INFLATED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Ceiling on a metadata file read out of an archive (`.PKGINFO`,
/// `package.json`). These are a few kilobytes in practice; the bound is
/// generous but stops a crafted archive from declaring one entry the size
/// of the whole inflated stream.
pub(crate) const MAX_METADATA_BYTES: u64 = 16 * 1024 * 1024;

/// Reads a decompressing reader to the end, refusing to buffer more than
/// `limit` bytes.
///
/// Every caller passes [`MAX_INFLATED_BYTES`]; the limit is a parameter so
/// tests can drive the rejection path with a bomb that fits in a test
/// rather than one that has to allocate gigabytes to prove the point.
pub(crate) fn inflate_capped<R: std::io::Read>(
    reader: R,
    limit: u64,
    what: &str,
) -> Result<Vec<u8>, ParseError> {
    use std::io::Read;

    let mut out = Vec::new();
    // `limit + 1` so a stream that stops exactly at the ceiling is still
    // distinguishable from one that ran past it.
    reader
        .take(limit + 1)
        .read_to_end(&mut out)
        .map_err(|e| ParseError::invalid(format!("corrupt {what}: {e}")))?;
    if out.len() as u64 > limit {
        return Err(ParseError::invalid(format!(
            "{what} inflates past the {} MiB decompression limit",
            limit / (1024 * 1024)
        )));
    }
    Ok(out)
}

/// Reads one archive entry as UTF-8 text, bounded by
/// [`MAX_METADATA_BYTES`].
pub(crate) fn read_text_capped<R: std::io::Read>(
    reader: R,
    what: &str,
) -> Result<String, ParseError> {
    use std::io::Read;

    let mut text = String::new();
    reader
        .take(MAX_METADATA_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| ParseError::invalid(format!("unreadable {what}: {e}")))?;
    if text.len() as u64 > MAX_METADATA_BYTES {
        return Err(ParseError::invalid(format!(
            "{what} is larger than the {} MiB metadata limit",
            MAX_METADATA_BYTES / (1024 * 1024)
        )));
    }
    Ok(text)
}

/// Discards a reader's output, counting it and stopping at `limit`.
///
/// Takes `&mut` rather than ownership because the one caller
/// ([`split_gzip_members`]) needs the reader back afterwards to recover
/// how many *compressed* bytes it consumed.
pub(crate) fn drain_capped<R: std::io::Read>(reader: &mut R, limit: u64) -> std::io::Result<u64> {
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            return Ok(total);
        }
        total += read as u64;
        if total > limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "member inflates past the decompression limit",
            ));
        }
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
    let mut ranges = Vec::new();
    let mut offset = 0usize;
    // Budget shared across every member, not reset per member. A file can
    // hold arbitrarily many valid gzip members, so a per-member cap bounds
    // each one and nothing in total — and this runs on an apk before the
    // control member has even been identified, so it is reachable by
    // anyone who can publish.
    let mut budget = MAX_INFLATED_BYTES;
    while offset < bytes.len() {
        // Trailing NULs/padding after the last member: not another member.
        if bytes[offset..].len() < 18 || bytes[offset] != 0x1f || bytes[offset + 1] != 0x8b {
            break;
        }
        let remaining = &bytes[offset..];
        let mut decoder = flate2::bufread::GzDecoder::new(remaining);
        // The inflated bytes are thrown away — only the compressed length
        // matters here — but they still have to be produced to find the
        // member boundary, so the work is bounded rather than buffered.
        let inflated = drain_capped(&mut decoder, budget)
            .map_err(|e| ParseError::invalid(format!("corrupt gzip member: {e}")))?;
        budget -= inflated;
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

    /// A gzip member that inflates to `count` zero bytes. Zeroes compress
    /// to roughly nothing, which is exactly what makes this shape a cheap
    /// denial of service against an unbounded decompressor.
    fn zeros_gz(count: usize) -> Vec<u8> {
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&vec![0u8; count]).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn inflate_capped_accepts_input_up_to_the_limit() {
        let bytes = zeros_gz(1024);
        let out = inflate_capped(
            flate2::bufread::GzDecoder::new(bytes.as_slice()),
            MAX_INFLATED_BYTES,
            "test",
        )
        .unwrap();
        assert_eq!(out.len(), 1024);

        // Exactly at the ceiling is still allowed through.
        let out = inflate_capped(
            flate2::bufread::GzDecoder::new(zeros_gz(1024).as_slice()),
            1024,
            "test",
        )
        .unwrap();
        assert_eq!(out.len(), 1024);
    }

    #[test]
    fn a_decompression_bomb_is_refused_instead_of_buffered() {
        // 64 MiB of zeroes in about 64 KiB of gzip — the cheap shape of
        // the attack. What matters is that the reader stops at the limit
        // rather than allocating whatever the stream decides to produce.
        let bomb = zeros_gz(64 * 1024 * 1024);
        assert!(
            bomb.len() < 256 * 1024,
            "the input has to be small for this to be the bug it is"
        );

        let err = inflate_capped(
            flate2::bufread::GzDecoder::new(bomb.as_slice()),
            1024 * 1024,
            "package",
        )
        .unwrap_err();
        assert!(err.to_string().contains("decompression limit"), "got {err}");

        // The same stream drained rather than buffered stops too.
        let mut decoder = flate2::bufread::GzDecoder::new(bomb.as_slice());
        assert!(drain_capped(&mut decoder, 1024 * 1024).is_err());
    }

    #[test]
    fn read_text_capped_rejects_a_file_past_the_metadata_limit() {
        let oversized = vec![b'x'; (MAX_METADATA_BYTES + 1) as usize];
        let err = read_text_capped(oversized.as_slice(), ".PKGINFO").unwrap_err();
        assert!(err.to_string().contains("metadata limit"), "got {err}");

        // The boundary itself is allowed through.
        let exact = vec![b'x'; MAX_METADATA_BYTES as usize];
        assert!(read_text_capped(exact.as_slice(), ".PKGINFO").is_ok());
    }

    #[test]
    fn the_inflation_budget_is_shared_across_gzip_members() {
        // Two members that each fit the limit but together exceed it. A
        // per-member cap would wave this through, and an apk can carry as
        // many members as the uploader likes.
        let member = zeros_gz(4 * 1024 * 1024);
        let mut both = member.clone();
        both.extend_from_slice(&member);

        // Sanity: one member alone is well inside a 6 MiB budget.
        let mut decoder = flate2::bufread::GzDecoder::new(member.as_slice());
        assert_eq!(
            drain_capped(&mut decoder, 6 * 1024 * 1024).unwrap(),
            4 * 1024 * 1024
        );

        // Draining them in sequence against one shared budget must not.
        let mut budget = 6u64 * 1024 * 1024;
        let mut decoder = flate2::bufread::GzDecoder::new(both.as_slice());
        budget -= drain_capped(&mut decoder, budget).unwrap();
        let rest = both.len() - decoder.into_inner().len();
        let mut decoder = flate2::bufread::GzDecoder::new(&both[rest..]);
        assert!(
            drain_capped(&mut decoder, budget).is_err(),
            "the second member must be charged against what the first spent"
        );
    }

    #[test]
    fn drain_capped_counts_what_it_discards() {
        let bytes = zeros_gz(4096);
        let mut decoder = flate2::bufread::GzDecoder::new(bytes.as_slice());
        assert_eq!(
            drain_capped(&mut decoder, MAX_INFLATED_BYTES).unwrap(),
            4096
        );
    }

    #[test]
    fn compare_versions_dispatches_epoch_correctly_per_format() {
        use std::cmp::Ordering;
        assert_eq!(
            PackageFormat::Rpm.compare_versions((1, "1.0", "1"), (0, "9.0", "1")),
            Ordering::Greater
        );
        assert_eq!(
            PackageFormat::Pacman.compare_versions((1, "1.0", "1"), (0, "9.0", "1")),
            Ordering::Greater
        );
        assert_eq!(
            PackageFormat::Deb.compare_versions((1, "1.0", "1"), (0, "9.0", "1")),
            Ordering::Greater
        );
    }

    #[test]
    fn compare_versions_orders_apk_and_npm_by_their_version_string_alone() {
        use std::cmp::Ordering;
        assert_eq!(
            PackageFormat::Apk.compare_versions((0, "1.0-r0", ""), (0, "1.0-r1", "")),
            Ordering::Less
        );
        assert_eq!(
            PackageFormat::Npm.compare_versions((0, "1.0.0", ""), (0, "1.0.1", "")),
            Ordering::Less
        );
    }

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
        assert_eq!(
            PackageFormat::from_filename("foo-1.0-1-x86_64.pkg.tar.zst"),
            Some(PackageFormat::Pacman)
        );
        assert_eq!(
            PackageFormat::from_filename("foo-1.0-1-any.pkg.tar.xz"),
            Some(PackageFormat::Pacman)
        );
        assert_eq!(
            PackageFormat::from_filename("hello_1.0-1_amd64.deb"),
            Some(PackageFormat::Deb)
        );
        assert_eq!(PackageFormat::from_filename("foo.txt"), None);
    }

    #[test]
    fn unknown_format_string_is_an_error() {
        assert!(PackageFormat::from_str("snap").is_err());
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
