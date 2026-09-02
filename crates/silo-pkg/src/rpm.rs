//! RPM: parsing, `dnf`/`yum` layout, and repodata generation.
//!
//! Repodata is rendered by [`crate::repodata`], in-process, from database
//! rows alone — the same as apk and npm. primary.xml needs a great deal
//! that no column holds (dependencies, file lists, header byte ranges), so
//! [`crate::repodata::extract`] reads all of it out of the rpm headers
//! once at publish time and it is stored as the row's metadata.

use std::future::Future;
use std::pin::Pin;

use quick_xml::events::Event;
use quick_xml::Reader;

use crate::repodata::{self, RepodataEntry, RepodataLocation};
use crate::upstream::{
    UpstreamError, UpstreamFetchOptions, UpstreamHttp, UpstreamIndex, UpstreamPackage,
};
use crate::{Format, IndexContext, IndexObject, PackageFormat, ParseError, ParsedPackage};

pub struct RpmFormat;

impl Format for RpmFormat {
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

        // Everything repodata will ever need from these headers, read now
        // so regenerating the index never has to open a `.rpm` again.
        //
        // For a package silo goes on to sign this is provisional: signing
        // rewrites the signature header, which moves the header byte range
        // primary.xml publishes. `index_metadata` re-derives it from the
        // bytes that actually get stored.
        let metadata = index_metadata_json(bytes)?;

        Ok(ParsedPackage {
            format: PackageFormat::Rpm,
            name,
            epoch,
            version,
            release,
            arch,
            filename,
            metadata,
            payload: bytes.to_vec(),
        })
    }

    fn storage_key(&self, repo: &str, channel: &str, pkg: &ParsedPackage) -> String {
        format!("{}/{}", packages_prefix(repo, channel), pkg.filename)
    }

    /// One repodata tree per repo/channel — RPM has no sub-partitioning,
    /// so every publish invalidates the same single group.
    fn index_group(&self, _pkg: &ParsedPackage) -> String {
        String::new()
    }

    fn index_prefix(&self, repo: &str, channel: &str, _group: &str) -> String {
        repodata_prefix(repo, channel)
    }

    /// Signing rewrites the signature header, so a signed package's
    /// header byte range — and its size and digest — are not the ones its
    /// pre-signing headers described. dnf uses that range to fetch a
    /// single package's header with a ranged GET, so publishing a stale
    /// one hands clients bytes that are not a header.
    fn index_metadata(&self, stored: &[u8]) -> Result<Option<serde_json::Value>, ParseError> {
        Ok(Some(index_metadata_json(stored)?))
    }

    fn build_index<'a>(
        &'a self,
        ctx: &'a IndexContext<'a>,
    ) -> Pin<Box<dyn std::future::Future<Output = anyhow::Result<Vec<IndexObject>>> + Send + 'a>>
    {
        Box::pin(async move {
            let inputs = ctx
                .records
                .iter()
                .map(|record| {
                    // A row whose metadata will not deserialize is a hard
                    // error rather than a skip. Nothing here reads the
                    // package file, so there is nothing to fall back to,
                    // and quietly dropping one package from an otherwise
                    // complete repo is far harder to notice than a failed
                    // publish.
                    let entry: RepodataEntry = serde_json::from_value(record.metadata.clone())
                        .map_err(|e| {
                            anyhow::anyhow!(
                                "package row for {} has unreadable rpm metadata ({e}); \
                                 republish it to repair the row",
                                record.filename
                            )
                        })?;
                    Ok((
                        entry,
                        RepodataLocation {
                            href: format!("Packages/{}", record.filename),
                            sha256: record.sha256.clone(),
                            size: record.size_bytes.max(0) as u64,
                        },
                    ))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;

            // The revision is what a client compares against its cached
            // copy. Deriving it from the newest publish keeps regenerating
            // an unchanged repo a no-op instead of churning every object
            // name on a clock tick.
            let revision = ctx
                .records
                .iter()
                .map(|r| r.published_at)
                .max()
                .unwrap_or_default();

            let mut objects: Vec<IndexObject> = repodata::build(&inputs, revision)?
                .into_iter()
                .map(|file| IndexObject {
                    name: file.name,
                    bytes: file.bytes,
                    content_type: file.content_type,
                })
                .collect();

            // `repo_gpgcheck=1` in a .repo file verifies repomd.xml against
            // a detached armored signature next to it. Package signatures
            // (gpgcheck=1) are applied separately, at publish time.
            if let Some(signer) = ctx.signer {
                if let Some(repomd) = objects.iter().find(|o| o.name == "repomd.xml") {
                    let sig = signer.sign(&repomd.bytes)?;
                    objects.push(IndexObject {
                        name: "repomd.xml.asc".to_string(),
                        bytes: sig,
                        content_type: "text/plain",
                    });
                }
            }

            Ok(objects)
        })
    }
}

/// The repodata fields for `bytes`, as the JSON stored on a package row.
fn index_metadata_json(bytes: &[u8]) -> Result<serde_json::Value, ParseError> {
    let entry = repodata::extract(bytes)
        .map_err(|e| ParseError::invalid(format!("could not read rpm headers: {e}")))?;
    serde_json::to_value(entry)
        .map_err(|e| ParseError::invalid(format!("could not serialize rpm metadata: {e}")))
}

pub fn packages_prefix(repo: &str, channel: &str) -> String {
    format!("{repo}/{channel}/Packages")
}

pub fn repodata_prefix(repo: &str, channel: &str) -> String {
    format!("{repo}/{channel}/repodata")
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

/// Re-parses an RPM after signing so callers get metadata consistent with
/// what's actually in storage, and re-serializes it to bytes.
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

/// Fetches and parses an upstream rpm repository's repodata: `repomd.xml`
/// to locate `primary.xml(.gz)`, then that document for the package list.
/// One repo, one repodata tree — no per-architecture partitioning the way
/// apk/pacman need, matching [`Format::index_group`] above.
pub struct RpmUpstream;

impl UpstreamIndex for RpmUpstream {
    fn format(&self) -> PackageFormat {
        PackageFormat::Rpm
    }

    fn fetch_index<'a>(
        &'a self,
        http: &'a UpstreamHttp,
        _opts: &'a UpstreamFetchOptions,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<UpstreamPackage>, UpstreamError>> + Send + 'a>>
    {
        Box::pin(async move {
            let repomd = http.get("repodata/repomd.xml").await?;
            let primary_href = find_primary_location(&repomd)?;
            let primary_bytes = http.get(&primary_href).await?;
            // Real repositories vary: gzip is the traditional choice,
            // but newer `createrepo_c` defaults (rawhide, at the time of
            // writing) offer only zstd, with zchunk (`.zck`, a
            // partial-download-friendly format layered on top of zstd)
            // as the other alternative `type="primary"` never uses on
            // its own. zchunk isn't supported here — falling back to it
            // would need reassembling its chunk index, not just
            // decompression — so an upstream that offers *only* zchunk
            // (no plain `.gz`/`.zst`) fails with a clear message instead
            // of silently parsing garbage.
            let primary_xml = if primary_href.ends_with(".gz") {
                crate::inflate_capped(
                    flate2::bufread::GzDecoder::new(primary_bytes.as_slice()),
                    crate::MAX_INFLATED_BYTES,
                    "upstream primary.xml.gz",
                )
                .map_err(|e| UpstreamError::parse(e.to_string()))?
            } else if primary_href.ends_with(".zst") {
                let decoder = zstd::stream::read::Decoder::new(primary_bytes.as_slice())
                    .map_err(|e| UpstreamError::parse(format!("corrupt zstd primary.xml: {e}")))?;
                crate::inflate_capped(
                    decoder,
                    crate::MAX_INFLATED_BYTES,
                    "upstream primary.xml.zst",
                )
                .map_err(|e| UpstreamError::parse(e.to_string()))?
            } else if primary_href.ends_with(".zck") {
                return Err(UpstreamError::parse(
                    "upstream only offers zchunk (.zck) primary metadata, which is not supported",
                ));
            } else {
                primary_bytes
            };
            parse_primary_xml(&primary_xml, http.base_url())
        })
    }
}

/// Finds `<data type="primary"><location href="..."/></data>` in a fetched
/// `repomd.xml`. Namespace-agnostic: real repositories declare
/// `xmlns="http://linux.duke.edu/metadata/repo"`, which `quick_xml`'s
/// basic reader surfaces as part of the tag name only if prefixed — most
/// repodata uses a default (unprefixed) namespace, so tag names are
/// matched on their local part regardless.
fn find_primary_location(repomd: &[u8]) -> Result<String, UpstreamError> {
    let mut reader = Reader::from_reader(repomd);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut in_primary_data = false;

    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| UpstreamError::parse(e.to_string()))?
        {
            Event::Eof => break,
            Event::Start(e) | Event::Empty(e) => {
                let name = local_name(e.name().into_inner());
                if name == "data" {
                    in_primary_data = e
                        .attributes()
                        .flatten()
                        .any(|a| a.key.as_ref() == b"type" && a.value.as_ref() == b"primary");
                } else if name == "location" && in_primary_data {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"href" {
                            return Ok(String::from_utf8_lossy(&attr.value).into_owned());
                        }
                    }
                }
            }
            Event::End(e) if local_name(e.name().into_inner()) == "data" => {
                in_primary_data = false;
            }
            _ => {}
        }
        buf.clear();
    }
    Err(UpstreamError::parse(
        "repomd.xml has no primary <data> location",
    ))
}

/// Parses a fetched (already-decompressed) `primary.xml` into normalized
/// upstream packages.
fn parse_primary_xml(xml: &[u8], base_url: &str) -> Result<Vec<UpstreamPackage>, UpstreamError> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut out = Vec::new();
    let mut current: Option<PartialPackage> = None;
    let mut in_text_field: Option<&'static str> = None;

    loop {
        match reader
            .read_event_into(&mut buf)
            .map_err(|e| UpstreamError::parse(e.to_string()))?
        {
            Event::Eof => break,
            Event::Start(e) | Event::Empty(e) => {
                let name = local_name(e.name().into_inner());
                match name.as_str() {
                    "package" => current = Some(PartialPackage::default()),
                    "name" => in_text_field = Some("name"),
                    "arch" => in_text_field = Some("arch"),
                    "version" => {
                        if let Some(pkg) = &mut current {
                            for attr in e.attributes().flatten() {
                                let value = String::from_utf8_lossy(&attr.value).into_owned();
                                match attr.key.as_ref() {
                                    b"epoch" => pkg.epoch = value.parse().unwrap_or(0),
                                    b"ver" => pkg.version = value,
                                    b"rel" => pkg.release = value,
                                    _ => {}
                                }
                            }
                        }
                    }
                    "checksum" => {
                        // Only a sha256 pkgid is usable: the field it
                        // lands in is republished as
                        // `<checksum type="sha256">`. `createrepo_c`
                        // also supports sha512, and older repositories
                        // still publish sha1 — storing either of those
                        // under a field named and consumed as sha256
                        // would make dnf reject the package for a
                        // digest mismatch.
                        let is_sha256 = e
                            .attributes()
                            .flatten()
                            .any(|a| a.key.as_ref() == b"type" && a.value.as_ref() == b"sha256");
                        in_text_field = if is_sha256 { Some("checksum") } else { None };
                    }
                    "size" => {
                        if let Some(pkg) = &mut current {
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"package" {
                                    pkg.size_bytes =
                                        String::from_utf8_lossy(&attr.value).parse().ok();
                                }
                            }
                        }
                    }
                    "location" => {
                        if let Some(pkg) = &mut current {
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"href" {
                                    pkg.href = String::from_utf8_lossy(&attr.value).into_owned();
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            Event::Text(e) => {
                if let (Some(field), Some(pkg)) = (in_text_field, &mut current) {
                    let text = e
                        .unescape()
                        .map_err(|err| UpstreamError::parse(err.to_string()))?;
                    match field {
                        "name" => pkg.name = text.into_owned(),
                        "arch" => pkg.arch = text.into_owned(),
                        "checksum" => pkg.sha256 = Some(text.into_owned()),
                        _ => {}
                    }
                }
            }
            Event::End(e) => {
                let name = local_name(e.name().into_inner());
                if matches!(name.as_str(), "name" | "arch" | "checksum") {
                    in_text_field = None;
                }
                if name == "package" {
                    if let Some(pkg) = current.take() {
                        if let Some(upstream_pkg) = pkg.finish(base_url) {
                            out.push(upstream_pkg);
                        }
                    }
                }
            }
            _ => {}
        }
        buf.clear();
    }
    Ok(out)
}

#[derive(Default)]
struct PartialPackage {
    name: String,
    arch: String,
    epoch: u32,
    version: String,
    release: String,
    sha256: Option<String>,
    size_bytes: Option<i64>,
    href: String,
}

impl PartialPackage {
    fn finish(self, base_url: &str) -> Option<UpstreamPackage> {
        if self.name.is_empty() || self.version.is_empty() || self.href.is_empty() {
            return None;
        }
        let filename = self
            .href
            .rsplit('/')
            .next()
            .unwrap_or(&self.href)
            .to_string();
        Some(UpstreamPackage {
            name: self.name,
            epoch: self.epoch,
            version: self.version,
            release: self.release,
            arch: self.arch,
            filename,
            download_url: format!("{}/{}", base_url.trim_end_matches('/'), self.href),
            size_bytes: self.size_bytes,
            sha256: self.sha256.map(|s| s.to_string()),
            metadata: serde_json::json!({}),
        })
    }
}

/// Strips any namespace prefix (`ns:tag` -> `tag`) so parsing doesn't
/// depend on which prefix (if any) a given repository's XML declares.
fn local_name(qname: &[u8]) -> String {
    let s = String::from_utf8_lossy(qname);
    s.rsplit_once(':')
        .map(|(_, local)| local)
        .unwrap_or(&s)
        .to_string()
}

/// Compares two rpm `[epoch:]version-release` strings per RPM's own
/// algorithm: epoch numerically first, then version and release each
/// compared by RPM's alternating alphabetic/numeric/tilde rule — `~`
/// sorts below everything, including the empty string, so `1.0~rc1`
/// precedes `1.0`.
///
/// A pragmatic subset of `rpmvercmp`, covering the shapes real packages
/// use; not a byte-for-byte reimplementation of every corner (rpm's
/// caret `^` post-release marker is not handled, since it postdates most
/// packages still commonly mirrored).
pub fn version_cmp(
    a_epoch: u32,
    a_version: &str,
    a_release: &str,
    b_epoch: u32,
    b_version: &str,
    b_release: &str,
) -> std::cmp::Ordering {
    a_epoch
        .cmp(&b_epoch)
        .then_with(|| rpmvercmp(a_version, b_version))
        .then_with(|| rpmvercmp(a_release, b_release))
}

fn rpmvercmp(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;

    let mut a = a;
    let mut b = b;
    loop {
        // Skip non-alphanumeric, non-tilde separators on both sides.
        a = a.trim_start_matches(|c: char| !c.is_ascii_alphanumeric() && c != '~');
        b = b.trim_start_matches(|c: char| !c.is_ascii_alphanumeric() && c != '~');

        if a.starts_with('~') || b.starts_with('~') {
            match (a.starts_with('~'), b.starts_with('~')) {
                (true, true) => {
                    a = &a[1..];
                    b = &b[1..];
                    continue;
                }
                (true, false) => return Ordering::Less,
                (false, true) => return Ordering::Greater,
                (false, false) => unreachable!(),
            }
        }

        if a.is_empty() && b.is_empty() {
            return Ordering::Equal;
        }
        // rpmvercmp: whichever side still has characters left over is
        // newer, full stop — it does not matter whether that leftover
        // run is alphabetic or numeric. `1.1.1` < `1.1.1k` here exactly
        // as real rpm orders openssl's `1.1.1k` above `1.1.1`; `~` above
        // is rpm's actual mechanism for a trailing tag to sort *below*
        // the release it precedes; a bare, non-tilde suffix does not.
        if a.is_empty() {
            return Ordering::Less;
        }
        if b.is_empty() {
            return Ordering::Greater;
        }

        let a_digit = a.starts_with(|c: char| c.is_ascii_digit());
        let b_digit = b.starts_with(|c: char| c.is_ascii_digit());

        if a_digit != b_digit {
            // A numeric segment always outranks an alphabetic one at the
            // same position.
            return if a_digit {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }

        if a_digit {
            let a_end = a.find(|c: char| !c.is_ascii_digit()).unwrap_or(a.len());
            let b_end = b.find(|c: char| !c.is_ascii_digit()).unwrap_or(b.len());
            let a_num = a[..a_end].trim_start_matches('0');
            let b_num = b[..b_end].trim_start_matches('0');
            let cmp = a_num.len().cmp(&b_num.len()).then_with(|| a_num.cmp(b_num));
            a = &a[a_end..];
            b = &b[b_end..];
            if cmp != Ordering::Equal {
                return cmp;
            }
        } else {
            let a_end = a
                .find(|c: char| !c.is_ascii_alphabetic())
                .unwrap_or(a.len());
            let b_end = b
                .find(|c: char| !c.is_ascii_alphabetic())
                .unwrap_or(b.len());
            let cmp = a[..a_end].cmp(&b[..b_end]);
            a = &a[a_end..];
            b = &b[b_end..];
            if cmp != Ordering::Equal {
                return cmp;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::build_test_rpm;
    use crate::PackageRecord;
    use std::io::Read;

    /// A package row exactly as `publish` would have written it: the
    /// metadata is what `parse` extracted from these very bytes.
    fn record(bytes: &[u8], filename: &str) -> PackageRecord {
        let parsed = RpmFormat.parse(bytes).expect("parse rpm");
        PackageRecord {
            format: PackageFormat::Rpm,
            name: parsed.name,
            epoch: parsed.epoch,
            version: parsed.version,
            release: parsed.release,
            arch: parsed.arch,
            storage_key: format!("r/c/Packages/{filename}"),
            filename: filename.into(),
            size_bytes: bytes.len() as i64,
            sha256: "0".repeat(64),
            metadata: parsed.metadata,
            published_at: 1_700_000_000,
        }
    }

    #[test]
    fn parses_valid_rpm_metadata() {
        let bytes = build_test_rpm("silo-test", "1.2.3", "4", "x86_64");
        let parsed = RpmFormat.parse(&bytes).expect("parse rpm");
        assert_eq!(parsed.name, "silo-test");
        assert_eq!(parsed.version, "1.2.3");
        assert_eq!(parsed.release, "4");
        assert_eq!(parsed.arch, "x86_64");
        assert_eq!(parsed.format, PackageFormat::Rpm);
    }

    #[test]
    fn rejects_garbage_bytes() {
        let err = RpmFormat.parse(b"not an rpm file at all").unwrap_err();
        assert!(matches!(err, ParseError::Rpm(_)));
    }

    #[test]
    fn nevra_includes_epoch_only_when_nonzero() {
        let mut parsed = ParsedPackage {
            format: PackageFormat::Rpm,
            name: "foo".into(),
            epoch: 0,
            version: "1.0".into(),
            release: "1".into(),
            arch: "noarch".into(),
            filename: "foo-1.0-1.noarch.rpm".into(),
            metadata: serde_json::Value::Null,
            payload: vec![],
        };
        assert_eq!(parsed.nevra(), "foo-1.0-1.noarch");
        parsed.epoch = 2;
        assert_eq!(parsed.nevra(), "foo-2:1.0-1.noarch");
    }

    #[test]
    fn layout_paths_are_namespaced_by_repo_and_channel() {
        let pkg = ParsedPackage {
            format: PackageFormat::Rpm,
            name: "foo".into(),
            epoch: 0,
            version: "1.0".into(),
            release: "1".into(),
            arch: "x86_64".into(),
            filename: "foo-1.0-1.x86_64.rpm".into(),
            metadata: serde_json::Value::Null,
            payload: vec![],
        };
        assert_eq!(
            RpmFormat.storage_key("myrepo", "stable", &pkg),
            "myrepo/stable/Packages/foo-1.0-1.x86_64.rpm"
        );
        assert_eq!(RpmFormat.index_group(&pkg), "");
        assert_eq!(
            RpmFormat.index_prefix("myrepo", "stable", ""),
            "myrepo/stable/repodata"
        );
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
        let (name, ..) = parse_nvra_filename("my-cool-daemon-2.0.0-1.noarch.rpm").unwrap();
        assert_eq!(name, "my-cool-daemon");
    }

    #[test]
    fn rejects_non_rpm_filename() {
        assert!(parse_nvra_filename("not-an-rpm.txt").is_none());
    }

    fn context(records: &[PackageRecord]) -> IndexContext<'_> {
        IndexContext {
            repo: "r",
            channel: "c",
            group: "",
            records,
            public_base_url: None,
            signer: None,
        }
    }

    fn inflate(bytes: &[u8]) -> String {
        let mut out = Vec::new();
        flate2::bufread::GzDecoder::new(bytes)
            .read_to_end(&mut out)
            .unwrap();
        String::from_utf8(out).unwrap()
    }

    #[tokio::test]
    async fn build_index_renders_a_repodata_tree_from_the_rows_alone() {
        // No package bytes anywhere in this test: that is the point.
        let bytes = build_test_rpm("t", "1.0", "1", "x86_64");
        let records = [record(&bytes, "t-1.0-1.x86_64.rpm")];

        let objects = RpmFormat.build_index(&context(&records)).await.unwrap();

        assert_eq!(objects.len(), 4, "repomd plus primary/filelists/other");
        let repomd = objects.iter().find(|o| o.name == "repomd.xml").unwrap();
        let xml = String::from_utf8(repomd.bytes.clone()).unwrap();
        for kind in ["primary", "filelists", "other"] {
            assert!(xml.contains(&format!("type=\"{kind}\"")), "{xml}");
        }

        let primary = inflate(
            &objects
                .iter()
                .find(|o| o.name.contains("primary"))
                .unwrap()
                .bytes,
        );
        assert!(primary.contains("<name>t</name>"));
        assert!(primary.contains("<location href=\"Packages/t-1.0-1.x86_64.rpm\"/>"));
    }

    #[tokio::test]
    async fn a_row_with_unreadable_metadata_fails_loudly() {
        // There is no package file to fall back to any more, so a row that
        // cannot be read has to stop the regeneration. Quietly dropping
        // one package from an otherwise complete repo would be much harder
        // to notice than a failed publish.
        let bytes = build_test_rpm("t", "1.0", "1", "x86_64");
        let mut broken = record(&bytes, "t-1.0-1.x86_64.rpm");
        broken.metadata = serde_json::json!({ "summary": "a pre-0.3 row" });

        let records = [broken];
        let err = RpmFormat
            .build_index(&context(&records))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("t-1.0-1.x86_64.rpm"), "got: {err}");
        assert!(err.contains("republish"), "got: {err}");
    }

    #[test]
    fn index_metadata_describes_the_bytes_it_was_given() {
        // The reason `index_metadata` exists at all: silo signs RPMs, and
        // signing rewrites the signature header, moving everything after
        // it. Metadata taken from the uploaded bytes would publish a
        // header range that no longer points at a header, sending dnf's
        // ranged header GET to the wrong offsets.
        //
        // Over unchanged bytes the two must agree — that is what makes it
        // safe for the publish flow to call this unconditionally rather
        // than only for signed packages.
        let bytes = build_test_rpm("t", "1.0", "1", "x86_64");
        assert_eq!(
            RpmFormat.index_metadata(&bytes).unwrap().unwrap(),
            RpmFormat.parse(&bytes).unwrap().metadata,
        );
    }

    #[test]
    fn parse_stores_everything_the_index_will_need() {
        let bytes = build_test_rpm("t", "1.0", "1", "x86_64");
        let metadata = RpmFormat.parse(&bytes).unwrap().metadata;
        // Round-trips as the type build_index deserializes it into.
        let entry: crate::repodata::RepodataEntry =
            serde_json::from_value(metadata.clone()).unwrap();
        assert_eq!(
            serde_json::to_value(&entry).unwrap(),
            metadata,
            "the stored JSON is exactly the entry, with nothing dropped"
        );
    }

    #[test]
    fn finds_the_primary_location_in_a_repomd_document() {
        let repomd = r#"<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <revision>1700000000</revision>
  <data type="filelists">
    <location href="repodata/aaa-filelists.xml.gz"/>
  </data>
  <data type="primary">
    <checksum type="sha256">deadbeef</checksum>
    <location href="repodata/bbb-primary.xml.gz"/>
    <size>1234</size>
  </data>
</repomd>"#;
        assert_eq!(
            find_primary_location(repomd.as_bytes()).unwrap(),
            "repodata/bbb-primary.xml.gz"
        );
    }

    #[test]
    fn missing_primary_data_is_an_error() {
        let repomd = r#"<repomd><data type="filelists"><location href="x"/></data></repomd>"#;
        assert!(find_primary_location(repomd.as_bytes()).is_err());
    }

    #[tokio::test]
    async fn parses_an_upstream_primary_xml_round_tripped_through_our_own_renderer() {
        let bytes = build_test_rpm("curl", "8.0.1", "1", "x86_64");
        let records = [record(&bytes, "curl-8.0.1-1.x86_64.rpm")];
        let objects = RpmFormat.build_index(&context(&records)).await.unwrap();
        let primary = objects.iter().find(|o| o.name.contains("primary")).unwrap();
        let inflated = {
            let mut out = Vec::new();
            flate2::bufread::GzDecoder::new(primary.bytes.as_slice())
                .read_to_end(&mut out)
                .unwrap();
            out
        };

        let packages = parse_primary_xml(&inflated, "https://example.com/repo").unwrap();
        assert_eq!(packages.len(), 1);
        let pkg = &packages[0];
        assert_eq!(pkg.name, "curl");
        assert_eq!(pkg.version, "8.0.1");
        assert_eq!(pkg.release, "1");
        assert_eq!(pkg.arch, "x86_64");
        assert_eq!(pkg.filename, "curl-8.0.1-1.x86_64.rpm");
        assert_eq!(
            pkg.download_url,
            "https://example.com/repo/Packages/curl-8.0.1-1.x86_64.rpm"
        );
        assert!(pkg.sha256.is_some());
    }

    #[test]
    fn version_cmp_orders_epoch_above_everything_else() {
        use std::cmp::Ordering;
        assert_eq!(version_cmp(1, "1.0", "1", 0, "9.0", "1"), Ordering::Greater);
        assert_eq!(version_cmp(0, "9.0", "1", 1, "1.0", "1"), Ordering::Less);
    }

    #[test]
    fn version_cmp_orders_numeric_segments_numerically_not_lexically() {
        use std::cmp::Ordering;
        assert_eq!(version_cmp(0, "1.2", "1", 0, "1.10", "1"), Ordering::Less);
        assert_eq!(version_cmp(0, "1.0", "1", 0, "1.0", "2"), Ordering::Less);
        assert_eq!(version_cmp(0, "1.0", "1", 0, "1.0", "1"), Ordering::Equal);
    }

    #[test]
    fn version_cmp_orders_a_tilde_prerelease_below_its_release() {
        use std::cmp::Ordering;
        assert_eq!(rpmvercmp("1.0~rc1", "1.0"), Ordering::Less);
        assert_eq!(rpmvercmp("1.0", "1.0~rc1"), Ordering::Greater);
    }

    #[test]
    fn rpmvercmp_treats_alpha_and_numeric_runs_correctly() {
        use std::cmp::Ordering;
        // Real rpmvercmp: whichever side has characters left over wins,
        // regardless of whether that leftover is alphabetic or numeric —
        // this is exactly why openssl's `1.1.1k` sorts above `1.1.1`,
        // and why packagers who want a trailing tag to sort *below* its
        // release reach for `~` instead of a bare suffix.
        assert_eq!(rpmvercmp("1.0a", "1.0"), Ordering::Greater);
        assert_eq!(rpmvercmp("1.0", "1.0a"), Ordering::Less);
        assert_eq!(rpmvercmp("a", "b"), Ordering::Less);
    }

    /// Newer `createrepo_c` defaults (Fedora rawhide, at the time of
    /// writing) offer `primary.xml` only as zstd, with no plain `.gz`
    /// fallback — confirmed against the real, live rawhide mirror while
    /// building this. `fetch_index` has to decompress that directly, not
    /// just gzip.
    #[tokio::test]
    async fn fetch_index_decompresses_a_zstd_primary_xml() {
        let bytes = build_test_rpm("curl", "8.0.1", "1", "x86_64");
        let records = [record(&bytes, "curl-8.0.1-1.x86_64.rpm")];
        let objects = RpmFormat.build_index(&context(&records)).await.unwrap();
        let primary_gz = objects.iter().find(|o| o.name.contains("primary")).unwrap();
        let mut inflated = Vec::new();
        flate2::bufread::GzDecoder::new(primary_gz.bytes.as_slice())
            .read_to_end(&mut inflated)
            .unwrap();
        let primary_zst = zstd::stream::encode_all(inflated.as_slice(), 0).unwrap();

        let repomd = r#"<?xml version="1.0"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <data type="primary">
    <location href="repodata/primary.xml.zst"/>
  </data>
</repomd>"#
            .to_string();

        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/repodata/repomd.xml"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(repomd.into_bytes()))
            .mount(&mock)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/repodata/primary.xml.zst"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(primary_zst))
            .mount(&mock)
            .await;

        let http = crate::UpstreamHttp::new(reqwest::Client::new(), mock.uri());
        let packages = RpmUpstream
            .fetch_index(&http, &crate::UpstreamFetchOptions::default())
            .await
            .unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "curl");
    }

    #[tokio::test]
    async fn fetch_index_reports_a_clear_error_for_zchunk_only_primary() {
        let repomd = r#"<?xml version="1.0"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <data type="primary">
    <location href="repodata/primary.xml.zck"/>
  </data>
</repomd>"#;
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/repodata/repomd.xml"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(repomd.as_bytes()))
            .mount(&mock)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/repodata/primary.xml.zck"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_bytes(b"not really zchunk".to_vec()),
            )
            .mount(&mock)
            .await;

        let http = crate::UpstreamHttp::new(reqwest::Client::new(), mock.uri());
        let err = RpmUpstream
            .fetch_index(&http, &crate::UpstreamFetchOptions::default())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("zchunk"), "{err}");
    }
}
