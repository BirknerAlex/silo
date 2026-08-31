//! Alpine `.apk`: parsing, layout, and APKINDEX generation.
//!
//! An apk file is *not* a single tarball — it's several gzip members
//! concatenated: an optional signature member, a control member holding
//! `.PKGINFO`, and the data member. The index checksum (`C:` field) is
//! `Q1` + base64(SHA-1) over the **compressed** bytes of the control
//! member, so parsing has to preserve exact member boundaries rather than
//! transparently concatenating them the way a multi-member gzip reader
//! would. That's what [`crate::split_gzip_members`] is for.
//!
//! Unlike RPM, everything the index needs is in `.PKGINFO`, so APKINDEX
//! regeneration is a pure function of the database — no package bytes are
//! read back out of object storage.

use std::collections::BTreeMap;
use std::io::Write;
use std::pin::Pin;

use base64::Engine;
use serde_json::json;
use sha1::{Digest, Sha1};

use crate::{
    split_gzip_members, Format, IndexContext, IndexObject, PackageFormat, ParseError, ParsedPackage,
};

pub struct ApkFormat;

/// Fields carried from `.PKGINFO` into the database and back out into
/// APKINDEX, in the order apk-tools writes them.
const INDEX_FIELDS: &[(&str, &str)] = &[
    ("C", "checksum"),
    ("P", "name"),
    ("V", "version"),
    ("A", "arch"),
    ("S", "size"),
    ("I", "installed_size"),
    ("T", "description"),
    ("U", "url"),
    ("L", "license"),
    ("o", "origin"),
    ("m", "maintainer"),
    ("t", "build_time"),
    ("c", "commit"),
    ("k", "provider_priority"),
    ("D", "depends"),
    ("p", "provides"),
    ("i", "install_if"),
];

impl Format for ApkFormat {
    fn format(&self) -> PackageFormat {
        PackageFormat::Apk
    }

    fn parse(&self, bytes: &[u8]) -> Result<ParsedPackage, ParseError> {
        let members = split_gzip_members(bytes)?;

        let mut pkginfo = None;
        for (start, end) in &members {
            let raw = &bytes[*start..*end];
            let Some(text) = read_pkginfo(raw) else {
                continue;
            };
            // `C:` covers the compressed control member verbatim.
            let checksum = format!(
                "Q1{}",
                base64::engine::general_purpose::STANDARD.encode(Sha1::digest(raw))
            );
            pkginfo = Some((text, checksum));
            break;
        }
        let (text, checksum) = pkginfo
            .ok_or_else(|| ParseError::invalid("apk package contains no .PKGINFO member"))?;

        let fields = parse_pkginfo(&text);
        let get = |k: &str| fields.get(k).and_then(|v| v.first()).cloned();
        let joined = |k: &str| fields.get(k).map(|v| v.join(" ")).filter(|s| !s.is_empty());

        let name =
            get("pkgname").ok_or_else(|| ParseError::invalid(".PKGINFO is missing pkgname"))?;
        let version =
            get("pkgver").ok_or_else(|| ParseError::invalid(".PKGINFO is missing pkgver"))?;
        let arch = get("arch").unwrap_or_else(|| "noarch".to_string());

        let metadata = json!({
            "checksum": checksum,
            "size": bytes.len(),
            "installed_size": get("size").and_then(|s| s.parse::<u64>().ok()),
            "description": get("pkgdesc"),
            "url": get("url"),
            "license": get("license"),
            "origin": get("origin"),
            "maintainer": get("maintainer"),
            "build_time": get("builddate").and_then(|s| s.parse::<i64>().ok()),
            "commit": get("commit"),
            "provider_priority": get("provider_priority").and_then(|s| s.parse::<i64>().ok()),
            "depends": joined("depend"),
            "provides": joined("provides"),
            "install_if": joined("install_if"),
        });

        Ok(ParsedPackage {
            format: PackageFormat::Apk,
            name: name.clone(),
            epoch: 0,
            version: version.clone(),
            release: String::new(),
            arch: arch.clone(),
            filename: format!("{name}-{version}.apk"),
            metadata,
            payload: bytes.to_vec(),
        })
    }

    fn storage_key(&self, repo: &str, channel: &str, pkg: &ParsedPackage) -> String {
        format!("{}/{}", arch_prefix(repo, channel, &pkg.arch), pkg.filename)
    }

    /// `apk` fetches one APKINDEX per architecture, so a publish only
    /// invalidates its own arch — two arches can publish concurrently
    /// without contending for the same lock.
    fn index_group(&self, pkg: &ParsedPackage) -> String {
        pkg.arch.clone()
    }

    /// Every architecture's index also lists the channel's `noarch`
    /// packages, because apk-tools will never look in a `noarch`
    /// directory of its own accord.
    fn shared_groups(&self, group: &str) -> Vec<String> {
        if group == NOARCH {
            Vec::new()
        } else {
            vec![NOARCH.to_string()]
        }
    }

    fn is_shared_group(&self, group: &str) -> bool {
        group == NOARCH
    }

    fn index_prefix(&self, repo: &str, channel: &str, group: &str) -> String {
        arch_prefix(repo, channel, group)
    }

    fn build_index<'a>(
        &'a self,
        ctx: &'a IndexContext<'a>,
    ) -> Pin<Box<dyn std::future::Future<Output = anyhow::Result<Vec<IndexObject>>> + Send + 'a>>
    {
        Box::pin(async move {
            let index = render_apkindex(ctx.records);
            let unsigned = tar_gz(&[
                ("APKINDEX", index.as_bytes()),
                (
                    "DESCRIPTION",
                    format!("{}/{} ({})\n", ctx.repo, ctx.channel, ctx.group).as_bytes(),
                ),
            ])?;

            let bytes = match ctx.signer {
                // apk verifies the index by checking a detached RSA
                // signature that sits in a gzip member *prepended* to the
                // index and covers the remaining bytes verbatim.
                Some(signer) => {
                    let signature = signer.sign(&unsigned)?;
                    let member_name = format!(".SIGN.RSA.{}", signer.key_name());
                    let sig_tar = tar_bytes(&[(member_name.as_str(), signature.as_slice())])?;
                    let mut out = gzip(strip_tar_eof(&sig_tar))?;
                    out.extend_from_slice(&unsigned);
                    out
                }
                None => unsigned,
            };

            Ok(vec![IndexObject {
                name: "APKINDEX.tar.gz".to_string(),
                bytes,
                content_type: "application/gzip",
            }])
        })
    }
}

/// The architecture a package declares when it works on all of them.
///
/// Not an architecture apk ever asks for: apk requests its own, so
/// packages here have to be surfaced through every other architecture's
/// index and served from every other architecture's path.
pub const NOARCH: &str = "noarch";

pub fn arch_prefix(repo: &str, channel: &str, arch: &str) -> String {
    format!("{repo}/{channel}/apk/{arch}")
}

/// Renders the plain-text APKINDEX body: one blank-line-separated record
/// per package, fields in apk-tools' canonical order.
pub fn render_apkindex(records: &[crate::PackageRecord]) -> String {
    let mut sorted: Vec<&crate::PackageRecord> = records.iter().collect();
    sorted.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));

    let mut out = String::new();
    for record in sorted {
        for (key, field) in INDEX_FIELDS {
            let value = match *field {
                "name" => Some(record.name.clone()),
                "version" => Some(record.version.clone()),
                "arch" => Some(record.arch.clone()),
                // Trust the row's authoritative size over the metadata
                // blob, which is only as good as the parse that wrote it.
                "size" => Some(record.size_bytes.to_string()),
                other => json_field(&record.metadata, other),
            };
            if let Some(value) = value {
                if !value.is_empty() {
                    out.push_str(&format!("{key}:{value}\n"));
                }
            }
        }
        out.push('\n');
    }
    out
}

fn json_field(metadata: &serde_json::Value, field: &str) -> Option<String> {
    match metadata.get(field)? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Null => None,
        other => Some(other.to_string()),
    }
}

/// Pulls `.PKGINFO` out of one inflated gzip member, or `None` if this
/// member isn't the control member.
fn read_pkginfo(compressed: &[u8]) -> Option<String> {
    let decoder = flate2::bufread::GzDecoder::new(compressed);
    let inflated =
        crate::inflate_capped(decoder, crate::MAX_INFLATED_BYTES, "apk control member").ok()?;

    let mut archive = tar::Archive::new(inflated.as_slice());
    for entry in archive.entries().ok()? {
        let mut entry = entry.ok()?;
        let path = entry.path().ok()?.to_string_lossy().into_owned();
        if path == ".PKGINFO" || path == "./.PKGINFO" {
            return crate::read_text_capped(&mut entry, ".PKGINFO").ok();
        }
    }
    None
}

/// `.PKGINFO` is `key = value` lines; keys like `depend` legitimately
/// repeat, so every key maps to a list.
///
/// `pub(crate)`: pacman's `.PKGINFO` is the same `key = value` shape, so
/// `pacman.rs` reuses this rather than re-implementing it.
pub(crate) fn parse_pkginfo(text: &str) -> BTreeMap<String, Vec<String>> {
    let mut fields: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        fields
            .entry(key.trim().to_string())
            .or_default()
            .push(value.to_string());
    }
    fields
}

/// Builds a tar archive. A name ending in `/` becomes a directory entry.
///
/// Directory entries matter for apk specifically: apk-tools refuses to
/// unpack a file whose parent directories have no entry in the archive
/// ("no dirent in archive"), so a payload tar has to name `usr/` and
/// `usr/share/` before `usr/share/hello.txt`.
pub(crate) fn tar_bytes(entries: &[(&str, &[u8])]) -> anyhow::Result<Vec<u8>> {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, bytes) in entries {
        let is_dir = name.ends_with('/');
        let mut header = tar::Header::new_ustar();
        header.set_path(name)?;
        header.set_size(if is_dir { 0 } else { bytes.len() as u64 });
        header.set_mode(if is_dir { 0o755 } else { 0o644 });
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_entry_type(if is_dir {
            tar::EntryType::Directory
        } else {
            tar::EntryType::Regular
        });
        header.set_cksum();
        builder.append(&header, if is_dir { &[][..] } else { *bytes })?;
    }
    Ok(builder.into_inner()?)
}

pub(crate) fn gzip(bytes: impl AsRef<[u8]>) -> anyhow::Result<Vec<u8>> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes.as_ref())?;
    Ok(encoder.finish()?)
}

fn tar_gz(entries: &[(&str, &[u8])]) -> anyhow::Result<Vec<u8>> {
    gzip(tar_bytes(entries)?)
}

/// Drops the trailing end-of-archive zero blocks.
///
/// apk's segments are gzip members, but apk-tools reads them as a *single
/// tar stream* spanning those members. So every segment except the last
/// must be a truncated tar (what `abuild-tar --cut` produces): leaving the
/// EOF blocks in place ends the tar stream early, and everything in the
/// following segment is never seen.
pub(crate) fn strip_tar_eof(bytes: &[u8]) -> &[u8] {
    let mut end = bytes.len();
    while end >= 512 && bytes[end - 512..end].iter().all(|b| *b == 0) {
        end -= 512;
    }
    &bytes[..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::build_test_apk;
    use crate::PackageRecord;
    use std::io::Read;

    fn record(name: &str, version: &str) -> PackageRecord {
        PackageRecord {
            format: PackageFormat::Apk,
            name: name.into(),
            epoch: 0,
            version: version.into(),
            release: String::new(),
            arch: "x86_64".into(),
            filename: format!("{name}-{version}.apk"),
            storage_key: format!("r/c/apk/x86_64/{name}-{version}.apk"),
            size_bytes: 1234,
            sha256: "deadbeef".into(),
            metadata: json!({
                "checksum": "Q1abc",
                "installed_size": 4096,
                "description": "a test package",
                "license": "MIT",
                "depends": "musl so:libc.musl-x86_64.so.1",
            }),
            published_at: 0,
        }
    }

    #[test]
    fn parses_pkginfo_key_value_lines_with_repeats() {
        let fields = parse_pkginfo(
            "# generated by abuild\npkgname = foo\npkgver = 1.0-r0\ndepend = musl\ndepend = zlib\n\n",
        );
        assert_eq!(fields["pkgname"], vec!["foo"]);
        assert_eq!(fields["depend"], vec!["musl", "zlib"]);
    }

    #[test]
    fn parses_a_generated_apk() {
        let bytes = build_test_apk("hello", "1.0-r0", "x86_64");
        let parsed = ApkFormat.parse(&bytes).expect("parse apk");
        assert_eq!(parsed.name, "hello");
        assert_eq!(parsed.version, "1.0-r0");
        assert_eq!(parsed.arch, "x86_64");
        assert_eq!(parsed.filename, "hello-1.0-r0.apk");
        assert_eq!(parsed.format, PackageFormat::Apk);
        // The C: field must be a Q1-prefixed base64 SHA-1.
        let checksum = parsed.metadata["checksum"].as_str().unwrap();
        assert!(checksum.starts_with("Q1"));
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(&checksum[2..])
                .unwrap()
                .len(),
            20
        );
    }

    #[test]
    fn rejects_an_apk_without_pkginfo() {
        let bytes = tar_gz(&[("not-pkginfo", b"x".as_slice())]).unwrap();
        assert!(ApkFormat.parse(&bytes).is_err());
    }

    #[test]
    fn rejects_non_gzip_bytes() {
        assert!(ApkFormat.parse(b"plain text").is_err());
    }

    #[test]
    fn layout_partitions_by_arch() {
        let pkg = ApkFormat
            .parse(&build_test_apk("hello", "1.0-r0", "aarch64"))
            .unwrap();
        assert_eq!(
            ApkFormat.storage_key("r", "edge", &pkg),
            "r/edge/apk/aarch64/hello-1.0-r0.apk"
        );
        assert_eq!(ApkFormat.index_group(&pkg), "aarch64");
        assert_eq!(
            ApkFormat.index_prefix("r", "edge", "aarch64"),
            "r/edge/apk/aarch64"
        );
    }

    #[test]
    fn apkindex_renders_records_in_canonical_field_order() {
        let out = render_apkindex(&[record("foo", "1.0-r0")]);
        let lines: Vec<&str> = out.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines[0], "C:Q1abc");
        assert_eq!(lines[1], "P:foo");
        assert_eq!(lines[2], "V:1.0-r0");
        assert_eq!(lines[3], "A:x86_64");
        assert_eq!(lines[4], "S:1234");
        assert_eq!(lines[5], "I:4096");
        assert!(out.contains("D:musl so:libc.musl-x86_64.so.1"));
        assert!(out.ends_with("\n\n"));
    }

    #[test]
    fn apkindex_sorts_records_and_separates_them_with_blank_lines() {
        let out = render_apkindex(&[record("zzz", "1.0-r0"), record("aaa", "1.0-r0")]);
        let first = out.find("P:aaa").unwrap();
        let second = out.find("P:zzz").unwrap();
        assert!(first < second);
        assert_eq!(out.matches("\n\n").count(), 2);
    }

    #[tokio::test]
    async fn build_index_produces_a_readable_apkindex_tarball() {
        let records = [record("foo", "1.0-r0")];
        let ctx = IndexContext {
            repo: "r",
            channel: "edge",
            group: "x86_64",
            records: &records,
            public_base_url: None,
            signer: None,
        };
        let objects = ApkFormat.build_index(&ctx).await.unwrap();
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].name, "APKINDEX.tar.gz");

        let mut inflated = Vec::new();
        flate2::bufread::MultiGzDecoder::new(objects[0].bytes.as_slice())
            .read_to_end(&mut inflated)
            .unwrap();
        let mut archive = tar::Archive::new(inflated.as_slice());
        let names: Vec<String> = archive
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"APKINDEX".to_string()));
        assert!(names.contains(&"DESCRIPTION".to_string()));
    }

    struct FakeSigner;
    impl crate::IndexSigner for FakeSigner {
        fn key_name(&self) -> &str {
            "test@silo.rsa.pub"
        }
        fn sign(&self, _data: &[u8]) -> anyhow::Result<Vec<u8>> {
            Ok(vec![0xAB; 256])
        }
    }

    #[tokio::test]
    async fn signed_index_prepends_a_signature_member() {
        let records = [record("foo", "1.0-r0")];
        let signer = FakeSigner;
        let ctx = IndexContext {
            repo: "r",
            channel: "edge",
            group: "x86_64",
            records: &records,
            public_base_url: None,
            signer: Some(&signer),
        };
        let objects = ApkFormat.build_index(&ctx).await.unwrap();
        let members = split_gzip_members(&objects[0].bytes).unwrap();
        assert_eq!(members.len(), 2, "signature member + index member");

        // The signature member must name the key so apk can pick the
        // matching public key out of /etc/apk/keys.
        let (start, end) = members[0];
        let mut inflated = Vec::new();
        flate2::bufread::GzDecoder::new(&objects[0].bytes[start..end])
            .read_to_end(&mut inflated)
            .unwrap();
        let mut archive = tar::Archive::new(inflated.as_slice());
        let entry = archive.entries().unwrap().next().unwrap().unwrap();
        assert_eq!(
            entry.path().unwrap().to_string_lossy(),
            ".SIGN.RSA.test@silo.rsa.pub"
        );
    }

    #[test]
    fn trailing_slashes_produce_directory_entries() {
        let tar = tar_bytes(&[
            ("usr/", b"".as_slice()),
            ("usr/hello.txt", b"hi".as_slice()),
        ])
        .unwrap();
        let mut archive = tar::Archive::new(tar.as_slice());
        let entries: Vec<(String, tar::EntryType)> = archive
            .entries()
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (
                    e.path().unwrap().to_string_lossy().into_owned(),
                    e.header().entry_type(),
                )
            })
            .collect();
        assert_eq!(entries[0].1, tar::EntryType::Directory);
        assert_eq!(entries[1].1, tar::EntryType::Regular);
    }

    #[test]
    fn strip_tar_eof_removes_only_trailing_zero_blocks() {
        let tar = tar_bytes(&[("a", b"hello".as_slice())]).unwrap();
        let stripped = strip_tar_eof(&tar);
        assert!(stripped.len() < tar.len());
        assert_eq!(stripped.len() % 512, 0);
        // The header block and its data block must survive.
        assert_eq!(stripped.len(), 1024);
    }
}
