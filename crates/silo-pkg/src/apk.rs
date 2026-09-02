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
use serde_json::{json, Map, Value};
use sha1::{Digest, Sha1};

use std::collections::HashMap;
use std::future::Future;

use crate::upstream::{
    UpstreamError, UpstreamFetchOptions, UpstreamHttp, UpstreamIndex, UpstreamPackage,
};
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

/// Fetches and parses an upstream Alpine repository's `APKINDEX.tar.gz`,
/// one per configured architecture — apk has no arch-agnostic root index,
/// the same reason [`Format::index_group`] partitions by arch above.
pub struct ApkUpstream;

impl UpstreamIndex for ApkUpstream {
    fn format(&self) -> PackageFormat {
        PackageFormat::Apk
    }

    fn fetch_index<'a>(
        &'a self,
        http: &'a UpstreamHttp,
        opts: &'a UpstreamFetchOptions,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<UpstreamPackage>, UpstreamError>> + Send + 'a>>
    {
        Box::pin(async move {
            if opts.arches.is_empty() {
                return Err(UpstreamError::parse(
                    "an apk upstream needs at least one --arch",
                ));
            }
            // One `APKINDEX.tar.gz` per architecture, fetched concurrently
            // rather than one at a time — a mirror configured with several
            // arches otherwise pays their round-trip latencies serially.
            let fetched =
                futures::future::try_join_all(opts.arches.iter().map(|arch| async move {
                    let bytes = http.get(&format!("{arch}/APKINDEX.tar.gz")).await?;
                    Ok::<_, UpstreamError>((arch, bytes))
                }))
                .await?;
            let mut out = Vec::new();
            for (arch, bytes) in fetched {
                let base = format!("{}/{arch}", http.base_url().trim_end_matches('/'));
                out.extend(parse_apkindex_tar_gz(&bytes, arch, &base)?);
            }
            Ok(out)
        })
    }
}

/// Extracts and parses the `APKINDEX` text member out of a fetched
/// `APKINDEX.tar.gz`. Handles the same multi-gzip-member shape
/// [`split_gzip_members`] exists for on the write side: a signed index
/// prepends a signature member ahead of the one actually holding the
/// `APKINDEX` file.
pub fn parse_apkindex_tar_gz(
    bytes: &[u8],
    arch: &str,
    base_url: &str,
) -> Result<Vec<UpstreamPackage>, UpstreamError> {
    let members = split_gzip_members(bytes).map_err(|e| UpstreamError::parse(e.to_string()))?;
    for (start, end) in &members {
        let raw = &bytes[*start..*end];
        let decoder = flate2::bufread::GzDecoder::new(raw);
        let Ok(inflated) =
            crate::inflate_capped(decoder, crate::MAX_INFLATED_BYTES, "apk index member")
        else {
            continue;
        };
        let mut archive = tar::Archive::new(inflated.as_slice());
        let Ok(entries) = archive.entries() else {
            continue;
        };
        for entry in entries {
            let Ok(mut entry) = entry else { continue };
            let Ok(path) = entry.path() else { continue };
            if path.to_string_lossy() != "APKINDEX" {
                continue;
            }
            let text = crate::read_text_capped(&mut entry, "APKINDEX")
                .map_err(|e| UpstreamError::parse(e.to_string()))?;
            return Ok(parse_apkindex_text(&text, arch, base_url));
        }
    }
    Err(UpstreamError::parse(
        "APKINDEX.tar.gz has no APKINDEX member",
    ))
}

/// Parses the plain-text `APKINDEX` body — the exact shape
/// [`render_apkindex`] produces, one `KEY:value` line per field,
/// blank-line-separated records — into normalized upstream packages.
/// Unlike `.PKGINFO`, fields are single letters (`P:name`, not
/// `pkgname = name`), so this doesn't reuse [`parse_pkginfo`].
pub fn parse_apkindex_text(text: &str, arch: &str, base_url: &str) -> Vec<UpstreamPackage> {
    let mut out = Vec::new();
    for block in text.split("\n\n") {
        if block.trim().is_empty() {
            continue;
        }
        let fields = parse_apkindex_block(block);
        let (Some(name), Some(version)) = (fields.get(&'P'), fields.get(&'V')) else {
            continue;
        };
        let filename = format!("{name}-{version}.apk");
        // Everything beyond the four columns above rides in `metadata`,
        // under the same keys `ApkFormat::parse` uses — `INDEX_FIELDS`
        // maps the single-letter wire field to that key, so a package
        // synced from a real upstream carries its description/url/
        // license/depends/etc. into a synthetic index entry exactly the
        // way a locally-published one would, not just a bare name and
        // version.
        let mut metadata = Map::new();
        for (key, meta_key) in INDEX_FIELDS {
            let ch = key.chars().next().unwrap();
            if matches!(ch, 'P' | 'V' | 'A' | 'S') {
                continue; // already columns on UpstreamPackage itself
            }
            if let Some(value) = fields.get(&ch) {
                metadata.insert((*meta_key).to_string(), Value::String(value.clone()));
            }
        }
        out.push(UpstreamPackage {
            name: name.clone(),
            epoch: 0,
            version: version.clone(),
            release: String::new(),
            arch: fields
                .get(&'A')
                .cloned()
                .unwrap_or_else(|| arch.to_string()),
            download_url: format!("{}/{filename}", base_url.trim_end_matches('/')),
            filename,
            size_bytes: fields.get(&'S').and_then(|s| s.parse::<i64>().ok()),
            sha256: None,
            metadata: Value::Object(metadata),
        });
    }
    out
}

fn parse_apkindex_block(block: &str) -> HashMap<char, String> {
    let mut fields = HashMap::new();
    for line in block.lines() {
        let line = line.trim();
        let mut chars = line.chars();
        let Some(key) = chars.next() else { continue };
        if chars.next() != Some(':') {
            continue;
        }
        fields.insert(key, line[key.len_utf8() + 1..].to_string());
    }
    fields
}

/// Compares two apk version strings per apk-tools' own ordering: numeric
/// and alphabetic segments compare in the obvious way, and a fixed set of
/// pre/post-release suffixes (`_alpha` < `_beta` < `_pre` < `_rc` <
/// (no suffix) < `_cvs`/`_svn`/`_git`/`_hg`/`_p`) order around the plain
/// release the same way RPM's tilde/no-tilde does. apk's package
/// revision is actually separated with `-r` (`1.0-r0`), which
/// `compare_segments`/`tokenize_version` already order correctly as an
/// ordinary trailing numeric segment; [`split_apk_revision`] instead
/// breaks ties on a *different*, rarer `_rN` marker apk-tools also
/// recognizes mid-version (as in `1.0_alpha1_r2`'s `_r2`).
///
/// This is a pragmatic subset of the real algorithm (`apk_pkg_version.c`)
/// covering the shapes real Alpine packages actually use; it does not
/// claim byte-for-byte parity with every edge case apk-tools handles.
pub fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let (a_main, a_rev) = split_apk_revision(a);
    let (b_main, b_rev) = split_apk_revision(b);
    compare_segments(a_main, b_main).then_with(|| a_rev.cmp(&b_rev))
}

fn split_apk_revision(v: &str) -> (&str, u64) {
    match v.rsplit_once("_r") {
        Some((main, rev)) if rev.chars().all(|c| c.is_ascii_digit()) && !rev.is_empty() => {
            (main, rev.parse().unwrap_or(0))
        }
        _ => (v, 0),
    }
}

/// Ordering rank for apk's recognized suffix words — lower sorts earlier.
/// A plain segment with no recognized suffix ranks as "release" (between
/// `_rc` and the post-release markers), matching apk-tools' treatment of
/// an unmarked version as the "final" release relative to its
/// pre-releases and equal-or-later to its post-release snapshots.
fn suffix_rank(word: &str) -> i32 {
    match word {
        "alpha" => -4,
        "beta" => -3,
        "pre" => -2,
        "rc" => -1,
        "cvs" | "svn" | "git" | "hg" | "p" => 1,
        _ => 0,
    }
}

fn compare_segments(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;

    let mut a_tokens = tokenize_version(a).into_iter().peekable();
    let mut b_tokens = tokenize_version(b).into_iter().peekable();

    loop {
        match (a_tokens.next(), b_tokens.next()) {
            (None, None) => return Ordering::Equal,
            // A leftover token when the other side has ended decides
            // based on *what* it is, not just that it exists: a leftover
            // numeric component means "more specific, so newer" (`1.0.1`
            // > `1.0`), but a leftover pre-release word (`_alpha`,
            // `_beta`, `_pre`, `_rc`) means "not released yet, so older"
            // (`1.0_rc1` < `1.0`) while a post-release word (`_git`,
            // `_cvs`, ...) still means newer.
            (Some(Token::Num(_)), None) => return Ordering::Greater,
            (None, Some(Token::Num(_))) => return Ordering::Less,
            (Some(Token::Suffix(s)), None) => {
                return if suffix_rank(&s) < 0 {
                    Ordering::Less
                } else {
                    Ordering::Greater
                };
            }
            (None, Some(Token::Suffix(s))) => {
                return if suffix_rank(&s) < 0 {
                    Ordering::Greater
                } else {
                    Ordering::Less
                };
            }
            (Some(Token::Num(x)), Some(Token::Num(y))) => match x.cmp(&y) {
                Ordering::Equal => continue,
                other => return other,
            },
            (Some(Token::Suffix(x)), Some(Token::Suffix(y))) => {
                match suffix_rank(&x).cmp(&suffix_rank(&y)) {
                    Ordering::Equal => match x.cmp(&y) {
                        Ordering::Equal => continue,
                        other => return other,
                    },
                    other => return other,
                }
            }
            // A numeric segment always outranks a suffix word at the same
            // position — `1.0` is newer than `1.0_alpha`.
            (Some(Token::Num(_)), Some(Token::Suffix(_))) => return Ordering::Greater,
            (Some(Token::Suffix(_)), Some(Token::Num(_))) => return Ordering::Less,
        }
    }
}

enum Token {
    Num(u64),
    Suffix(String),
}

/// Splits a version's main part into alternating numeric and
/// alpha/underscore-word tokens, e.g. `1.2.3_alpha1` ->
/// `[Num(1), Num(2), Num(3), Suffix("alpha"), Num(1)]`.
fn tokenize_version(v: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = v.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            let mut num = String::new();
            while chars.peek().is_some_and(|c| c.is_ascii_digit()) {
                num.push(chars.next().unwrap());
            }
            tokens.push(Token::Num(num.parse().unwrap_or(0)));
        } else if c == '.' || c == '_' || c == '-' {
            chars.next();
        } else {
            let mut word = String::new();
            while chars.peek().is_some_and(|c| c.is_ascii_alphabetic()) {
                word.push(chars.next().unwrap());
            }
            tokens.push(Token::Suffix(word));
        }
    }
    tokens
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

    #[test]
    fn parses_an_upstream_apkindex_round_tripped_through_our_own_renderer() {
        // The upstream parser's real-world input is another apk-tools
        // repository, but the fastest way to exercise it end to end
        // without vendoring a real Alpine mirror snippet is our own
        // renderer, since it emits the exact same wire shape.
        let text = render_apkindex(&[record("curl", "8.0.1-r0"), record("wget", "1.21-r2")]);
        let packages = parse_apkindex_text(&text, "x86_64", "https://example.com/x86_64");
        assert_eq!(packages.len(), 2);
        let curl = packages.iter().find(|p| p.name == "curl").unwrap();
        assert_eq!(curl.version, "8.0.1-r0");
        assert_eq!(curl.arch, "x86_64");
        assert_eq!(curl.filename, "curl-8.0.1-r0.apk");
        assert_eq!(
            curl.download_url,
            "https://example.com/x86_64/curl-8.0.1-r0.apk"
        );
        assert_eq!(curl.size_bytes, Some(1234));
        assert_eq!(curl.metadata["checksum"], "Q1abc");
        // Description/license/depends must survive too — a synthetic
        // index entry should look the same as a locally published one,
        // not just carry a bare name and version.
        assert_eq!(curl.metadata["description"], "a test package");
        assert_eq!(curl.metadata["license"], "MIT");
        assert_eq!(curl.metadata["depends"], "musl so:libc.musl-x86_64.so.1");
    }

    #[test]
    fn parses_an_upstream_apkindex_tar_gz_including_a_signature_member() {
        let text = render_apkindex(&[record("curl", "8.0.1-r0")]);
        let index_tar_gz = tar_gz(&[("APKINDEX", text.as_bytes())]).unwrap();

        // Prepend a bogus signature member, the same shape a real signed
        // upstream index has — the parser must skip past it to find the
        // member that actually contains APKINDEX.
        let sig_tar = tar_bytes(&[(".SIGN.RSA.fake", &[0xAB; 32])]).unwrap();
        let mut signed = gzip(strip_tar_eof(&sig_tar)).unwrap();
        signed.extend_from_slice(&index_tar_gz);

        let packages =
            parse_apkindex_tar_gz(&signed, "x86_64", "https://example.com/x86_64").unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "curl");
    }

    #[test]
    fn version_cmp_orders_numeric_segments_and_release_revisions() {
        use std::cmp::Ordering;
        assert_eq!(version_cmp("1.2.3", "1.2.4"), Ordering::Less);
        assert_eq!(version_cmp("1.10.0", "1.9.0"), Ordering::Greater);
        assert_eq!(version_cmp("1.0-r0", "1.0-r1"), Ordering::Less);
        assert_eq!(version_cmp("1.0", "1.0"), Ordering::Equal);
    }

    #[test]
    fn version_cmp_orders_pre_release_suffixes_below_the_plain_release() {
        use std::cmp::Ordering;
        assert_eq!(version_cmp("1.0_alpha1", "1.0"), Ordering::Less);
        assert_eq!(version_cmp("1.0_alpha1", "1.0_beta1"), Ordering::Less);
        assert_eq!(version_cmp("1.0_beta1", "1.0_rc1"), Ordering::Less);
        assert_eq!(version_cmp("1.0_rc1", "1.0"), Ordering::Less);
    }

    #[test]
    fn version_cmp_orders_post_release_suffixes_above_the_plain_release() {
        use std::cmp::Ordering;
        assert_eq!(version_cmp("1.0", "1.0_git1"), Ordering::Less);
    }

    #[test]
    fn parse_apkindex_block_does_not_panic_on_a_multi_byte_field_key() {
        // A key is documented as always being a single ASCII character,
        // but an upstream (malicious or buggy) can still serve one that
        // isn't — this must not panic by slicing mid-character.
        let fields = parse_apkindex_block("€:x\nP:hello\nV:1.0\n");
        assert_eq!(fields.get(&'P').map(String::as_str), Some("hello"));
        assert_eq!(fields.get(&'V').map(String::as_str), Some("1.0"));
    }
}
