//! Debian `.deb`: parsing, `apt` pool/dists layout, and `Packages`/`Release`
//! generation.
//!
//! A `.deb` is a Unix `ar` archive of exactly three members: `debian-binary`,
//! `control.tar.<codec>` and `data.tar.<codec>`. Everything the index needs
//! lives in `control.tar`'s `control` file, a deb822 (RFC822-shaped)
//! key/value stanza — the same story as apk's `.PKGINFO` and pacman's
//! `.PKGINFO`, just a different text shape.
//!
//! Unlike RPM/apk/pacman, `apt` does not fetch a per-architecture tree of
//! its own accord *and* a channel-wide summary in one request the way apk
//! fetches `$arch/APKINDEX.tar.gz` alone: it always fetches `dists/<suite>`'s
//! `Release`/`InRelease` first, which enumerates every architecture's
//! `Packages*` by name, size and checksum. That makes `Release` a function
//! of *every* architecture's rows at once, not just one — so `index_group`
//! is the whole channel here, the same choice RPM makes and for the same
//! reason: [`build_index`](Format::build_index) has to see every row to
//! render `Release`, so there is exactly one group, and one lock, per
//! channel. Splitting by architecture the way apk/pacman do would mean
//! `Release` could only be rendered by re-reading sibling architectures'
//! already-written index objects, breaking the "index is a pure function of
//! the database rows" invariant every other renderer here relies on.
//!
//! Component is always `main` and suite is always the channel name — apt
//! repositories can carry several components and several suites sharing one
//! pool, but nothing in silo's model partitions a channel any further than
//! that, so this offers exactly one of each, the same scope RPM's single
//! repodata tree and npm's one-tarball-per-name already keep to.

use std::collections::BTreeMap;
use std::io::Write;
use std::pin::Pin;

use serde_json::json;
use sha2::{Digest, Sha256};

use crate::apk::gzip;
use crate::{
    Format, IndexContext, IndexObject, PackageFormat, PackageRecord, ParseError, ParsedPackage,
};

pub struct DebFormat;

/// The architecture a `.deb` declares when it works on all of them —
/// Debian's `noarch`. Unlike apk's `noarch` and pacman's `any`, `all`
/// packages are not published under their own directory at all: a real
/// Debian archive folds them into every concrete architecture's `Packages`
/// file and apt never asks for a `binary-all` tree on its own, so one is
/// never produced here either.
pub const ALL: &str = "all";

/// Fields carried from `control` into the database and back out into a
/// `Packages` stanza, in the order `dpkg-scanpackages` writes them for a
/// freshly built archive.
const STANZA_FIELDS: &[&str] = &[
    "Installed-Size",
    "Maintainer",
    "Depends",
    "Recommends",
    "Suggests",
    "Conflicts",
    "Breaks",
    "Provides",
    "Replaces",
    "Section",
    "Priority",
    "Homepage",
    "Description",
];

impl Format for DebFormat {
    fn format(&self) -> PackageFormat {
        PackageFormat::Deb
    }

    fn parse(&self, bytes: &[u8]) -> Result<ParsedPackage, ParseError> {
        let control_text = read_control(bytes)?;
        let fields = parse_control(&control_text);
        let get = |k: &str| fields.get(k).cloned();

        let name =
            get("Package").ok_or_else(|| ParseError::invalid("control is missing Package"))?;
        let raw_version =
            get("Version").ok_or_else(|| ParseError::invalid("control is missing Version"))?;
        let arch = get("Architecture")
            .ok_or_else(|| ParseError::invalid("control is missing Architecture"))?;
        let (epoch, version, release) = split_version(&raw_version)?;

        let filename = format!(
            "{name}_{}_{arch}.deb",
            version_without_epoch(&version, &release)
        );

        let metadata = json!({
            "installed_size": get("Installed-Size").and_then(|s| s.parse::<u64>().ok()),
            "maintainer": get("Maintainer"),
            "depends": get("Depends"),
            "recommends": get("Recommends"),
            "suggests": get("Suggests"),
            "conflicts": get("Conflicts"),
            "breaks": get("Breaks"),
            "provides": get("Provides"),
            "replaces": get("Replaces"),
            "section": get("Section"),
            "priority": get("Priority"),
            "homepage": get("Homepage"),
            "description": get("Description"),
        });

        Ok(ParsedPackage {
            format: PackageFormat::Deb,
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
        format!("{}/{}", pool_prefix(repo, channel), pkg.filename)
    }

    /// One `Release` per channel, covering every architecture at once — see
    /// the module doc for why apt's shape rules out per-architecture groups
    /// the way apk/pacman use them.
    fn index_group(&self, _pkg: &ParsedPackage) -> String {
        String::new()
    }

    fn index_prefix(&self, repo: &str, channel: &str, _group: &str) -> String {
        dists_prefix(repo, channel)
    }

    fn build_index<'a>(
        &'a self,
        ctx: &'a IndexContext<'a>,
    ) -> Pin<Box<dyn std::future::Future<Output = anyhow::Result<Vec<IndexObject>>> + Send + 'a>>
    {
        Box::pin(async move {
            let mut by_arch: BTreeMap<&str, Vec<&PackageRecord>> = BTreeMap::new();
            for record in ctx.records {
                by_arch
                    .entry(record.arch.as_str())
                    .or_default()
                    .push(record);
            }
            let all_records: Vec<&PackageRecord> = by_arch.get(ALL).cloned().unwrap_or_default();
            let arches: Vec<&str> = by_arch
                .keys()
                .copied()
                .filter(|arch| *arch != ALL)
                .collect();

            let mut objects = Vec::new();
            // (path relative to the dists/<suite> root, sha256, size)
            let mut release_entries: Vec<(String, String, usize)> = Vec::new();

            for arch in &arches {
                let mut records: Vec<&PackageRecord> =
                    by_arch.get(arch).cloned().unwrap_or_default();
                records.extend(&all_records);
                records.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));

                let packages = render_packages(&records).into_bytes();
                let packages_gz = gzip(&packages)?;
                let packages_xz = xz(&packages)?;

                for (name, bytes, content_type) in [
                    (
                        format!("main/binary-{arch}/Packages"),
                        packages,
                        "text/plain",
                    ),
                    (
                        format!("main/binary-{arch}/Packages.gz"),
                        packages_gz,
                        "application/gzip",
                    ),
                    (
                        format!("main/binary-{arch}/Packages.xz"),
                        packages_xz,
                        "application/x-xz",
                    ),
                ] {
                    let sha256 = hex::encode(Sha256::digest(&bytes));
                    release_entries.push((name.clone(), sha256, bytes.len()));
                    objects.push(IndexObject {
                        name,
                        bytes,
                        content_type,
                    });
                }
            }

            // Same reasoning as RPM's repomd revision: derived from the
            // newest publish so an unchanged repo regenerates a byte-
            // identical Release instead of churning its Date on every run.
            let revision = ctx
                .records
                .iter()
                .map(|r| r.published_at)
                .max()
                .unwrap_or_default();

            let release =
                render_release(ctx.repo, ctx.channel, &arches, &release_entries, revision);
            objects.push(IndexObject {
                name: "Release".to_string(),
                bytes: release.clone().into_bytes(),
                content_type: "text/plain",
            });

            // `apt` only trusts a repository whose `Release` is verified
            // either through a detached `Release.gpg` or the equivalent
            // (and now more common) clearsigned `InRelease`. Both are
            // produced here when signing is on; neither exists otherwise.
            if let Some(signer) = ctx.signer {
                let detached = signer.sign(release.as_bytes())?;
                objects.push(IndexObject {
                    name: "Release.gpg".to_string(),
                    bytes: detached,
                    content_type: "text/plain",
                });
                if let Some(inrelease) = signer.clearsign(&release)? {
                    objects.push(IndexObject {
                        name: "InRelease".to_string(),
                        bytes: inrelease.into_bytes(),
                        content_type: "text/plain",
                    });
                }
            }

            Ok(objects)
        })
    }
}

pub fn pool_prefix(repo: &str, channel: &str) -> String {
    format!("{repo}/{channel}/pool")
}

pub fn dists_prefix(repo: &str, channel: &str) -> String {
    format!("{repo}/{channel}/dists/{channel}")
}

/// The `[epoch:]version[-revision]` string a `.deb` filename embeds. Real
/// `.deb` filenames never carry the epoch — `:` is not a safe filename
/// character on every filesystem apt has to run on — so it's dropped here
/// exactly as `dpkg-deb` drops it.
fn version_without_epoch(version: &str, release: &str) -> String {
    if release.is_empty() {
        version.to_string()
    } else {
        format!("{version}-{release}")
    }
}

/// The full `Version:` field value a `Packages` stanza carries, epoch
/// included — unlike the filename, apt's version comparison depends on it
/// being there.
fn full_version(record: &PackageRecord) -> String {
    if record.epoch == 0 {
        version_without_epoch(&record.version, &record.release)
    } else {
        format!(
            "{}:{}",
            record.epoch,
            version_without_epoch(&record.version, &record.release)
        )
    }
}

/// Splits a control file's `Version` field (`[epoch:]upstream_version[-debian_revision]`)
/// into its parts. The revision is separated on the *last* hyphen, since
/// upstream versions legitimately contain hyphens of their own — the same
/// rightmost-hyphen convention RPM's NEVRA and pacman's pkgver splitting
/// both rely on.
fn split_version(version: &str) -> Result<(u32, String, String), ParseError> {
    let (epoch, rest) = match version.split_once(':') {
        Some((e, rest)) => (
            e.parse::<u32>().map_err(|_| {
                ParseError::invalid(format!("invalid epoch in version `{version}`"))
            })?,
            rest,
        ),
        None => (0, version),
    };
    match rest.rsplit_once('-') {
        Some((upstream, revision)) => Ok((epoch, upstream.to_string(), revision.to_string())),
        None => Ok((epoch, rest.to_string(), String::new())),
    }
}

/// Renders the plain-text `Packages` body: one blank-line-separated stanza
/// per package, in `dpkg-scanpackages`' canonical field order.
pub fn render_packages(records: &[&PackageRecord]) -> String {
    let mut out = String::new();
    for record in records {
        out.push_str(&format!("Package: {}\n", record.name));
        out.push_str(&format!("Version: {}\n", full_version(record)));
        out.push_str(&format!("Architecture: {}\n", record.arch));
        for field in STANZA_FIELDS {
            if let Some(value) = json_field(&record.metadata, field) {
                if !value.is_empty() {
                    render_field(&mut out, field, &value);
                }
            }
        }
        out.push_str(&format!("Filename: pool/{}\n", record.filename));
        out.push_str(&format!("Size: {}\n", record.size_bytes));
        out.push_str(&format!("SHA256: {}\n", record.sha256));
        out.push('\n');
    }
    out
}

/// Renders one `Key: value` field, re-indenting embedded newlines as
/// deb822 continuation lines (a leading space, `.` standing in for an
/// empty line) — the inverse of what [`parse_control`] strips off. Without
/// this, a multi-line `Description` would come back out with unindented
/// lines that look like new top-level fields, corrupting the stanza
/// boundary apt scans on.
fn render_field(out: &mut String, field: &str, value: &str) {
    let mut lines = value.split('\n');
    out.push_str(&format!("{field}: {}\n", lines.next().unwrap_or("")));
    for line in lines {
        out.push(' ');
        out.push_str(if line.is_empty() { "." } else { line });
        out.push('\n');
    }
}

/// Renders the channel-wide `Release` control file: repo identity, the
/// architectures actually indexed, and a `SHA256` section listing every
/// `Packages*` object's path, checksum and size — what apt cross-checks
/// each `Packages` download against before trusting a byte of it.
fn render_release(
    repo: &str,
    channel: &str,
    arches: &[&str],
    entries: &[(String, String, usize)],
    revision: i64,
) -> String {
    let date = chrono::DateTime::from_timestamp(revision, 0)
        .unwrap_or_default()
        .to_rfc2822();
    let mut out = String::new();
    out.push_str(&format!("Origin: {repo}\n"));
    out.push_str(&format!("Label: {repo}\n"));
    out.push_str(&format!("Suite: {channel}\n"));
    out.push_str(&format!("Codename: {channel}\n"));
    out.push_str(&format!("Architectures: {}\n", arches.join(" ")));
    out.push_str("Components: main\n");
    out.push_str(&format!("Date: {date}\n"));
    out.push_str("SHA256:\n");
    for (path, sha256, size) in entries {
        out.push_str(&format!(" {sha256} {size} {path}\n"));
    }
    out
}

fn json_field(metadata: &serde_json::Value, field: &str) -> Option<String> {
    match metadata.get(control_key(field))? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Null => None,
        other => Some(other.to_string()),
    }
}

/// Maps a `Packages` stanza field name to the metadata JSON key `parse`
/// stored it under (lower-cased, hyphens to underscores).
fn control_key(field: &str) -> String {
    field.to_ascii_lowercase().replace('-', "_")
}

/// Extracts and inflates `control.tar.<codec>`'s `control` member from a
/// `.deb`'s outer `ar` archive.
fn read_control(bytes: &[u8]) -> Result<String, ParseError> {
    let mut archive = ar::Archive::new(bytes);
    while let Some(entry) = archive.next_entry() {
        let mut entry =
            entry.map_err(|e| ParseError::invalid(format!("corrupt deb ar archive: {e}")))?;
        let identifier = String::from_utf8_lossy(entry.header().identifier()).into_owned();
        if !identifier.starts_with("control.tar") {
            continue;
        }
        let mut compressed = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut compressed)
            .map_err(|e| ParseError::invalid(format!("could not read {identifier}: {e}")))?;
        let inflated = decompress_member(&identifier, &compressed)?;

        let mut tar = tar::Archive::new(inflated.as_slice());
        for tar_entry in tar
            .entries()
            .map_err(|e| ParseError::invalid(format!("corrupt control.tar: {e}")))?
        {
            let mut tar_entry =
                tar_entry.map_err(|e| ParseError::invalid(format!("corrupt control.tar: {e}")))?;
            let path = tar_entry
                .path()
                .map_err(|e| ParseError::invalid(format!("corrupt control.tar entry: {e}")))?
                .to_string_lossy()
                .into_owned();
            if path == "control" || path == "./control" {
                return crate::read_text_capped(&mut tar_entry, "control");
            }
        }
        return Err(ParseError::invalid("control.tar has no control file"));
    }
    Err(ParseError::invalid("deb package has no control.tar member"))
}

/// `control.tar`'s name carries its own codec, unlike apk/pacman where the
/// codec has to be sniffed from magic bytes — so this dispatches on the
/// member name rather than duplicating that detection.
fn decompress_member(identifier: &str, bytes: &[u8]) -> Result<Vec<u8>, ParseError> {
    if identifier.ends_with(".gz") {
        crate::inflate_capped(
            flate2::bufread::GzDecoder::new(bytes),
            crate::MAX_INFLATED_BYTES,
            "deb control.tar.gz",
        )
    } else if identifier.ends_with(".xz") {
        crate::inflate_capped(
            liblzma::read::XzDecoder::new(bytes),
            crate::MAX_INFLATED_BYTES,
            "deb control.tar.xz",
        )
    } else if identifier.ends_with(".zst") {
        let decoder = zstd::stream::read::Decoder::new(bytes)
            .map_err(|e| ParseError::invalid(format!("corrupt zstd control.tar: {e}")))?;
        crate::inflate_capped(decoder, crate::MAX_INFLATED_BYTES, "deb control.tar.zst")
    } else if identifier == "control.tar" {
        if bytes.len() as u64 > crate::MAX_INFLATED_BYTES {
            return Err(ParseError::invalid(
                "control.tar exceeds the decompression limit",
            ));
        }
        Ok(bytes.to_vec())
    } else {
        Err(ParseError::invalid(format!(
            "unsupported control.tar compression: {identifier}"
        )))
    }
}

/// `control` is deb822: `Key: value` stanzas, continuation lines indented
/// with a space (a lone `.` on a continuation line means an empty line in
/// the value, `dpkg`'s convention for multi-paragraph `Description`s).
fn parse_control(text: &str) -> BTreeMap<String, String> {
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(key) = &current {
                let cont = line[1..].to_string();
                let cont = if cont == "." { String::new() } else { cont };
                if let Some(value) = fields.get_mut(key) {
                    value.push('\n');
                    value.push_str(&cont);
                }
            }
            continue;
        }
        if line.trim().is_empty() {
            current = None;
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_string();
        fields.insert(key.clone(), value.trim().to_string());
        current = Some(key);
    }
    fields
}

fn xz(bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut encoder = liblzma::write::XzEncoder::new(Vec::new(), 6);
    encoder.write_all(bytes)?;
    Ok(encoder.finish()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::build_test_deb;

    fn record(name: &str, version: &str, arch: &str) -> PackageRecord {
        let bytes = build_test_deb(name, version, arch);
        let parsed = DebFormat.parse(&bytes).expect("parse deb");
        PackageRecord {
            format: PackageFormat::Deb,
            name: parsed.name,
            epoch: parsed.epoch,
            version: parsed.version,
            release: parsed.release,
            arch: parsed.arch,
            storage_key: format!("r/c/pool/{}", parsed.filename),
            filename: parsed.filename,
            size_bytes: bytes.len() as i64,
            sha256: "deadbeef".into(),
            metadata: parsed.metadata,
            published_at: 1_700_000_000,
        }
    }

    #[test]
    fn parses_a_generated_deb() {
        let bytes = build_test_deb("hello", "1.0-1", "amd64");
        let parsed = DebFormat.parse(&bytes).expect("parse deb");
        assert_eq!(parsed.name, "hello");
        assert_eq!(parsed.version, "1.0");
        assert_eq!(parsed.release, "1");
        assert_eq!(parsed.arch, "amd64");
        assert_eq!(parsed.filename, "hello_1.0-1_amd64.deb");
        assert_eq!(parsed.format, PackageFormat::Deb);
        assert_eq!(parsed.metadata["depends"], json!("libc6"));
    }

    #[test]
    fn rejects_a_deb_without_control() {
        assert!(DebFormat.parse(b"not an ar archive").is_err());
    }

    #[test]
    fn splits_version_with_and_without_epoch() {
        assert_eq!(
            split_version("1.2.3-4").unwrap(),
            (0, "1.2.3".to_string(), "4".to_string())
        );
        assert_eq!(
            split_version("2:1.2.3-4").unwrap(),
            (2, "1.2.3".to_string(), "4".to_string())
        );
        assert_eq!(
            split_version("1.2.3").unwrap(),
            (0, "1.2.3".to_string(), String::new())
        );
    }

    #[test]
    fn filename_drops_the_epoch_but_the_version_field_keeps_it() {
        let bytes = build_test_deb("hello", "2:1.0-1", "amd64");
        let parsed = DebFormat.parse(&bytes).unwrap();
        assert_eq!(parsed.filename, "hello_1.0-1_amd64.deb");
        let rec = PackageRecord {
            format: PackageFormat::Deb,
            name: parsed.name.clone(),
            epoch: parsed.epoch,
            version: parsed.version.clone(),
            release: parsed.release.clone(),
            arch: parsed.arch.clone(),
            filename: parsed.filename.clone(),
            storage_key: format!("r/c/pool/{}", parsed.filename),
            size_bytes: 1234,
            sha256: "deadbeef".into(),
            metadata: parsed.metadata.clone(),
            published_at: 0,
        };
        assert_eq!(full_version(&rec), "2:1.0-1");
    }

    #[test]
    fn layout_paths_are_namespaced_by_repo_and_channel() {
        let pkg = DebFormat
            .parse(&build_test_deb("hello", "1.0-1", "amd64"))
            .unwrap();
        assert_eq!(
            DebFormat.storage_key("myrepo", "stable", &pkg),
            "myrepo/stable/pool/hello_1.0-1_amd64.deb"
        );
        assert_eq!(DebFormat.index_group(&pkg), "");
        assert_eq!(
            DebFormat.index_prefix("myrepo", "stable", ""),
            "myrepo/stable/dists/stable"
        );
    }

    #[test]
    fn packages_stanza_carries_the_curated_fields_and_the_pool_path() {
        let out = render_packages(&[&record("foo", "1.0-1", "amd64")]);
        assert!(out.contains("Package: foo\n"));
        assert!(out.contains("Version: 1.0-1\n"));
        assert!(out.contains("Architecture: amd64\n"));
        assert!(out.contains("Depends: libc6\n"));
        assert!(out.contains("Filename: pool/foo_1.0-1_amd64.deb\n"));
        assert!(out.contains("SHA256: deadbeef\n"));
        assert!(out.ends_with("\n\n"));
    }

    /// A multi-line control field (`Description`'s extended text) has to
    /// come back out of the stanza with every continuation line re-
    /// indented — real `.deb`s from `dpkg-deb` carry exactly this shape,
    /// and an unindented continuation line reads as a bare "new field"
    /// with no colon, which apt silently drops rather than erroring on,
    /// corrupting the stanza a real client parses.
    #[test]
    fn multi_line_description_continuation_lines_stay_indented() {
        let out = render_packages(&[&record("foo", "1.0-1", "amd64")]);
        let stanza = out.split("\n\n").next().unwrap();
        for line in stanza.lines().skip(1) {
            assert!(
                line.starts_with(' ') || line.contains(':'),
                "line is neither a continuation nor a new field: {line:?}\nfull stanza:\n{stanza}"
            );
        }
        assert!(
            out.contains(
                "Description: a test package\n end-to-end tests exercise this description\n"
            ),
            "{out}"
        );
    }

    #[test]
    fn an_all_arch_package_is_folded_into_every_concrete_architecture() {
        let noarch = record("shared", "1.0-1", "all");
        let amd64 = record("hello", "1.0-1", "amd64");
        let arm64 = record("hello", "1.0-1", "arm64");
        let records = [&amd64, &arm64, &noarch];

        let mut by_arch: BTreeMap<&str, Vec<&PackageRecord>> = BTreeMap::new();
        for r in records {
            by_arch.entry(r.arch.as_str()).or_default().push(r);
        }
        let all: Vec<&PackageRecord> = by_arch[ALL].clone();
        for arch in ["amd64", "arm64"] {
            let mut recs = by_arch[arch].clone();
            recs.extend(&all);
            let out = render_packages(&recs);
            assert!(out.contains("Package: hello\n"));
            assert!(out.contains("Package: shared\n"));
        }
    }

    #[tokio::test]
    async fn build_index_renders_release_and_per_arch_packages_files() {
        let amd64 = record("hello", "1.0-1", "amd64");
        let records = [amd64];
        let ctx = IndexContext {
            repo: "r",
            channel: "stable",
            group: "",
            records: &records,
            public_base_url: None,
            signer: None,
        };
        let objects = DebFormat.build_index(&ctx).await.unwrap();
        let names: Vec<&str> = objects.iter().map(|o| o.name.as_str()).collect();
        assert!(names.contains(&"main/binary-amd64/Packages"));
        assert!(names.contains(&"main/binary-amd64/Packages.gz"));
        assert!(names.contains(&"main/binary-amd64/Packages.xz"));
        assert!(names.contains(&"Release"));
        assert!(
            !names.contains(&"Release.gpg"),
            "unsigned build must not sign"
        );
        assert!(!names.contains(&"InRelease"));

        let release = objects.iter().find(|o| o.name == "Release").unwrap();
        let text = String::from_utf8(release.bytes.clone()).unwrap();
        assert!(text.contains("Suite: stable\n"));
        assert!(text.contains("Architectures: amd64\n"));
        assert!(text.contains("main/binary-amd64/Packages"));
    }

    #[tokio::test]
    async fn no_binary_all_directory_is_ever_produced() {
        let noarch = record("shared", "1.0-1", "all");
        let records = [noarch];
        let ctx = IndexContext {
            repo: "r",
            channel: "stable",
            group: "",
            records: &records,
            public_base_url: None,
            signer: None,
        };
        let objects = DebFormat.build_index(&ctx).await.unwrap();
        assert!(
            objects.iter().all(|o| !o.name.contains("binary-all")),
            "an all-only repo must never produce a binary-all directory — apt never asks \
             for one any more than apk asks for noarch or pacman asks for any, so an \
             all-arch package stays invisible until a concrete architecture is published"
        );
        // Release is still emitted, the same "always valid, even empty" precedent
        // repodata.rs's `an_empty_repo_still_produces_valid_metadata` sets for RPM.
        let release = objects.iter().find(|o| o.name == "Release").unwrap();
        let text = String::from_utf8(release.bytes.clone()).unwrap();
        assert!(text.contains("Architectures: \n"));
    }

    struct FakeSigner;
    impl crate::IndexSigner for FakeSigner {
        fn key_name(&self) -> &str {
            "test"
        }
        fn sign(&self, _data: &[u8]) -> anyhow::Result<Vec<u8>> {
            Ok(vec![0xEF; 64])
        }
        fn clearsign(&self, text: &str) -> anyhow::Result<Option<String>> {
            Ok(Some(format!(
                "-----BEGIN PGP SIGNED MESSAGE-----\n\n{text}"
            )))
        }
    }

    #[tokio::test]
    async fn signed_index_adds_release_gpg_and_inrelease() {
        let amd64 = record("hello", "1.0-1", "amd64");
        let records = [amd64];
        let signer = FakeSigner;
        let ctx = IndexContext {
            repo: "r",
            channel: "stable",
            group: "",
            records: &records,
            public_base_url: None,
            signer: Some(&signer),
        };
        let objects = DebFormat.build_index(&ctx).await.unwrap();
        let names: Vec<&str> = objects.iter().map(|o| o.name.as_str()).collect();
        assert!(names.contains(&"Release.gpg"));
        assert!(names.contains(&"InRelease"));

        let inrelease = objects.iter().find(|o| o.name == "InRelease").unwrap();
        let text = String::from_utf8(inrelease.bytes.clone()).unwrap();
        assert!(text.starts_with("-----BEGIN PGP SIGNED MESSAGE-----"));
        assert!(text.contains("Suite: stable"));
    }
}
