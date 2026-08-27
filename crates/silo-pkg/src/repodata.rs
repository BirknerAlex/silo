//! yum/dnf repodata, generated in-process.
//!
//! This replaces a `createrepo_c` subprocess. The motivation is deployment
//! rather than performance: `createrepo_c` is packaged only for a handful
//! of Linux distributions, which forced the server image to be Debian with
//! an apt-installed C toolchain, made the RPM tests unrunnable on macOS,
//! and put an external binary on the critical path of every publish. The
//! `rpm` crate already parses every header field the format needs, so the
//! remaining work is XML serialization and checksums.
//!
//! ## What is generated
//!
//! Four files, the same set `createrepo_c` produces with default options:
//!
//! | file | contents |
//! |---|---|
//! | `primary.xml.gz` | identity, dependencies, and the "primary" subset of the file list |
//! | `filelists.xml.gz` | every file in every package |
//! | `other.xml.gz` | changelogs |
//! | `repomd.xml` | checksums, sizes and locations of the three above |
//!
//! Compressed members are named `<sha256-of-compressed>-<file>`, which is
//! the `createrepo_c` convention: the name changes whenever the content
//! does, so a cache or CDN in front of the repo can serve them immutably.
//! `repomd.xml` keeps a fixed name because it is the entry point clients
//! resolve everything else through.
//!
//! ## What is deliberately not generated
//!
//! No sqlite databases (`primary.sqlite` and friends), no delta metadata,
//! no `updateinfo`. dnf has read XML metadata natively since 2015 and only
//! falls back to sqlite for repos that advertise it; advertising none is
//! a supported configuration, not a degraded one.
//!
//! ## Why this is split in two
//!
//! [`extract`] reads a `.rpm`'s headers once, at publish time, into a
//! [`RepodataEntry`] that is stored in the database alongside the package
//! row. [`build`] renders XML from those entries and never sees a `.rpm`
//! at all.
//!
//! The split is what lets RPM be indexed from database rows like apk and
//! npm are. Before it, regenerating a channel's repodata meant downloading
//! every package in that channel out of object storage first — on every
//! single publish, because RPM has one index per channel rather than one
//! per architecture or package name.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use rpm::{DependencyFlags, FileFlags, FileType, IndexTag, PackageMetadata};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One generated repodata file, ready to be written to storage.
#[derive(Debug, Clone, PartialEq)]
pub struct RepodataFile {
    /// Filename relative to the `repodata/` prefix.
    pub name: String,
    pub bytes: Vec<u8>,
    pub content_type: &'static str,
}

/// Where clients fetch a package, and what they should get.
///
/// Separate from [`RepodataEntry`] because these three are *not* properties
/// of the rpm headers: the href depends on the repo layout, and the size
/// and digest are of the bytes as stored — which, for a package silo
/// signed, differ from the bytes that were uploaded. All three are already
/// columns on the package row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepodataLocation {
    /// `location href` relative to the repo root, e.g.
    /// `Packages/foo-1.0-1.x86_64.rpm`.
    pub href: String,
    /// Hex sha256 of the stored package file.
    pub sha256: String,
    pub size: u64,
}

/// Renders a full repodata tree from previously [`extract`]ed entries.
///
/// `revision` is the value clients compare to decide whether their cached
/// metadata is stale; pass the newest publish timestamp in the repo so
/// that regenerating an unchanged repo produces an unchanged revision.
pub fn build(
    packages: &[(RepodataEntry, RepodataLocation)],
    revision: i64,
) -> anyhow::Result<Vec<RepodataFile>> {
    let parsed: Vec<(&RepodataEntry, &RepodataLocation)> =
        packages.iter().map(|(e, l)| (e, l)).collect();

    let sections = [
        ("primary", primary_xml(&parsed)),
        ("filelists", filelists_xml(&parsed)),
        ("other", other_xml(&parsed)),
    ];

    let mut files = Vec::with_capacity(4);
    let mut entries = Vec::with_capacity(3);
    for (kind, xml) in sections {
        let open_bytes = xml.into_bytes();
        let compressed = gzip(&open_bytes)?;

        let checksum = hex_sha256(&compressed);
        let name = format!("{checksum}-{kind}.xml.gz");

        entries.push(RepomdEntry {
            kind,
            checksum,
            open_checksum: hex_sha256(&open_bytes),
            location: format!("repodata/{name}"),
            size: compressed.len(),
            open_size: open_bytes.len(),
            timestamp: revision,
        });
        files.push(RepodataFile {
            name,
            bytes: compressed,
            content_type: "application/gzip",
        });
    }

    files.push(RepodataFile {
        name: "repomd.xml".to_string(),
        bytes: repomd_xml(&entries, revision).into_bytes(),
        content_type: "application/xml",
    });
    Ok(files)
}

// ------------------------------------------------------------- extraction

/// Everything repodata needs from an RPM's headers.
///
/// Stored as JSON on the package row, so the headers are read exactly
/// once — at publish — rather than on every index regeneration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepodataEntry {
    name: String,
    arch: String,
    epoch: u32,
    version: String,
    release: String,
    summary: String,
    description: String,
    packager: String,
    url: String,
    license: String,
    vendor: String,
    group: String,
    build_host: String,
    source_rpm: String,
    build_time: u64,
    installed_size: u64,
    archive_size: u64,
    header_start: u64,
    header_end: u64,
    files: Vec<FileRecord>,
    provides: Vec<Entry>,
    requires: Vec<Entry>,
    conflicts: Vec<Entry>,
    obsoletes: Vec<Entry>,
    recommends: Vec<Entry>,
    suggests: Vec<Entry>,
    supplements: Vec<Entry>,
    enhances: Vec<Entry>,
    changelogs: Vec<Changelog>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct FileRecord {
    path: String,
    /// `""` for regular files, `"dir"`, or `"ghost"` — the values the
    /// filelists schema uses.
    kind: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Changelog {
    author: String,
    date: u64,
    text: String,
}

/// A dependency, in the shape `<rpm:entry>` wants it: the version is
/// pre-split into the epoch/ver/rel attributes rather than a `1:2.3-4`
/// string.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Entry {
    name: String,
    flags: String,
    epoch: Option<String>,
    version: Option<String>,
    release: Option<String>,
    /// Set on requires that must be satisfied before install scriptlets
    /// run. Only meaningful in `<rpm:requires>`.
    pre: bool,
}

/// Reads an RPM's headers into the form [`build`] renders from.
///
/// Only the lead and the two headers are read; the compressed payload is
/// never touched, so this is cheap even for a large package.
pub fn extract(bytes: &[u8]) -> anyhow::Result<RepodataEntry> {
    RepodataEntry::from_rpm(bytes)
}

impl RepodataEntry {
    fn from_rpm(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut reader = std::io::BufReader::new(bytes);
        let md = PackageMetadata::parse(&mut reader)
            .map_err(|e| anyhow::anyhow!("failed to read rpm headers: {e}"))?;

        let offsets = md.get_package_segment_offsets();
        // `header_end` is where the compressed payload begins: dnf ranged-
        // GETs `[start, end)` to read a package's header without pulling
        // the whole file.
        let (header_start, header_end) = (offsets.header, offsets.payload);

        let files = md
            .get_file_entries()
            .map(|entries| {
                entries
                    .into_iter()
                    .map(|entry| FileRecord {
                        path: entry.path().to_string_lossy().into_owned(),
                        kind: if entry.flags().contains(FileFlags::GHOST) {
                            "ghost".to_string()
                        } else if entry.file_type() == FileType::Dir {
                            "dir".to_string()
                        } else {
                            String::new()
                        },
                    })
                    .collect()
            })
            .unwrap_or_default();

        let changelogs = md
            .get_changelog_entries()
            .map(|entries| {
                entries
                    .into_iter()
                    .map(|c| Changelog {
                        author: c.name,
                        date: c.timestamp,
                        text: c.description,
                    })
                    .collect()
            })
            .unwrap_or_default();

        // `get_installed_size` already falls back from LONGSIZE to SIZE.
        // Archive size has the same two-tag split but no helper.
        let archive_size = md
            .header
            .get_entry_data_as_u64(IndexTag::RPMTAG_LONGARCHIVESIZE)
            .or_else(|_| {
                md.header
                    .get_entry_data_as_u32(IndexTag::RPMTAG_ARCHIVESIZE)
                    .map(u64::from)
            })
            .unwrap_or(0);

        Ok(RepodataEntry {
            name: md.get_name().unwrap_or_default().to_string(),
            arch: md.get_arch().unwrap_or_default().to_string(),
            epoch: md.get_epoch().unwrap_or(0),
            version: md.get_version().unwrap_or_default().to_string(),
            release: md.get_release().unwrap_or_default().to_string(),
            summary: md.get_summary().unwrap_or_default().to_string(),
            description: md.get_description().unwrap_or_default().to_string(),
            packager: md.get_packager().unwrap_or_default().to_string(),
            url: md.get_url().unwrap_or_default().to_string(),
            license: md.get_license().unwrap_or_default().to_string(),
            vendor: md.get_vendor().unwrap_or_default().to_string(),
            group: md.get_group().unwrap_or_default().to_string(),
            build_host: md.get_build_host().unwrap_or_default().to_string(),
            source_rpm: md.get_source_rpm().unwrap_or_default().to_string(),
            build_time: md.get_build_time().unwrap_or(0),
            installed_size: md.get_installed_size().unwrap_or(0),
            archive_size,
            header_start,
            header_end,
            files,
            provides: entries(md.get_provides().unwrap_or_default(), false),
            requires: entries(dedupe_requires(md.get_requires().unwrap_or_default()), true),
            conflicts: entries(md.get_conflicts().unwrap_or_default(), false),
            obsoletes: entries(md.get_obsoletes().unwrap_or_default(), false),
            recommends: entries(md.get_recommends().unwrap_or_default(), false),
            suggests: entries(md.get_suggests().unwrap_or_default(), false),
            supplements: entries(md.get_supplements().unwrap_or_default(), false),
            enhances: entries(md.get_enhances().unwrap_or_default(), false),
            changelogs,
        })
    }

    fn version_tag(&self) -> String {
        format!(
            "<version epoch=\"{}\" ver=\"{}\" rel=\"{}\"/>",
            self.epoch,
            escape(&self.version),
            escape(&self.release)
        )
    }
}

fn entries(deps: Vec<rpm::Dependency>, requires: bool) -> Vec<Entry> {
    deps.into_iter()
        .map(|dep| {
            let (epoch, version, release) = split_evr(&dep.version);
            Entry {
                flags: flag_name(dep.flags).to_string(),
                name: dep.name,
                epoch,
                version,
                release,
                pre: requires && dep.flags.intersects(PREINSTALL_FLAGS),
            }
        })
        .collect()
}

/// Requires that `createrepo_c` also drops before writing primary.xml.
///
/// `rpmlib(...)` entries describe capabilities of the rpm binary itself,
/// not of any package in the repo. Leaving them in makes every depsolve
/// chase a provider that no repository can ever supply.
fn dedupe_requires(deps: Vec<rpm::Dependency>) -> Vec<rpm::Dependency> {
    let mut seen = BTreeSet::new();
    deps.into_iter()
        .filter(|dep| !dep.name.starts_with("rpmlib("))
        .filter(|dep| seen.insert((dep.name.clone(), dep.flags.bits(), dep.version.clone())))
        .collect()
}

/// Flags marking a dependency as needed before the package's own scripts
/// run, which primary.xml surfaces as `pre="1"`.
const PREINSTALL_FLAGS: DependencyFlags = DependencyFlags::PREREQ
    .union(DependencyFlags::SCRIPT_PRE)
    .union(DependencyFlags::SCRIPT_POST)
    .union(DependencyFlags::PRETRANS)
    .union(DependencyFlags::POSTTRANS);

/// The comparison operator, spelled the way the repodata schema spells it
/// (`EQ`/`LT`/…) rather than the way rpm does (`=`/`<`/…).
fn flag_name(flags: DependencyFlags) -> &'static str {
    match flags.comparator_str() {
        "<=" => "LE",
        ">=" => "GE",
        "<" => "LT",
        ">" => "GT",
        "=" => "EQ",
        _ => "",
    }
}

/// Splits an rpm version string (`[epoch:]version[-release]`) into the
/// three attributes `<rpm:entry>` carries separately.
fn split_evr(evr: &str) -> (Option<String>, Option<String>, Option<String>) {
    if evr.is_empty() {
        return (None, None, None);
    }
    let (epoch, rest) = match evr.split_once(':') {
        // Only treat the prefix as an epoch if it actually is a number;
        // otherwise a version that merely contains a colon would lose its
        // first segment.
        Some((head, tail)) if !head.is_empty() && head.bytes().all(|b| b.is_ascii_digit()) => {
            (head.to_string(), tail)
        }
        _ => ("0".to_string(), evr),
    };
    let (version, release) = match rest.split_once('-') {
        Some((v, r)) => (v.to_string(), Some(r.to_string())),
        None => (rest.to_string(), None),
    };
    (Some(epoch), Some(version), release)
}

/// Whether a path belongs in primary.xml's abbreviated file list.
///
/// primary.xml is downloaded by every client on every refresh, so it
/// carries only the paths a dependency can plausibly name: anything under
/// a `bin/` directory, anything in `/etc`, and the one historical special
/// case rpm itself hardcodes. Everything else is in filelists.xml, which
/// clients fetch only when they need it.
fn is_primary_file(path: &str) -> bool {
    path.starts_with("/etc/")
        || path == "/etc"
        || path.contains("bin/")
        || path == "/usr/lib/sendmail"
}

// ----------------------------------------------------------------- render

fn primary_xml(packages: &[(&RepodataEntry, &RepodataLocation)]) -> String {
    let mut out = String::with_capacity(4096);
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let _ = writeln!(
        out,
        "<metadata xmlns=\"http://linux.duke.edu/metadata/common\" \
         xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\" packages=\"{}\">",
        packages.len()
    );

    for (pkg, location) in packages {
        out.push_str("<package type=\"rpm\">\n");
        let _ = writeln!(out, "  <name>{}</name>", escape(&pkg.name));
        let _ = writeln!(out, "  <arch>{}</arch>", escape(&pkg.arch));
        let _ = writeln!(out, "  {}", pkg.version_tag());
        let _ = writeln!(
            out,
            "  <checksum type=\"sha256\" pkgid=\"YES\">{}</checksum>",
            escape(&location.sha256)
        );
        let _ = writeln!(out, "  <summary>{}</summary>", escape(&pkg.summary));
        let _ = writeln!(
            out,
            "  <description>{}</description>",
            escape(&pkg.description)
        );
        let _ = writeln!(out, "  <packager>{}</packager>", escape(&pkg.packager));
        let _ = writeln!(out, "  <url>{}</url>", escape(&pkg.url));
        // `file` is normally the .rpm's mtime. Silo has no meaningful
        // mtime — the same package can be re-uploaded or restored from a
        // backup — so build time stands in, which keeps regeneration
        // deterministic.
        let _ = writeln!(
            out,
            "  <time file=\"{}\" build=\"{}\"/>",
            pkg.build_time, pkg.build_time
        );
        let _ = writeln!(
            out,
            "  <size package=\"{}\" installed=\"{}\" archive=\"{}\"/>",
            location.size, pkg.installed_size, pkg.archive_size
        );
        let _ = writeln!(out, "  <location href=\"{}\"/>", escape(&location.href));
        out.push_str("  <format>\n");
        let _ = writeln!(
            out,
            "    <rpm:license>{}</rpm:license>",
            escape(&pkg.license)
        );
        let _ = writeln!(out, "    <rpm:vendor>{}</rpm:vendor>", escape(&pkg.vendor));
        let _ = writeln!(out, "    <rpm:group>{}</rpm:group>", escape(&pkg.group));
        let _ = writeln!(
            out,
            "    <rpm:buildhost>{}</rpm:buildhost>",
            escape(&pkg.build_host)
        );
        let _ = writeln!(
            out,
            "    <rpm:sourcerpm>{}</rpm:sourcerpm>",
            escape(&pkg.source_rpm)
        );
        let _ = writeln!(
            out,
            "    <rpm:header-range start=\"{}\" end=\"{}\"/>",
            pkg.header_start, pkg.header_end
        );

        for (tag, deps) in [
            ("provides", &pkg.provides),
            ("requires", &pkg.requires),
            ("conflicts", &pkg.conflicts),
            ("obsoletes", &pkg.obsoletes),
            ("recommends", &pkg.recommends),
            ("suggests", &pkg.suggests),
            ("supplements", &pkg.supplements),
            ("enhances", &pkg.enhances),
        ] {
            if deps.is_empty() {
                continue;
            }
            let _ = writeln!(out, "    <rpm:{tag}>");
            for dep in deps.iter() {
                out.push_str("      ");
                write_entry(&mut out, dep);
            }
            let _ = writeln!(out, "    </rpm:{tag}>");
        }

        for file in pkg.files.iter().filter(|f| is_primary_file(&f.path)) {
            write_file(&mut out, "    ", file);
        }

        out.push_str("  </format>\n</package>\n");
    }

    out.push_str("</metadata>\n");
    out
}

/// A `<file>` element, which is spelled identically in primary.xml and
/// filelists.xml and differs only in how deeply it is indented.
fn write_file(out: &mut String, indent: &str, file: &FileRecord) {
    out.push_str(indent);
    if file.kind.is_empty() {
        let _ = writeln!(out, "<file>{}</file>", escape(&file.path));
    } else {
        let _ = writeln!(
            out,
            "<file type=\"{}\">{}</file>",
            file.kind,
            escape(&file.path)
        );
    }
}

fn write_entry(out: &mut String, dep: &Entry) {
    let _ = write!(out, "<rpm:entry name=\"{}\"", escape(&dep.name));
    if !dep.flags.is_empty() {
        let _ = write!(out, " flags=\"{}\"", dep.flags);
        if let Some(epoch) = &dep.epoch {
            let _ = write!(out, " epoch=\"{}\"", escape(epoch));
        }
        if let Some(version) = &dep.version {
            let _ = write!(out, " ver=\"{}\"", escape(version));
        }
        if let Some(release) = &dep.release {
            let _ = write!(out, " rel=\"{}\"", escape(release));
        }
    }
    if dep.pre {
        out.push_str(" pre=\"1\"");
    }
    out.push_str("/>\n");
}

fn filelists_xml(packages: &[(&RepodataEntry, &RepodataLocation)]) -> String {
    let mut out = String::with_capacity(4096);
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let _ = writeln!(
        out,
        "<filelists xmlns=\"http://linux.duke.edu/metadata/filelists\" packages=\"{}\">",
        packages.len()
    );
    for (pkg, location) in packages {
        let _ = writeln!(
            out,
            "<package pkgid=\"{}\" name=\"{}\" arch=\"{}\">",
            escape(&location.sha256),
            escape(&pkg.name),
            escape(&pkg.arch)
        );
        let _ = writeln!(out, "  {}", pkg.version_tag());
        for file in &pkg.files {
            write_file(&mut out, "  ", file);
        }
        out.push_str("</package>\n");
    }
    out.push_str("</filelists>\n");
    out
}

fn other_xml(packages: &[(&RepodataEntry, &RepodataLocation)]) -> String {
    let mut out = String::with_capacity(1024);
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let _ = writeln!(
        out,
        "<otherdata xmlns=\"http://linux.duke.edu/metadata/other\" packages=\"{}\">",
        packages.len()
    );
    for (pkg, location) in packages {
        let _ = writeln!(
            out,
            "<package pkgid=\"{}\" name=\"{}\" arch=\"{}\">",
            escape(&location.sha256),
            escape(&pkg.name),
            escape(&pkg.arch)
        );
        let _ = writeln!(out, "  {}", pkg.version_tag());
        for entry in &pkg.changelogs {
            let _ = writeln!(
                out,
                "  <changelog author=\"{}\" date=\"{}\">{}</changelog>",
                escape(&entry.author),
                entry.date,
                escape(&entry.text)
            );
        }
        out.push_str("</package>\n");
    }
    out.push_str("</otherdata>\n");
    out
}

struct RepomdEntry {
    kind: &'static str,
    checksum: String,
    open_checksum: String,
    location: String,
    size: usize,
    open_size: usize,
    timestamp: i64,
}

fn repomd_xml(entries: &[RepomdEntry], revision: i64) -> String {
    let mut out = String::with_capacity(1024);
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(
        "<repomd xmlns=\"http://linux.duke.edu/metadata/repo\" \
         xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\">\n",
    );
    let _ = writeln!(out, "  <revision>{revision}</revision>");
    for entry in entries {
        let _ = writeln!(out, "  <data type=\"{}\">", entry.kind);
        let _ = writeln!(
            out,
            "    <checksum type=\"sha256\">{}</checksum>",
            entry.checksum
        );
        let _ = writeln!(
            out,
            "    <open-checksum type=\"sha256\">{}</open-checksum>",
            entry.open_checksum
        );
        let _ = writeln!(out, "    <location href=\"{}\"/>", escape(&entry.location));
        let _ = writeln!(out, "    <timestamp>{}</timestamp>", entry.timestamp);
        let _ = writeln!(out, "    <size>{}</size>", entry.size);
        let _ = writeln!(out, "    <open-size>{}</open-size>", entry.open_size);
        out.push_str("  </data>\n");
    }
    out.push_str("</repomd>\n");
    out
}

// ---------------------------------------------------------------- helpers

/// XML-escapes text and attribute content.
///
/// Also strips control characters: RPM headers are attacker-supplied in a
/// registry that accepts uploads, and a raw `\x00` or `\x08` makes the
/// whole metadata document unparseable for every client, not just the one
/// that uploaded it. XML 1.0 has no escape for them, so dropping is the
/// only option that keeps the document well-formed.
fn escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' => out.push(ch),
            c if (c as u32) < 0x20 => {}
            c => out.push(c),
        }
    }
    out
}

fn gzip(bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes)?;
    encoder.finish()
}

fn hex_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::build_test_rpm;
    use std::io::Read;

    /// The pair `build` takes: headers read from real `.rpm` bytes, plus
    /// the location fields the package row would supply.
    fn input(bytes: &[u8], href: &str) -> (RepodataEntry, RepodataLocation) {
        (
            extract(bytes).expect("extract rpm headers"),
            RepodataLocation {
                sha256: hex_sha256(bytes),
                size: bytes.len() as u64,
                href: href.to_string(),
            },
        )
    }

    fn inflate(bytes: &[u8]) -> String {
        let mut out = Vec::new();
        flate2::bufread::GzDecoder::new(bytes)
            .read_to_end(&mut out)
            .unwrap();
        String::from_utf8(out).unwrap()
    }

    /// Returns the four generated files keyed by their repomd `type`,
    /// with the compressed ones inflated back to XML.
    fn generate(packages: &[(RepodataEntry, RepodataLocation)]) -> (String, Vec<(String, String)>) {
        let files = build(packages, 1_700_000_000).unwrap();
        let repomd = files.iter().find(|f| f.name == "repomd.xml").unwrap();
        let rest = files
            .iter()
            .filter(|f| f.name != "repomd.xml")
            .map(|f| (f.name.clone(), inflate(&f.bytes)))
            .collect();
        (String::from_utf8(repomd.bytes.clone()).unwrap(), rest)
    }

    #[test]
    fn produces_the_four_files_dnf_expects() {
        let rpm = build_test_rpm("silo-test", "1.2.3", "4", "x86_64");
        let files = build(
            &[input(&rpm, "Packages/silo-test-1.2.3-4.x86_64.rpm")],
            1_700_000_000,
        )
        .unwrap();

        assert_eq!(files.len(), 4);
        assert!(files.iter().any(|f| f.name == "repomd.xml"));
        for kind in ["primary", "filelists", "other"] {
            let file = files
                .iter()
                .find(|f| f.name.ends_with(&format!("-{kind}.xml.gz")))
                .unwrap_or_else(|| panic!("missing {kind}"));
            assert_eq!(file.content_type, "application/gzip");
            // The name is the checksum of the content it names.
            assert_eq!(
                file.name,
                format!("{}-{kind}.xml.gz", hex_sha256(&file.bytes))
            );
        }
    }

    #[test]
    fn repomd_checksums_and_sizes_match_the_files_it_points_at() {
        let rpm = build_test_rpm("silo-test", "1.0", "1", "noarch");
        let files = build(&[input(&rpm, "Packages/silo-test-1.0-1.noarch.rpm")], 42).unwrap();
        let repomd = String::from_utf8(
            files
                .iter()
                .find(|f| f.name == "repomd.xml")
                .unwrap()
                .bytes
                .clone(),
        )
        .unwrap();

        assert!(repomd.contains("<revision>42</revision>"));
        for file in files.iter().filter(|f| f.name != "repomd.xml") {
            assert!(
                repomd.contains(&format!("repodata/{}", file.name)),
                "repomd does not reference {}",
                file.name
            );
            assert!(repomd.contains(&hex_sha256(&file.bytes)));
            assert!(repomd.contains(&format!("<size>{}</size>", file.bytes.len())));
            let open_size = inflate(&file.bytes).len();
            assert!(repomd.contains(&format!("<open-size>{open_size}</open-size>")));
        }
    }

    #[test]
    fn primary_carries_the_identity_dnf_resolves_against() {
        let rpm = build_test_rpm("silo-test", "1.2.3", "4", "x86_64");
        let href = "Packages/silo-test-1.2.3-4.x86_64.rpm";
        let (_, files) = generate(&[input(&rpm, href)]);
        let primary = &files
            .iter()
            .find(|(name, _)| name.contains("primary"))
            .unwrap()
            .1;

        assert!(primary.contains("packages=\"1\""));
        assert!(primary.contains("<name>silo-test</name>"));
        assert!(primary.contains("<arch>x86_64</arch>"));
        assert!(primary.contains("<version epoch=\"0\" ver=\"1.2.3\" rel=\"4\"/>"));
        assert!(primary.contains(&format!("<location href=\"{href}\"/>")));
        assert!(primary.contains(&format!(
            "<checksum type=\"sha256\" pkgid=\"YES\">{}</checksum>",
            hex_sha256(&rpm)
        )));
        assert!(primary.contains(&format!("package=\"{}\"", rpm.len())));
        assert!(primary.contains("<rpm:license>MIT</rpm:license>"));
        // The header range is what lets dnf fetch one package's header
        // with a ranged GET instead of the whole file.
        assert!(primary.contains("<rpm:header-range start="));
        assert!(primary.contains("<rpm:provides>"));
    }

    #[test]
    fn filelists_has_every_file_and_primary_only_the_interesting_ones() {
        // `/usr/share/...` is deliberately not a primary path, so this
        // fixture separates the two file lists.
        let rpm = build_test_rpm("silo-test", "1.0", "1", "noarch");
        let (_, files) = generate(&[input(&rpm, "Packages/silo-test-1.0-1.noarch.rpm")]);
        let primary = &files.iter().find(|(n, _)| n.contains("primary")).unwrap().1;
        let filelists = &files
            .iter()
            .find(|(n, _)| n.contains("filelists"))
            .unwrap()
            .1;

        assert!(filelists.contains("/usr/share/silo-test/hello.txt"));
        assert!(
            !primary.contains("/usr/share/silo-test/hello.txt"),
            "primary.xml must stay small; non-bin, non-/etc paths belong in filelists"
        );
        assert!(filelists.contains(&format!("pkgid=\"{}\"", hex_sha256(&rpm))));
    }

    #[test]
    fn other_is_emitted_even_without_changelogs() {
        let rpm = build_test_rpm("silo-test", "1.0", "1", "noarch");
        let (_, files) = generate(&[input(&rpm, "Packages/silo-test-1.0-1.noarch.rpm")]);
        let other = &files.iter().find(|(n, _)| n.contains("other")).unwrap().1;
        assert!(other.contains("<otherdata"));
        assert!(other.contains("packages=\"1\""));
        assert!(other.contains("name=\"silo-test\""));
    }

    #[test]
    fn an_empty_repo_still_produces_valid_metadata() {
        let (repomd, files) = generate(&[]);
        assert!(repomd.contains("type=\"primary\""));
        for (_, xml) in &files {
            assert!(xml.contains("packages=\"0\""));
        }
    }

    #[test]
    fn every_package_appears_exactly_once() {
        let a = build_test_rpm("alpha", "1.0", "1", "noarch");
        let b = build_test_rpm("beta", "2.0", "1", "x86_64");
        let (_, files) = generate(&[
            input(&a, "Packages/alpha-1.0-1.noarch.rpm"),
            input(&b, "Packages/beta-2.0-1.x86_64.rpm"),
        ]);
        for (name, xml) in &files {
            assert!(xml.contains("packages=\"2\""), "{name}");
            assert_eq!(xml.matches("<package ").count(), 2, "{name}");
            assert!(xml.contains("alpha"), "{name}");
            assert!(xml.contains("beta"), "{name}");
        }
    }

    #[test]
    fn generation_is_deterministic_for_the_same_input() {
        let rpm = build_test_rpm("silo-test", "1.0", "1", "noarch");
        let first = build(&[input(&rpm, "Packages/x.rpm")], 7).unwrap();
        let second = build(&[input(&rpm, "Packages/x.rpm")], 7).unwrap();
        assert_eq!(first, second, "regeneration must not churn object names");
    }

    #[test]
    fn a_truncated_package_is_rejected_at_extraction() {
        let rpm = build_test_rpm("silo-test", "1.0", "1", "noarch");
        let err = extract(&rpm[..64]).unwrap_err();
        assert!(err.to_string().contains("rpm headers"), "got: {err}");
    }

    #[test]
    fn an_entry_survives_a_round_trip_through_json() {
        // This is how it is actually stored: serialized into the package
        // row's metadata at publish, read back on every regeneration.
        let rpm = build_test_rpm("silo-test", "1.2.3", "4", "x86_64");
        let entry = extract(&rpm).unwrap();
        let json = serde_json::to_value(&entry).unwrap();
        let restored: RepodataEntry = serde_json::from_value(json).unwrap();
        assert_eq!(restored, entry);

        // ...and rendering from the restored copy is byte-identical.
        let location = RepodataLocation {
            href: "Packages/silo-test-1.2.3-4.x86_64.rpm".into(),
            sha256: hex_sha256(&rpm),
            size: rpm.len() as u64,
        };
        assert_eq!(
            build(&[(restored, location.clone())], 7).unwrap(),
            build(&[(entry, location)], 7).unwrap()
        );
    }

    #[test]
    fn the_header_range_points_at_the_actual_header() {
        // dnf issues a ranged GET for exactly these bytes to read one
        // package's header without downloading the package. If the range
        // is wrong, what comes back is not parseable as a header.
        let rpm = build_test_rpm("silo-test", "1.0", "1", "noarch");
        let entry = extract(&rpm).unwrap();

        assert!(entry.header_start < entry.header_end);
        assert!(entry.header_end as usize <= rpm.len());
        // The RPM header section starts with the header magic.
        assert_eq!(
            &rpm[entry.header_start as usize..entry.header_start as usize + 3],
            &[0x8e, 0xad, 0xe8],
            "header_start does not point at an rpm header magic"
        );
    }

    #[test]
    fn evr_strings_split_into_the_attributes_the_schema_wants() {
        assert_eq!(
            split_evr("2.3-4"),
            (Some("0".into()), Some("2.3".into()), Some("4".into()))
        );
        assert_eq!(
            split_evr("1:2.3-4"),
            (Some("1".into()), Some("2.3".into()), Some("4".into()))
        );
        // No release, e.g. `>= 2.17`.
        assert_eq!(
            split_evr("2.17"),
            (Some("0".into()), Some("2.17".into()), None)
        );
        assert_eq!(split_evr(""), (None, None, None));
        // A colon that isn't an epoch separator must not eat the version.
        assert_eq!(
            split_evr("v:1.0"),
            (Some("0".into()), Some("v:1.0".into()), None)
        );
    }

    #[test]
    fn comparison_flags_use_the_repodata_spelling() {
        assert_eq!(flag_name(DependencyFlags::EQUAL), "EQ");
        assert_eq!(flag_name(DependencyFlags::LESS), "LT");
        assert_eq!(flag_name(DependencyFlags::GREATER), "GT");
        assert_eq!(flag_name(DependencyFlags::LE), "LE");
        assert_eq!(flag_name(DependencyFlags::GE), "GE");
        assert_eq!(flag_name(DependencyFlags::ANY), "");
    }

    #[test]
    fn rpmlib_requires_are_dropped_and_duplicates_collapsed() {
        let deps = vec![
            rpm::Dependency::rpmlib("CompressedFileNames", "3.0.4-1"),
            rpm::Dependency::any("bash"),
            rpm::Dependency::any("bash"),
            rpm::Dependency::greater_eq("glibc", "2.17"),
        ];
        let kept = dedupe_requires(deps);
        assert_eq!(kept.len(), 2);
        assert!(kept.iter().all(|d| !d.name.starts_with("rpmlib(")));
        assert_eq!(kept[0].name, "bash");
        assert_eq!(kept[1].name, "glibc");
    }

    #[test]
    fn primary_file_list_is_limited_to_paths_a_dependency_can_name() {
        assert!(is_primary_file("/etc/silo/config.yaml"));
        assert!(is_primary_file("/usr/bin/silo"));
        assert!(is_primary_file("/usr/sbin/silod"));
        assert!(is_primary_file("/usr/lib/sendmail"));
        assert!(!is_primary_file("/usr/share/doc/silo/README"));
        assert!(!is_primary_file("/var/lib/silo"));
    }

    #[test]
    fn header_text_cannot_break_the_document() {
        assert_eq!(escape("a & b < c"), "a &amp; b &lt; c");
        assert_eq!(escape("\"quoted\""), "&quot;quoted&quot;");
        // Control characters have no XML 1.0 escape and are dropped
        // rather than emitted raw, which would make the file unparseable.
        assert_eq!(escape("a\u{0}b\u{8}c"), "abc");
        assert_eq!(escape("keep\nnewlines\t"), "keep\nnewlines\t");
    }

    #[test]
    fn a_package_with_hostile_metadata_still_yields_parseable_xml() {
        let rpm = rpm::PackageBuilder::new(
            "evil",
            "1.0",
            "MIT & \"friends\"",
            "noarch",
            "</metadata><injected/>",
        )
        .release("1")
        .build()
        .unwrap();
        let mut bytes = Vec::new();
        rpm.write(&mut bytes).unwrap();

        let (_, files) = generate(&[input(&bytes, "Packages/evil-1.0-1.noarch.rpm")]);
        let primary = &files.iter().find(|(n, _)| n.contains("primary")).unwrap().1;
        assert!(!primary.contains("<injected/>"));
        assert!(primary.contains("&lt;/metadata&gt;&lt;injected/&gt;"));
        assert_eq!(primary.matches("</metadata>").count(), 1);
    }
}
