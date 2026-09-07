//! Arch Linux `pacman` packages: parsing, layout, and repo-database
//! generation.
//!
//! Unlike apk, a pacman package (`.pkg.tar.zst`/`.pkg.tar.xz`/`.pkg.tar.gz`)
//! is a **single** compressed tar archive: `.PKGINFO` sits at the archive
//! root next to the installed files, whichever codec was used. Silo accepts
//! all three because `makepkg` has shipped different defaults across
//! versions — zstd today, xz and gzip on older toolchains still in use.
//!
//! The repo database `repo-add` builds (`{name}.db.tar.gz`) is a second,
//! separate tar+gzip archive: one directory per package, holding a `desc`
//! file of `%FIELD%\nvalue\n` blocks. Unlike APKINDEX, pacman verifies the
//! database against a **detached sibling signature** (`....db.tar.gz.sig`)
//! rather than a signature prepended into the same object, so
//! `build_index` here returns two [`IndexObject`]s when a signer is
//! configured instead of apk's one.
//!
//! The object names this module writes are fixed (`db.tar.gz` /
//! `db.tar.gz.sig`) regardless of what `[section]` name a user picks in
//! their `pacman.conf` — pacman requests `$section.db`, and the section
//! name is a client-side choice silo has no way to know in advance. The
//! HTTP layer resolves any `*.db`/`*.db.tar.{gz,zst,xz}` (and its `.sig`)
//! request to these fixed objects; see `silo-server`'s pacman route.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;

use alpm_types::{PackageRelease, PackageVersion};
use serde_json::json;

use crate::apk::{gzip, parse_pkginfo, tar_bytes};
use crate::upstream::{
    UpstreamError, UpstreamFetchOptions, UpstreamHttp, UpstreamIndex, UpstreamPackage,
};
use crate::{
    Format, IndexContext, IndexObject, PackageFormat, PackageRecord, ParseError, ParsedPackage,
};

pub struct PacmanFormat;

/// The architecture pacman packages declare when they work on all of them
/// — pacman's `noarch`, spelled `any`.
pub const ANY: &str = "any";

/// The fixed object names the repo database and its signature are stored
/// and served under, independent of the `pacman.conf` section name a
/// client happens to use.
pub const DB_OBJECT: &str = "db.tar.gz";
pub const DB_SIG_OBJECT: &str = "db.tar.gz.sig";

impl Format for PacmanFormat {
    fn format(&self) -> PackageFormat {
        PackageFormat::Pacman
    }

    fn parse(&self, bytes: &[u8]) -> Result<ParsedPackage, ParseError> {
        let compression = Compression::detect(bytes)?;
        let inflated = compression.decompress(bytes)?;

        let mut archive = tar::Archive::new(inflated.as_slice());
        let mut pkginfo = None;
        for entry in archive
            .entries()
            .map_err(|e| ParseError::invalid(format!("corrupt pacman package tar: {e}")))?
        {
            let mut entry = entry
                .map_err(|e| ParseError::invalid(format!("corrupt pacman package tar: {e}")))?;
            let path = entry
                .path()
                .map_err(|e| ParseError::invalid(format!("corrupt tar entry: {e}")))?
                .to_string_lossy()
                .into_owned();
            if path == ".PKGINFO" || path == "./.PKGINFO" {
                pkginfo = Some(crate::read_text_capped(&mut entry, ".PKGINFO")?);
                break;
            }
        }
        let text =
            pkginfo.ok_or_else(|| ParseError::invalid("pacman package contains no .PKGINFO"))?;

        let fields = parse_pkginfo(&text);
        let get = |k: &str| fields.get(k).and_then(|v| v.first()).cloned();
        let list = |k: &str| fields.get(k).cloned().unwrap_or_default();

        let name =
            get("pkgname").ok_or_else(|| ParseError::invalid(".PKGINFO is missing pkgname"))?;
        let pkgver =
            get("pkgver").ok_or_else(|| ParseError::invalid(".PKGINFO is missing pkgver"))?;
        // makepkg always writes this, even for `arch=any` packages (the
        // field's value is literally `any`) — a well-formed package never
        // hits the fallback apk's own `arch` handling uses, so a missing
        // one is treated the same as a missing pkgname/pkgver rather than
        // silently guessed at.
        let arch = get("arch").ok_or_else(|| ParseError::invalid(".PKGINFO is missing arch"))?;
        let (epoch, version, release) = split_pkgver(&pkgver)?;

        let filename = format!("{name}-{pkgver}-{arch}.pkg.{}", compression.extension());

        let metadata = json!({
            "pkgbase": get("pkgbase"),
            "description": get("pkgdesc"),
            "url": get("url"),
            // `license` legitimately repeats, the same as `depend` — a
            // multi-licensed package writes one `license = ` line per
            // license, and `repo-add` renders %LICENSE% as one value per
            // line too, not a single joined string.
            "license": list("license"),
            "builddate": get("builddate").and_then(|s| s.parse::<i64>().ok()),
            "packager": get("packager"),
            "isize": get("size").and_then(|s| s.parse::<u64>().ok()),
            "depends": list("depend"),
            "optdepends": list("optdepend"),
            "makedepends": list("makedepend"),
            "checkdepends": list("checkdepend"),
            "provides": list("provides"),
            "conflicts": list("conflict"),
            "replaces": list("replace"),
            "groups": list("group"),
        });

        Ok(ParsedPackage {
            format: PackageFormat::Pacman,
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
        format!("{}/{}", arch_prefix(repo, channel, &pkg.arch), pkg.filename)
    }

    /// pacman fetches one repo database per architecture (whatever
    /// `pacman.conf`'s `Server = .../$arch` resolves `$arch` to), so a
    /// publish only invalidates its own arch — same reasoning as apk.
    fn index_group(&self, pkg: &ParsedPackage) -> String {
        pkg.arch.clone()
    }

    /// A `pkg.tar.zst` marked `arch = any` still has to appear in every
    /// architecture's database, because pacman never asks for an `any`
    /// tree of its own accord any more than apk asks for `noarch`.
    fn shared_groups(&self, group: &str) -> Vec<String> {
        if group == ANY {
            Vec::new()
        } else {
            vec![ANY.to_string()]
        }
    }

    fn is_shared_group(&self, group: &str) -> bool {
        group == ANY
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
            // Unlike rpm/deb/npm — whose real-world tooling and wire
            // formats are built to carry several versions of the same
            // package name in one index (that's how `dnf downgrade` and
            // `apt-get install pkg=version` work) — a pacman sync database
            // may hold at most *one* entry per name. `ctx.records` can
            // (and normally will, once more than one version has ever been
            // published) contain every version still on record for this
            // repo/channel/arch; libalpm's `sync_db_read` throws "database
            // is inconsistent: version mismatch" the instant it meets a
            // second entry for a name it already loaded with a different
            // version, so only the newest one per name is kept here.
            //
            // Older versions stay untouched in storage and in Postgres —
            // this only changes what a regenerated index *lists* — so
            // deleting the current newest version and regenerating brings
            // the next-newest back into the index for free.
            let mut latest: HashMap<&str, &PackageRecord> = HashMap::new();
            for record in ctx.records {
                latest
                    .entry(record.name.as_str())
                    .and_modify(|cur| {
                        if is_newer(record, cur) {
                            *cur = record;
                        }
                    })
                    .or_insert(record);
            }

            let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
            let mut sorted: Vec<&PackageRecord> = latest.into_values().collect();
            sorted.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
            for record in sorted {
                let dir = format!("{}-{}", record.name, full_version(record));
                entries.push((format!("{dir}/desc"), render_desc(record).into_bytes()));
            }
            let entry_refs: Vec<(&str, &[u8])> = entries
                .iter()
                .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
                .collect();
            let db = gzip(tar_bytes(&entry_refs)?)?;

            let mut objects = vec![IndexObject {
                name: DB_OBJECT.to_string(),
                bytes: db.clone(),
                content_type: "application/gzip",
            }];

            if let Some(signer) = ctx.signer {
                // pacman verifies the database with a *detached* signature
                // served alongside it, not one embedded in the object
                // itself — the opposite convention from apk's prepended
                // gzip member.
                let signature = signer.sign(&db)?;
                objects.push(IndexObject {
                    name: DB_SIG_OBJECT.to_string(),
                    bytes: signature,
                    content_type: "application/octet-stream",
                });
            }

            Ok(objects)
        })
    }
}

pub fn arch_prefix(repo: &str, channel: &str, arch: &str) -> String {
    format!("{repo}/{channel}/pacman/{arch}")
}

/// Whether `record` is a newer package identity than `current` — epoch
/// first (an unconditional tie-breaker, same as real `vercmp`), then
/// `version-release` compared with [`version_cmp`].
fn is_newer(record: &PackageRecord, current: &PackageRecord) -> bool {
    match record.epoch.cmp(&current.epoch) {
        std::cmp::Ordering::Equal => {
            let record_ver = format!("{}-{}", record.version, record.release);
            let current_ver = format!("{}-{}", current.version, current.release);
            version_cmp(&record_ver, &current_ver) == std::cmp::Ordering::Greater
        }
        other => other == std::cmp::Ordering::Greater,
    }
}

/// The version string `repo-add` embeds in a database entry's directory
/// name and `%VERSION%` field: `[epoch:]version-release`.
fn full_version(record: &PackageRecord) -> String {
    if record.epoch == 0 {
        format!("{}-{}", record.version, record.release)
    } else {
        format!("{}:{}-{}", record.epoch, record.version, record.release)
    }
}

/// Splits a `.PKGINFO` `pkgver` field (`[epoch:]version-release`, the same
/// shape `makepkg` writes and `repo-add` expects back) into its parts.
fn split_pkgver(pkgver: &str) -> Result<(u32, String, String), ParseError> {
    let (epoch, rest) = match pkgver.split_once(':') {
        Some((e, rest)) => (
            e.parse::<u32>()
                .map_err(|_| ParseError::invalid(format!("invalid epoch in pkgver `{pkgver}`")))?,
            rest,
        ),
        None => (0, pkgver),
    };
    let (version, release) = rest
        .rsplit_once('-')
        .ok_or_else(|| ParseError::invalid(format!("pkgver `{pkgver}` is missing a pkgrel")))?;
    Ok((epoch, version.to_string(), release.to_string()))
}

/// Renders one package's `desc` file: `%FIELD%\nvalue\n\n` blocks, fields
/// omitted when empty, in `repo-add`'s canonical order.
///
/// No `%MD5SUM%`: current `repo-add` doesn't emit it either (verified
/// against a real `repo-add` run), `%SHA256SUM%` alone is what pacman
/// actually checks the download against.
fn render_desc(record: &PackageRecord) -> String {
    let mut out = String::new();
    let mut field = |key: &str, value: Option<String>| {
        if let Some(value) = value.filter(|v| !v.is_empty()) {
            out.push_str(&format!("%{key}%\n{value}\n\n"));
        }
    };

    field("FILENAME", Some(record.filename.clone()));
    field("NAME", Some(record.name.clone()));
    field(
        "BASE",
        json_field(&record.metadata, "pkgbase").or_else(|| Some(record.name.clone())),
    );
    field("VERSION", Some(full_version(record)));
    field("DESC", json_field(&record.metadata, "description"));
    field("CSIZE", Some(record.size_bytes.to_string()));
    field("ISIZE", json_field(&record.metadata, "isize"));
    field("SHA256SUM", Some(record.sha256.clone()));
    field("URL", json_field(&record.metadata, "url"));

    // `license` renders like `depends` below — one value per line, not a
    // single joined string — since a multi-licensed package has more than
    // one `license = ` line in its `.PKGINFO` to begin with.
    push_list_field(&mut out, &record.metadata, "LICENSE", "license");

    let mut field = |key: &str, value: Option<String>| {
        if let Some(value) = value.filter(|v| !v.is_empty()) {
            out.push_str(&format!("%{key}%\n{value}\n\n"));
        }
    };
    field("ARCH", Some(record.arch.clone()));
    field("BUILDDATE", json_field(&record.metadata, "builddate"));
    field("PACKAGER", json_field(&record.metadata, "packager"));

    for (key, meta_key) in [
        ("DEPENDS", "depends"),
        ("MAKEDEPENDS", "makedepends"),
        ("CHECKDEPENDS", "checkdepends"),
        ("OPTDEPENDS", "optdepends"),
        ("PROVIDES", "provides"),
        ("CONFLICTS", "conflicts"),
        ("REPLACES", "replaces"),
        ("GROUPS", "groups"),
    ] {
        push_list_field(&mut out, &record.metadata, key, meta_key);
    }

    out
}

/// Appends a multi-value field (`%KEY%` followed by one value per line) if
/// the metadata array is non-empty; a no-op otherwise.
fn push_list_field(out: &mut String, metadata: &serde_json::Value, key: &str, meta_key: &str) {
    let values: Vec<String> = metadata
        .get(meta_key)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if !values.is_empty() {
        out.push_str(&format!("%{key}%\n{}\n\n", values.join("\n")));
    }
}

fn json_field(metadata: &serde_json::Value, field: &str) -> Option<String> {
    match metadata.get(field)? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Null => None,
        other => Some(other.to_string()),
    }
}

enum Compression {
    Zstd,
    Xz,
    Gzip,
}

impl Compression {
    fn detect(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
            Ok(Compression::Zstd)
        } else if bytes.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
            Ok(Compression::Xz)
        } else if bytes.starts_with(&[0x1F, 0x8B]) {
            Ok(Compression::Gzip)
        } else {
            Err(ParseError::invalid(
                "not a recognized pacman package compression (expected zstd, xz, or gzip)",
            ))
        }
    }

    fn extension(&self) -> &'static str {
        match self {
            Compression::Zstd => "tar.zst",
            Compression::Xz => "tar.xz",
            Compression::Gzip => "tar.gz",
        }
    }

    /// Inflates the whole archive, bounded by `MAX_INFLATED_BYTES`.
    ///
    /// The bound matters most here: of the three formats silo accepts,
    /// pacman's are the ones compressed with xz and zstd, which reach the
    /// highest ratios and so make the cheapest decompression bombs.
    fn decompress(&self, bytes: &[u8]) -> Result<Vec<u8>, ParseError> {
        match self {
            Compression::Zstd => {
                let decoder = zstd::stream::read::Decoder::new(bytes)
                    .map_err(|e| ParseError::invalid(format!("corrupt zstd package: {e}")))?;
                crate::inflate_capped(decoder, crate::MAX_INFLATED_BYTES, "zstd package")
            }
            Compression::Xz => crate::inflate_capped(
                liblzma::read::XzDecoder::new(bytes),
                crate::MAX_INFLATED_BYTES,
                "xz package",
            ),
            Compression::Gzip => crate::inflate_capped(
                flate2::bufread::GzDecoder::new(bytes),
                crate::MAX_INFLATED_BYTES,
                "gzip package",
            ),
        }
    }
}

/// Fetches and parses an upstream Arch repository's database, one per
/// configured architecture — same reasoning as apk's [`crate::apk::ApkUpstream`]:
/// pacman has no arch-agnostic root index either.
///
/// Real pacman repositories name their database after the repo section a
/// client configures (`core.db.tar.gz`, `extra.db.tar.gz`, ...), which
/// this module has no independent way to know — so `opts.suite`
/// (otherwise deb-only) doubles as the database's base name here,
/// defaulting to `"repo"` when unset.
pub struct PacmanUpstream;

impl UpstreamIndex for PacmanUpstream {
    fn format(&self) -> PackageFormat {
        PackageFormat::Pacman
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
                    "a pacman upstream needs at least one --arch",
                ));
            }
            let db_name = opts.suite.as_deref().unwrap_or("repo");
            // One database per architecture, fetched concurrently — same
            // reasoning as apk's fetch_index.
            let fetched =
                futures::future::try_join_all(opts.arches.iter().map(|arch| async move {
                    let path = format!("{arch}/{db_name}.db.tar.gz");
                    let bytes = http.get(&path).await?;
                    Ok::<_, UpstreamError>((arch, bytes))
                }))
                .await?;
            let mut out = Vec::new();
            for (arch, bytes) in fetched {
                let base = format!("{}/{arch}", http.base_url().trim_end_matches('/'));
                out.extend(parse_pacman_db_tar_gz(&bytes, &base)?);
            }
            Ok(out)
        })
    }
}

/// Parses a fetched `{db}.tar.gz`: one directory per package, each holding
/// a `desc` file of `%FIELD%\nvalue\n\n` blocks — the exact shape
/// [`Format::build_index`] renders here, just read instead of written.
pub fn parse_pacman_db_tar_gz(
    bytes: &[u8],
    base_url: &str,
) -> Result<Vec<UpstreamPackage>, UpstreamError> {
    let decoder = flate2::bufread::GzDecoder::new(bytes);
    let inflated = crate::inflate_capped(decoder, crate::MAX_INFLATED_BYTES, "pacman db")
        .map_err(|e| UpstreamError::parse(e.to_string()))?;
    let mut archive = tar::Archive::new(inflated.as_slice());
    let entries = archive
        .entries()
        .map_err(|e| UpstreamError::parse(format!("corrupt pacman db tar: {e}")))?;

    let mut out = Vec::new();
    for entry in entries {
        let mut entry =
            entry.map_err(|e| UpstreamError::parse(format!("corrupt tar entry: {e}")))?;
        let path = entry
            .path()
            .map_err(|e| UpstreamError::parse(e.to_string()))?
            .to_string_lossy()
            .into_owned();
        if !path.ends_with("/desc") {
            continue;
        }
        let text = crate::read_text_capped(&mut entry, "desc")
            .map_err(|e| UpstreamError::parse(e.to_string()))?;
        if let Some(pkg) = parse_desc(&text, base_url) {
            out.push(pkg);
        }
    }
    Ok(out)
}

/// Parses one package's `desc` file into an [`UpstreamPackage`], or `None`
/// if it's missing the fields every real `repo-add`-generated entry has.
/// `%DESC%`-file key -> the metadata field name [`render_desc`] reads it
/// back from, and whether it's a multi-value (list) field. Keeping a
/// synced package's full metadata (not just name/version) means a
/// synthetic index entry looks the same to a client as a locally
/// published one, before it's ever actually been fetched.
const DESC_METADATA_FIELDS: &[(&str, &str, bool)] = &[
    ("BASE", "pkgbase", false),
    ("DESC", "description", false),
    ("URL", "url", false),
    ("LICENSE", "license", true),
    ("ISIZE", "isize", false),
    ("BUILDDATE", "builddate", false),
    ("PACKAGER", "packager", false),
    ("DEPENDS", "depends", true),
    ("MAKEDEPENDS", "makedepends", true),
    ("CHECKDEPENDS", "checkdepends", true),
    ("OPTDEPENDS", "optdepends", true),
    ("PROVIDES", "provides", true),
    ("CONFLICTS", "conflicts", true),
    ("REPLACES", "replaces", true),
    ("GROUPS", "groups", true),
];

fn parse_desc(text: &str, base_url: &str) -> Option<UpstreamPackage> {
    let fields = parse_desc_fields(text);
    let get1 = |k: &str| fields.get(k).and_then(|v| v.first()).cloned();

    let name = get1("NAME")?;
    let filename = get1("FILENAME")?;
    let full_version = get1("VERSION")?;
    let (epoch, version, release) = split_pkgver(&full_version).ok()?;
    let arch = get1("ARCH")?;

    let mut metadata = serde_json::Map::new();
    for (desc_key, meta_key, is_list) in DESC_METADATA_FIELDS {
        let Some(values) = fields.get(*desc_key) else {
            continue;
        };
        let value = if *is_list {
            json!(values)
        } else {
            json!(values.first())
        };
        metadata.insert((*meta_key).to_string(), value);
    }

    Some(UpstreamPackage {
        name,
        epoch,
        version,
        release,
        arch,
        download_url: format!("{}/{filename}", base_url.trim_end_matches('/')),
        filename,
        size_bytes: get1("CSIZE").and_then(|s| s.parse().ok()),
        sha256: get1("SHA256SUM"),
        metadata: serde_json::Value::Object(metadata),
    })
}

/// `%FIELD%\nvalue\n\n` blocks, one blank-line-separated block per field.
/// A multi-value field (`%LICENSE%`, `%DEPENDS%`, ...) has one value per
/// line within its block, mirroring [`push_list_field`]'s write side.
fn parse_desc_fields(text: &str) -> HashMap<String, Vec<String>> {
    let mut fields = HashMap::new();
    for block in text.split("\n\n") {
        let block = block.trim();
        if block.is_empty() {
            continue;
        }
        let mut lines = block.lines();
        let Some(key_line) = lines.next() else {
            continue;
        };
        let Some(key) = key_line.strip_prefix('%').and_then(|s| s.strip_suffix('%')) else {
            continue;
        };
        fields.insert(key.to_string(), lines.map(str::to_string).collect());
    }
    fields
}

/// Compares two pacman `pkgver-pkgrel` strings (already epoch-stripped by
/// the caller, which compares epoch separately — pacman's own vercmp
/// treats a higher epoch as unconditionally newer regardless of the rest).
///
/// Tokenizes with the upstream [`alpm-types`](alpm_types) crate's
/// [`PackageVersion::segments`], which implements libalpm's actual
/// segment/sub-segment splitting (see alpm-pkgver(7)) — including corners a
/// hand-rolled tokenizer missed, like a `.`-delimited trailing segment
/// (`1.0` vs `1.0.a`) ranking opposite to a delimiter-free one (`1.0` vs
/// `1.0alpha`), and distinguishing `1..0` (two leading delimiters) from
/// `1.0`. The final comparison over those segments is our own rather than
/// the crate's [`Ord`] impl: that impl parses each numeric segment as a
/// fixed-width `usize` and unwraps the result, which panics instead of
/// comparing on a segment longer than `usize::MAX` — reachable from an
/// untrusted uploaded package's `pkgver`, so it can't be relied on here.
/// [`compare_numeric_segments`] does the same magnitude comparison without
/// ever parsing to a fixed-width integer.
pub fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let (a_ver, a_rel) = a.rsplit_once('-').unwrap_or((a, "0"));
    let (b_ver, b_rel) = b.rsplit_once('-').unwrap_or((b, "0"));

    match (
        PackageVersion::new(a_ver.to_string()),
        PackageVersion::new(b_ver.to_string()),
    ) {
        (Ok(a_ver), Ok(b_ver)) => {
            compare_segments(&a_ver, &b_ver).then_with(|| compare_release(a_rel, b_rel))
        }
        // A `pkgver` real `makepkg` ever produces always parses — this
        // only triggers on something already malformed (e.g. a stray `:`
        // or `/`, which `PackageVersion`'s charset forbids), where falling
        // back to a plain string order is as good as any other total order.
        _ => a.cmp(b),
    }
}

/// Compares two [`PackageVersion`]s segment by segment, mirroring the
/// [`alpm_types`] crate's own `Ord for PackageVersion` (segments carry
/// their leading delimiter count, a longer side wins unless its extra
/// segment is a delimiter-free alphabetic suffix, matching types beat
/// mismatched ones), but comparing same-position numeric segments with
/// [`compare_numeric_segments`] instead of the crate's panic-on-overflow
/// `usize` parse. See [`version_cmp`] for why that substitution matters.
fn compare_segments(a: &PackageVersion, b: &PackageVersion) -> std::cmp::Ordering {
    use alpm_types::VersionSegment;
    use std::cmp::Ordering;

    if a.inner() == b.inner() {
        return Ordering::Equal;
    }

    let mut a_segments = a.segments();
    let mut b_segments = b.segments();

    loop {
        let (a_seg, b_seg) = match (a_segments.next(), b_segments.next()) {
            (Some(a_seg), Some(b_seg)) => (a_seg, b_seg),
            (None, None) => return Ordering::Equal,
            (Some(seg), None) => return trailing_segment_beats_end(&seg),
            (None, Some(seg)) => return trailing_segment_beats_end(&seg).reverse(),
        };

        match (a_seg.is_empty(), b_seg.is_empty()) {
            // Both ended in a run of trailing delimiters (`1.0.` vs
            // `1.0...`) — the delimiter count itself doesn't matter here.
            (true, true) => return Ordering::Equal,
            (true, false) => return trailing_delimiter_vs_segment(&b_seg).reverse(),
            (false, true) => return trailing_delimiter_vs_segment(&a_seg),
            (false, false) => {}
        }

        let (a_text, b_text) = match (&a_seg, &b_seg) {
            (
                VersionSegment::Segment {
                    delimiter_count: a_count,
                    text: a_text,
                },
                VersionSegment::Segment {
                    delimiter_count: b_count,
                    text: b_text,
                },
            ) => {
                if a_count != b_count {
                    return a_count.cmp(b_count);
                }
                (*a_text, *b_text)
            }
            (VersionSegment::Segment { .. }, VersionSegment::SubSegment { .. }) => {
                return Ordering::Greater;
            }
            (VersionSegment::SubSegment { .. }, VersionSegment::Segment { .. }) => {
                return Ordering::Less;
            }
            (
                VersionSegment::SubSegment { text: a_text },
                VersionSegment::SubSegment { text: b_text },
            ) => (*a_text, *b_text),
        };

        let a_numeric = is_ascii_numeric(a_text);
        let b_numeric = is_ascii_numeric(b_text);
        let cmp = if a_numeric && !b_numeric {
            Ordering::Greater
        } else if !a_numeric && b_numeric {
            Ordering::Less
        } else if a_numeric {
            compare_numeric_segments(a_text, b_text)
        } else {
            a_text.cmp(b_text)
        };
        if cmp != Ordering::Equal {
            return cmp;
        }
    }
}

/// One side ran out of segments while the other still has `seg` — the
/// longer side wins, unless `seg` is a delimiter-free alphabetic suffix (a
/// pre-release marker like `1.0alpha`'s `alpha`), in which case the shorter
/// side wins instead. Returns the ordering of the *longer* side relative to
/// the shorter one; callers on the shorter side `.reverse()` it.
fn trailing_segment_beats_end(seg: &alpm_types::VersionSegment) -> std::cmp::Ordering {
    use alpm_types::VersionSegment;
    use std::cmp::Ordering;

    let text = match seg {
        VersionSegment::Segment { .. } => return Ordering::Greater,
        VersionSegment::SubSegment { text } => text,
    };
    if !text.is_empty() && text.chars().all(char::is_alphabetic) {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

/// One side ended in a trailing delimiter (`seg` is the empty segment that
/// encodes it, e.g. `1.0.`'s final segment) while the other still has a
/// real `other` segment at the same position. A trailing delimiter beats an
/// alphabetic pre-release suffix but loses to anything else. Returns the
/// ordering of the trailing-delimiter side relative to `other`.
fn trailing_delimiter_vs_segment(other: &alpm_types::VersionSegment) -> std::cmp::Ordering {
    use std::cmp::Ordering;

    if other.chars().all(char::is_alphabetic) {
        Ordering::Greater
    } else {
        Ordering::Less
    }
}

fn is_ascii_numeric(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

/// Compares two all-ASCII-digit strings by magnitude without ever parsing
/// them to a fixed-width integer: strip leading zeros, then the longer
/// remaining digit string is larger (arbitrary length, unlike a `u64`/
/// `usize` parse), and equal-length digit strings compare lexically, which
/// is magnitude order for same-length unsigned decimal digits.
fn compare_numeric_segments(a: &str, b: &str) -> std::cmp::Ordering {
    let a = a.trim_start_matches('0');
    let b = b.trim_start_matches('0');
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// Compares two `pkgrel` strings — conventionally a bare integer, but
/// `makepkg` also permits a `major.minor` form, which `PackageRelease`
/// compares as two separate integers rather than as an opaque string, so
/// `1.2` sorts below `1.10` (minor `2 < 10`) rather than the reverse a
/// decimal or lexical reading would give.
fn compare_release(a: &str, b: &str) -> std::cmp::Ordering {
    match (PackageRelease::from_str(a), PackageRelease::from_str(b)) {
        (Ok(a), Ok(b)) => a.cmp(&b),
        _ => a.cmp(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::build_test_pacman;
    use std::io::Read;

    fn record(name: &str, version: &str) -> PackageRecord {
        PackageRecord {
            format: PackageFormat::Pacman,
            name: name.into(),
            epoch: 0,
            version: version.into(),
            release: "1".into(),
            arch: "x86_64".into(),
            filename: format!("{name}-{version}-1-x86_64.pkg.tar.zst"),
            storage_key: format!("r/c/pacman/x86_64/{name}-{version}-1-x86_64.pkg.tar.zst"),
            size_bytes: 1234,
            sha256: "deadbeef".into(),
            metadata: json!({
                "pkgbase": name,
                "description": "a test package",
                "license": ["MIT", "Apache-2.0"],
                "isize": 4096,
                "depends": ["glibc", "zlib"],
                "makedepends": ["cmake"],
                "checkdepends": ["python"],
            }),
            published_at: 0,
        }
    }

    #[test]
    fn splits_pkgver_with_and_without_epoch() {
        assert_eq!(
            split_pkgver("1.2.3-4").unwrap(),
            (0, "1.2.3".to_string(), "4".to_string())
        );
        assert_eq!(
            split_pkgver("2:1.2.3-4").unwrap(),
            (2, "1.2.3".to_string(), "4".to_string())
        );
    }

    #[test]
    fn rejects_pkgver_without_a_pkgrel() {
        assert!(split_pkgver("1.2.3").is_err());
    }

    #[test]
    fn parses_a_generated_zstd_package() {
        let bytes = build_test_pacman("hello", "1.0-1", "x86_64", "zst");
        let parsed = PacmanFormat.parse(&bytes).expect("parse pacman package");
        assert_eq!(parsed.name, "hello");
        assert_eq!(parsed.version, "1.0");
        assert_eq!(parsed.release, "1");
        assert_eq!(parsed.arch, "x86_64");
        assert_eq!(parsed.format, PackageFormat::Pacman);
        assert_eq!(parsed.filename, "hello-1.0-1-x86_64.pkg.tar.zst");
        assert_eq!(parsed.metadata["makedepends"], json!(["cmake"]));
        assert_eq!(parsed.metadata["checkdepends"], json!(["python"]));
    }

    #[test]
    fn parses_gzip_and_xz_packages_identically_to_zstd() {
        for ext in ["gz", "xz"] {
            let bytes = build_test_pacman("hello", "1.0-1", "x86_64", ext);
            let parsed = PacmanFormat.parse(&bytes).expect("parse pacman package");
            assert_eq!(parsed.name, "hello");
            assert_eq!(parsed.version, "1.0");
            assert!(parsed.filename.ends_with(&format!(".pkg.tar.{ext}")));
        }
    }

    #[test]
    fn epoch_is_extracted_from_pkgver() {
        let bytes = build_test_pacman("hello", "2:1.0-1", "x86_64", "zst");
        let parsed = PacmanFormat.parse(&bytes).unwrap();
        assert_eq!(parsed.epoch, 2);
        assert_eq!(parsed.version, "1.0");
        assert_eq!(parsed.release, "1");
    }

    #[test]
    fn rejects_a_package_without_pkginfo() {
        let tar = tar_bytes(&[("not-pkginfo", b"x".as_slice())]).unwrap();
        let bytes = gzip(tar).unwrap();
        assert!(PacmanFormat.parse(&bytes).is_err());
    }

    #[test]
    fn rejects_unrecognized_compression() {
        assert!(PacmanFormat.parse(b"plain text, not a package").is_err());
    }

    #[test]
    fn rejects_a_package_with_no_arch_field() {
        // Real makepkg output always carries `arch`, even for `arch=any`
        // packages (the value is literally `any`) — a missing field means
        // corrupt or hand-crafted input, not something to guess a default
        // for the same way pkgname/pkgver are never guessed at either.
        let pkginfo = "pkgname = foo\npkgver = 1.0-1\n";
        let tar = tar_bytes(&[(".PKGINFO", pkginfo.as_bytes())]).unwrap();
        let bytes = gzip(tar).unwrap();
        let err = PacmanFormat.parse(&bytes).unwrap_err();
        assert!(err.to_string().contains("arch"));
    }

    #[test]
    fn layout_partitions_by_arch() {
        let pkg = PacmanFormat
            .parse(&build_test_pacman("hello", "1.0-1", "aarch64", "zst"))
            .unwrap();
        assert_eq!(
            PacmanFormat.storage_key("r", "edge", &pkg),
            "r/edge/pacman/aarch64/hello-1.0-1-aarch64.pkg.tar.zst"
        );
        assert_eq!(PacmanFormat.index_group(&pkg), "aarch64");
        assert_eq!(
            PacmanFormat.index_prefix("r", "edge", "aarch64"),
            "r/edge/pacman/aarch64"
        );
    }

    #[test]
    fn desc_renders_required_and_list_fields() {
        let desc = render_desc(&record("foo", "1.0"));
        assert!(desc.contains("%FILENAME%\nfoo-1.0-1-x86_64.pkg.tar.zst\n\n"));
        assert!(desc.contains("%NAME%\nfoo\n\n"));
        assert!(desc.contains("%VERSION%\n1.0-1\n\n"));
        assert!(desc.contains("%SHA256SUM%\ndeadbeef\n\n"));
        assert!(desc.contains("%LICENSE%\nMIT\nApache-2.0\n\n"));
        assert!(desc.contains("%DEPENDS%\nglibc\nzlib\n\n"));
        assert!(desc.contains("%MAKEDEPENDS%\ncmake\n\n"));
        assert!(desc.contains("%CHECKDEPENDS%\npython\n\n"));
        // Empty list fields are omitted entirely rather than emitted empty.
        assert!(!desc.contains("%OPTDEPENDS%"));
        // repo-add no longer emits this field; SHA256SUM alone is checked.
        assert!(!desc.contains("%MD5SUM%"));
    }

    #[tokio::test]
    async fn build_index_produces_a_readable_database() {
        let records = [record("foo", "1.0")];
        let ctx = IndexContext {
            repo: "r",
            channel: "edge",
            group: "x86_64",
            records: &records,
            public_base_url: None,
            signer: None,
        };
        let objects = PacmanFormat.build_index(&ctx).await.unwrap();
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].name, DB_OBJECT);

        let mut inflated = Vec::new();
        flate2::bufread::GzDecoder::new(objects[0].bytes.as_slice())
            .read_to_end(&mut inflated)
            .unwrap();
        let mut archive = tar::Archive::new(inflated.as_slice());
        let names: Vec<String> = archive
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["foo-1.0-1/desc"]);
    }

    #[tokio::test]
    async fn build_index_keeps_only_the_newest_version_of_each_name() {
        // A sync database with two entries for the same name at different
        // versions is exactly what makes libalpm reject the repo with
        // "database is inconsistent: version mismatch" — old versions that
        // are still on record (never deleted, just superseded by a newer
        // publish) must not reach the rendered db.
        let records = [
            record("foo", "1.0"),
            record("foo", "2.0"),
            record("bar", "3.0"),
        ];
        let ctx = IndexContext {
            repo: "r",
            channel: "edge",
            group: "x86_64",
            records: &records,
            public_base_url: None,
            signer: None,
        };
        let objects = PacmanFormat.build_index(&ctx).await.unwrap();

        let mut inflated = Vec::new();
        flate2::bufread::GzDecoder::new(objects[0].bytes.as_slice())
            .read_to_end(&mut inflated)
            .unwrap();
        let mut archive = tar::Archive::new(inflated.as_slice());
        let mut names: Vec<String> = archive
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, vec!["bar-3.0-1/desc", "foo-2.0-1/desc"]);
    }

    #[test]
    fn is_newer_compares_epoch_before_version() {
        let mut low_epoch = record("foo", "9.0");
        low_epoch.epoch = 0;
        let mut high_epoch = record("foo", "1.0");
        high_epoch.epoch = 1;
        assert!(is_newer(&high_epoch, &low_epoch));
        assert!(!is_newer(&low_epoch, &high_epoch));
    }

    struct FakeSigner;
    impl crate::IndexSigner for FakeSigner {
        fn key_name(&self) -> &str {
            "test"
        }
        fn sign(&self, _data: &[u8]) -> anyhow::Result<Vec<u8>> {
            Ok(vec![0xCD; 64])
        }
    }

    #[tokio::test]
    async fn signed_index_adds_a_detached_sibling_signature() {
        let records = [record("foo", "1.0")];
        let signer = FakeSigner;
        let ctx = IndexContext {
            repo: "r",
            channel: "edge",
            group: "x86_64",
            records: &records,
            public_base_url: None,
            signer: Some(&signer),
        };
        let objects = PacmanFormat.build_index(&ctx).await.unwrap();
        assert_eq!(objects.len(), 2, "database + detached signature");
        assert_eq!(objects[0].name, DB_OBJECT);
        assert_eq!(objects[1].name, DB_SIG_OBJECT);
        assert_eq!(objects[1].bytes, vec![0xCD; 64]);
    }

    #[tokio::test]
    async fn parses_an_upstream_db_round_tripped_through_our_own_renderer() {
        let records = [record("foo", "1.0"), record("bar", "2.5")];
        let ctx = IndexContext {
            repo: "r",
            channel: "edge",
            group: "x86_64",
            records: &records,
            public_base_url: None,
            signer: None,
        };
        let objects = PacmanFormat.build_index(&ctx).await.unwrap();
        let db = objects.iter().find(|o| o.name == DB_OBJECT).unwrap();

        let packages = parse_pacman_db_tar_gz(&db.bytes, "https://example.com/x86_64").unwrap();
        assert_eq!(packages.len(), 2);
        let foo = packages.iter().find(|p| p.name == "foo").unwrap();
        assert_eq!(foo.version, "1.0");
        assert_eq!(foo.release, "1");
        assert_eq!(foo.arch, "x86_64");
        assert_eq!(foo.filename, "foo-1.0-1-x86_64.pkg.tar.zst");
        assert_eq!(
            foo.download_url,
            "https://example.com/x86_64/foo-1.0-1-x86_64.pkg.tar.zst"
        );
        assert_eq!(foo.sha256.as_deref(), Some("deadbeef"));
        assert_eq!(foo.metadata["description"], "a test package");
        assert_eq!(foo.metadata["depends"], json!(["glibc", "zlib"]));
        assert_eq!(foo.metadata["license"], json!(["MIT", "Apache-2.0"]));
    }

    #[test]
    fn version_cmp_orders_numerically_not_lexically() {
        use std::cmp::Ordering;
        assert_eq!(version_cmp("1.2-1", "1.10-1"), Ordering::Less);
        assert_eq!(version_cmp("1.0-1", "1.0-2"), Ordering::Less);
        assert_eq!(version_cmp("1.0-1", "1.0-1"), Ordering::Equal);
        assert_eq!(version_cmp("2.0-1", "1.9-9"), Ordering::Greater);
    }

    #[test]
    fn version_cmp_treats_a_trailing_alpha_suffix_as_older() {
        use std::cmp::Ordering;
        // A bare `1.0` beats a `1.0`-prefixed pre-release suffix...
        assert_eq!(version_cmp("1.0-1", "1.0foo.2-1"), Ordering::Greater);
        assert_eq!(version_cmp("1.0-1", "1.0alpha-1"), Ordering::Greater);
        // ...but loses to an actual point release, since that trailing
        // segment is numeric rather than alphabetic.
        assert_eq!(version_cmp("1.0-1", "1.0.1-1"), Ordering::Less);
    }

    #[test]
    fn version_cmp_treats_a_delimited_trailing_alpha_segment_as_newer() {
        use std::cmp::Ordering;
        // Unlike the glued `1.0alpha` suffix above, a `.`-delimited
        // trailing alphabetic segment is a genuine extra version
        // component, not a pre-release marker, so it's newer — same as
        // `1.0` losing to `1.0.1`.
        assert_eq!(version_cmp("1.0-1", "1.0.a-1"), Ordering::Less);
    }

    #[test]
    fn version_cmp_treats_a_delimited_trailing_alpha_sub_segment_as_older() {
        use std::cmp::Ordering;
        // Unlike the previous case's `1.0` vs `1.0.a`, here the trailing
        // alphabetic piece is a *sub*-segment of an existing segment
        // (`alpha`'s `.0` continues `alpha1`'s numeric sub-segment, it
        // doesn't start a new one) — real ALPM's segment/sub-segment
        // distinction still ranks this as a pre-release, so `alpha1` (no
        // trailing delimiter before its digit) loses to `alpha.0`.
        assert_eq!(version_cmp("alpha1-1", "alpha.0-1"), Ordering::Less);
    }

    #[test]
    fn version_cmp_counts_consecutive_delimiters() {
        use std::cmp::Ordering;
        // ALPM's segment splitter records how many leading delimiter
        // characters precede each segment, and more delimiters always
        // outranks fewer at the same position, independent of what
        // follows — `1...0` (three dots) beats `1.2` (one dot) even
        // though `0 < 2`, because the delimiter count is compared first.
        assert_eq!(version_cmp("1...0-1", "1.2-1"), Ordering::Greater);
        // Matching delimiter counts fall through to the segment itself as
        // usual.
        assert_eq!(version_cmp("1...0-1", "1...2-1"), Ordering::Less);
    }

    #[test]
    fn version_cmp_compares_numeric_segments_past_u64_range() {
        use std::cmp::Ordering;
        // A pkgver segment longer than `u64::MAX` (20 digits here, one
        // past it) must still compare on magnitude rather than panicking
        // or falling back to a lexical string compare, which would
        // wrongly rank this below `1.9` (`'1' < '9'` as characters).
        assert_eq!(
            version_cmp("1.18446744073709551616-1", "1.9-1"),
            Ordering::Greater
        );
    }
}
