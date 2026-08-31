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

use std::pin::Pin;

use serde_json::json;

use crate::apk::{gzip, parse_pkginfo, tar_bytes};
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
            let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
            let mut sorted: Vec<&PackageRecord> = ctx.records.iter().collect();
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
}
