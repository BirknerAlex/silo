//! RPM: parsing, `dnf`/`yum` layout, and repodata generation.
//!
//! Repodata is rendered by [`crate::repodata`], in-process, from database
//! rows alone — the same as apk and npm. primary.xml needs a great deal
//! that no column holds (dependencies, file lists, header byte ranges), so
//! [`crate::repodata::extract`] reads all of it out of the rpm headers
//! once at publish time and it is stored as the row's metadata.

use std::pin::Pin;

use crate::repodata::{self, RepodataEntry, RepodataLocation};
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
                    // error rather than a skip. There is no longer a
                    // package file to fall back to, and quietly dropping
                    // one package from an otherwise complete repo is far
                    // harder to notice than a failed publish.
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
}
