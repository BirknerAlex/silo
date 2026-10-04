//! Flatpak: a `.flatpak` bundle in, an OSTree remote out.
//!
//! A `(repo, channel)` pair is one OSTree remote, served from
//! `/{repo}/{channel}/ostree/`. A remote is a tree of immutable
//! content-addressed objects plus two mutable pieces: the refs, and the
//! `summary` that lists them. Silo keeps each of those where it already
//! keeps the equivalent for other formats:
//!
//! | piece | where it lives |
//! |---|---|
//! | objects | object storage, `ostree/objects/ab/cdef….filez` |
//! | one ref | a `packages` row, and its ref file `ostree/refs/heads/<ref>` |
//! | `summary`, `summary.sig`, `config` | the index, regenerated from the rows |
//!
//! The index group is the whole channel, the same choice RPM and deb make
//! and for the same reason: `summary` lists every ref, so rendering it
//! needs every row at once.
//!
//! A row is one ref. Its `name` is `app/org.example.Hello` (or
//! `runtime/...`), its `arch` the ref's architecture and its `version` the
//! branch. Publishing a ref again replaces the row and moves the ref. The
//! objects of the commit it moved away from stay where they are: objects are
//! shared between commits, and deleting one needs a reachability walk.
//!
//! Everything `summary` needs beyond the common columns — commit checksum
//! and size, timestamp, installed and download size, the app's `metadata`
//! keyfile — is read out of the commit at publish and kept in the row's
//! `metadata`, so rendering the index never reads an object back out of
//! storage.
//!
//! A bundle is imported by replaying its static delta (see
//! [`crate::ostree::delta`]); an OSTree repository pushed by a client
//! arrives object by object and only the ref update comes through
//! [`ref_package`]. Both end in the same row.

use std::future::Future;
use std::pin::Pin;

use serde_json::json;

use crate::ostree::archive;
use crate::ostree::delta::{read_bundle, validate_ref, Body, Bundle};
use crate::ostree::object::{Checksum, Commit, ObjType};
use crate::ostree::summary::{
    render_commit_signatures, render_config, render_signature_file, render_summary, SummaryRef,
};
use crate::ostree::tree::TreeWalk;
use crate::upstream::{
    UpstreamError, UpstreamFetchOptions, UpstreamHttp, UpstreamIndex, UpstreamPackage,
};
use crate::{
    ExtraObject, Format, IndexContext, IndexObject, IndexSigner, PackageFormat, PackageRecord,
    ParseError, ParsedPackage,
};

pub struct FlatpakFormat;

/// The storage prefix of a remote.
pub fn ostree_prefix(repo: &str, channel: &str) -> String {
    format!("{repo}/{channel}/ostree")
}

/// Where a ref's file lives, relative to the bucket root.
pub fn ref_key(repo: &str, channel: &str, reference: &str) -> String {
    format!("{}/refs/heads/{reference}", ostree_prefix(repo, channel))
}

/// Where an object lives, relative to the bucket root.
pub fn object_key(repo: &str, channel: &str, ty: ObjType, checksum: &Checksum) -> String {
    format!(
        "{}/{}",
        ostree_prefix(repo, channel),
        ty.archive_path(checksum)
    )
}

/// Where a commit's signatures live, relative to the bucket root.
pub fn commitmeta_key(repo: &str, channel: &str, checksum: &Checksum) -> String {
    let hex = checksum.hex();
    format!(
        "{}/objects/{}/{}.commitmeta",
        ostree_prefix(repo, channel),
        &hex[..2],
        &hex[2..]
    )
}

/// `app/org.example.Hello/x86_64/stable` as the row fields.
pub fn split_ref(reference: &str) -> Result<(String, String, String), ParseError> {
    validate_ref(reference).map_err(|e| ParseError::invalid(e.to_string()))?;
    let parts: Vec<&str> = reference.split('/').collect();
    Ok((
        format!("{}/{}", parts[0], parts[1]),
        parts[2].to_string(),
        parts[3].to_string(),
    ))
}

/// The row's fields as a ref name again.
pub fn join_ref(name: &str, arch: &str, branch: &str) -> String {
    format!("{name}/{arch}/{branch}")
}

/// What a commit says about itself that `summary` repeats.
struct CommitFacts {
    timestamp: u64,
    installed_size: u64,
    download_size: u64,
    metadata: String,
}

fn commit_facts(commit_bytes: &[u8]) -> Result<CommitFacts, ParseError> {
    let invalid = |e: crate::ostree::gvariant::Error| ParseError::invalid(e.to_string());
    let commit = Commit::parse(commit_bytes).map_err(invalid)?;
    let meta = Commit::metadata(commit_bytes).map_err(invalid)?;
    let size = |key: &str| -> Result<u64, ParseError> {
        match meta.dict_get(key).map_err(invalid)? {
            Some(v) => Ok(v.as_u64().map_err(invalid)?.swap_bytes()),
            None => Ok(0),
        }
    };
    let metadata = match meta.dict_get("xa.metadata").map_err(invalid)? {
        Some(v) => v.as_str().map_err(invalid)?.to_string(),
        None => String::new(),
    };
    Ok(CommitFacts {
        timestamp: commit.timestamp,
        installed_size: size("xa.installed-size")?,
        download_size: size("xa.download-size")?,
        metadata,
    })
}

/// The row for a ref pointing at `commit`. `extra_objects` is whatever
/// still has to be written to storage alongside it.
pub fn ref_package(
    reference: &str,
    checksum: Checksum,
    commit_bytes: &[u8],
    extra_objects: Vec<ExtraObject>,
) -> Result<ParsedPackage, ParseError> {
    let (name, arch, branch) = split_ref(reference)?;
    let facts = commit_facts(commit_bytes)?;
    Ok(ParsedPackage {
        format: PackageFormat::Flatpak,
        name,
        epoch: 0,
        version: branch,
        release: String::new(),
        arch,
        filename: reference.to_string(),
        metadata: json!({
            "commit": checksum.hex(),
            "commit_size": commit_bytes.len(),
            "timestamp": facts.timestamp,
            "installed_size": facts.installed_size,
            "download_size": facts.download_size,
            "metadata": facts.metadata,
        }),
        // The ref file: the commit checksum, as `ostree` writes it.
        payload: format!("{}\n", checksum.hex()).into_bytes(),
        extra_objects,
    })
}

/// The objects of a verified bundle, encoded as an `archive` repository
/// stores them, with the keys they are stored under (relative to the
/// remote's prefix, which the publisher supplies).
fn bundle_objects(bundle: &Bundle) -> Result<Vec<ExtraObject>, ParseError> {
    bundle
        .objects
        .iter()
        .map(|o| {
            let bytes = archive::encode(o).map_err(|e| ParseError::invalid(e.to_string()))?;
            Ok(ExtraObject {
                key: format!("ostree/{}", o.ty.archive_path(&o.checksum)),
                bytes,
                replace: false,
            })
        })
        .collect()
}

/// Checks that every object under the bundle's commit is in the bundle.
fn verify_bundle_tree(bundle: &Bundle) -> Result<(), ParseError> {
    use std::collections::HashMap;

    let metadata: HashMap<(ObjType, Checksum), &[u8]> = bundle
        .objects
        .iter()
        .filter_map(|o| match &o.body {
            Body::Metadata(bytes) => Some(((o.ty, o.checksum), bytes.as_slice())),
            Body::File { .. } => None,
        })
        .collect();
    let files: std::collections::HashSet<Checksum> = bundle
        .objects
        .iter()
        .filter(|o| o.ty == ObjType::File)
        .map(|o| o.checksum)
        .collect();

    let commit = Commit::parse(&bundle.commit).map_err(|e| ParseError::invalid(e.to_string()))?;
    let mut walk = TreeWalk::new(&commit);
    while let Some(want) = walk.next_wanted() {
        if want.ty == ObjType::File {
            if !files.contains(&want.checksum) {
                return Err(ParseError::invalid(format!(
                    "the bundle lacks file object {}",
                    want.checksum
                )));
            }
            continue;
        }
        let Some(bytes) = metadata.get(&(want.ty, want.checksum)) else {
            return Err(ParseError::invalid(format!(
                "the bundle lacks {:?} object {}",
                want.ty, want.checksum
            )));
        };
        walk.provide(&want, bytes)
            .map_err(|e| ParseError::invalid(e.to_string()))?;
    }
    Ok(())
}

/// The object a commit's signatures are stored in, relative to the
/// remote's prefix. `None` when no signing key is configured, or the
/// signer cannot sign.
pub fn commit_signature_object(
    checksum: &Checksum,
    commit_bytes: &[u8],
    signer: Option<&dyn IndexSigner>,
) -> anyhow::Result<Option<ExtraObject>> {
    let Some(signer) = signer else {
        return Ok(None);
    };
    let signature = signer.sign(commit_bytes)?;
    let hex = checksum.hex();
    Ok(Some(ExtraObject {
        key: format!("ostree/objects/{}/{}.commitmeta", &hex[..2], &hex[2..]),
        bytes: render_commit_signatures(&[signature]),
        replace: true,
    }))
}

impl Format for FlatpakFormat {
    fn format(&self) -> PackageFormat {
        PackageFormat::Flatpak
    }

    fn parse(&self, bytes: &[u8]) -> Result<ParsedPackage, ParseError> {
        let bundle = read_bundle(bytes).map_err(|e| ParseError::invalid(e.to_string()))?;
        verify_bundle_tree(&bundle)?;
        ref_package(
            &bundle.reference,
            bundle.commit_checksum,
            &bundle.commit,
            bundle_objects(&bundle)?,
        )
    }

    fn storage_key(&self, repo: &str, channel: &str, pkg: &ParsedPackage) -> String {
        ref_key(repo, channel, &join_ref(&pkg.name, &pkg.arch, &pkg.version))
    }

    fn index_group(&self, _pkg: &ParsedPackage) -> String {
        String::new()
    }

    fn index_prefix(&self, repo: &str, channel: &str, _group: &str) -> String {
        ostree_prefix(repo, channel)
    }

    fn companion_objects(
        &self,
        pkg: &ParsedPackage,
        signer: Option<&dyn IndexSigner>,
    ) -> anyhow::Result<Vec<ExtraObject>> {
        let commit = pkg.metadata["commit"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("a flatpak row carries its commit checksum"))?;
        let checksum = Checksum::from_hex(commit)?;
        // The bundle path has the commit in hand; a ref update does not,
        // and signs the commit it loaded itself.
        let wanted_suffix = format!("{}.commit", &commit[2..]);
        let Some(commit_object) = pkg
            .extra_objects
            .iter()
            .find(|o| o.key.ends_with(&wanted_suffix))
        else {
            return Ok(Vec::new());
        };
        Ok(
            commit_signature_object(&checksum, &commit_object.bytes, signer)?
                .into_iter()
                .collect(),
        )
    }

    fn build_index<'a>(
        &'a self,
        ctx: &'a IndexContext<'a>,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Vec<IndexObject>>> + Send + 'a>> {
        Box::pin(async move {
            let refs = summary_refs(ctx.records)?;
            let last_modified = ctx
                .records
                .iter()
                .map(|r| r.published_at.max(0) as u64)
                .max()
                .unwrap_or(0);
            let summary = render_summary(&refs, last_modified);

            let mut objects = vec![IndexObject {
                name: "config".into(),
                bytes: render_config().into_bytes(),
                content_type: "text/plain",
            }];
            if let Some(signer) = ctx.signer {
                let signature = signer.sign(&summary)?;
                objects.push(IndexObject {
                    name: "summary.sig".into(),
                    bytes: render_signature_file(&[signature]),
                    content_type: "application/octet-stream",
                });
            }
            objects.push(IndexObject {
                name: "summary".into(),
                bytes: summary,
                content_type: "application/octet-stream",
            });
            Ok(objects)
        })
    }
}

/// The summary entries for a channel's rows.
fn summary_refs(records: &[PackageRecord]) -> anyhow::Result<Vec<SummaryRef>> {
    records
        .iter()
        .map(|r| {
            let commit = r.metadata["commit"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("{} has no commit checksum", r.filename))?;
            let number = |key: &str| r.metadata[key].as_u64().unwrap_or(0);
            Ok(SummaryRef {
                name: join_ref(&r.name, &r.arch, &r.version),
                commit: Checksum::from_hex(commit)?,
                commit_size: number("commit_size"),
                timestamp: number("timestamp"),
                installed_size: number("installed_size"),
                download_size: number("download_size"),
                metadata: r.metadata["metadata"].as_str().unwrap_or("").to_string(),
            })
        })
        .collect()
}

/// The `.flatpakrepo` file `flatpak remote-add` reads: where the remote
/// is, and the key its signatures verify against.
///
/// `gpg_key` is the binary public key, which the file carries base64
/// encoded on one line. Without one the remote is declared unsigned, which
/// is the only thing an unconfigured server can honestly say.
pub fn render_flatpakrepo(title: &str, url: &str, gpg_key: Option<&[u8]>) -> String {
    let mut out = String::from("[Flatpak Repo]\n");
    out.push_str(&format!("Title={}\n", keyfile_value(title)));
    out.push_str(&format!("Url={}\n", keyfile_value(url)));
    match gpg_key {
        Some(key) => out.push_str(&format!("GPGKey={}\n", base64_standard(key))),
        None => out.push_str("GPGVerify=false\n"),
    }
    out
}

/// The runtime an app's `metadata` keyfile asks for, as a ref
/// (`runtime/org.example.Platform/x86_64/24.08`).
pub fn runtime_ref(metadata: &str) -> Option<String> {
    let mut in_application = false;
    for line in metadata.lines() {
        let line = line.trim();
        if let Some(group) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            in_application = group == "Application";
        } else if in_application {
            if let Some(value) = line.strip_prefix("runtime=") {
                let reference = format!("runtime/{}", value.trim());
                return validate_ref(&reference).is_ok().then_some(reference);
            }
        }
    }
    None
}

/// The `.flatpakref` file for one app or runtime: what `flatpak install
/// ./app.flatpakref` reads to add the remote and install in one step.
///
/// An app needs its runtime too, and flatpak looks for it only in remotes
/// that already exist or at `RuntimeRepo` — not in the remote the ref
/// itself names. `runtime_repo` is the `.flatpakrepo` to find it in, which
/// is this remote's own when the runtime is published beside the app.
pub fn render_flatpakref(
    title: &str,
    reference: &str,
    url: &str,
    gpg_key: Option<&[u8]>,
    runtime_repo: Option<&str>,
) -> Result<String, ParseError> {
    let (name, _arch, branch) = split_ref(reference)?;
    let (kind, id) = name.split_once('/').expect("split_ref joins kind and id");
    let mut out = String::from("[Flatpak Ref]\n");
    out.push_str(&format!("Title={}\n", keyfile_value(title)));
    out.push_str(&format!("Name={id}\n"));
    out.push_str(&format!("Branch={branch}\n"));
    out.push_str(&format!("Url={}\n", keyfile_value(url)));
    out.push_str(&format!("IsRuntime={}\n", kind == "runtime"));
    if let Some(key) = gpg_key {
        out.push_str(&format!("GPGKey={}\n", base64_standard(key)));
    }
    if let Some(repo) = runtime_repo {
        out.push_str(&format!("RuntimeRepo={}\n", keyfile_value(repo)));
    }
    Ok(out)
}

/// A keyfile value occupies one line, so a newline in a title would let
/// it inject keys of its own.
fn keyfile_value(value: &str) -> String {
    value.replace(['\n', '\r'], " ")
}

fn base64_standard(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Flatpak has no upstream index silo can mirror: an OSTree remote's
/// `summary` is a different document from the package lists the sync job
/// consumes, and pull-through works one named artifact at a time.
pub struct FlatpakUpstream;

impl UpstreamIndex for FlatpakUpstream {
    fn format(&self) -> PackageFormat {
        PackageFormat::Flatpak
    }

    fn fetch_index<'a>(
        &'a self,
        _http: &'a UpstreamHttp,
        _opts: &'a UpstreamFetchOptions,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<UpstreamPackage>, UpstreamError>> + Send + 'a>>
    {
        Box::pin(async {
            Err(UpstreamError::parse(
                "flatpak remotes cannot be used as an upstream",
            ))
        })
    }
}

/// Branch comparison. Flatpak branches are free-form labels (`stable`,
/// `24.08`, `beta`), so there is no ordering beyond a stable one.
pub fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.cmp(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ostree::gvariant::View;

    const HELLO: &[u8] = include_bytes!("../tests/fixtures/hello.flatpak");

    #[test]
    fn a_bundle_parses_into_one_ref_row() {
        let pkg = FlatpakFormat.parse(HELLO).unwrap();
        assert_eq!(pkg.format, PackageFormat::Flatpak);
        assert_eq!(pkg.name, "app/org.example.Hello");
        assert_eq!(pkg.arch, "x86_64");
        assert_eq!(pkg.version, "stable");
        assert_eq!(pkg.nevra(), "app/org.example.Hello/x86_64/stable");
        assert_eq!(
            pkg.metadata["commit"],
            "6bff8a2710a3eb3d2124d3804230e388836e089e9e4761293f6c0d160e38151e"
        );
        assert!(pkg.metadata["installed_size"].as_u64().unwrap() > 0);
        assert!(pkg.metadata["metadata"]
            .as_str()
            .unwrap()
            .contains("[Application]"));
        assert_eq!(
            pkg.payload,
            b"6bff8a2710a3eb3d2124d3804230e388836e089e9e4761293f6c0d160e38151e\n"
        );
        // Seven objects and the commit.
        assert_eq!(pkg.extra_objects.len(), 8);
        assert!(pkg
            .extra_objects
            .iter()
            .any(|o| o.key.starts_with("ostree/objects/") && o.key.ends_with(".commit")));
    }

    #[test]
    fn a_runtime_bundle_with_symlinks_parses_and_round_trips() {
        use crate::ostree::delta::Body;

        let bytes = include_bytes!("../tests/fixtures/mini-runtime.flatpak");
        let pkg = FlatpakFormat.parse(bytes).unwrap();
        assert_eq!(pkg.name, "runtime/org.example.Mini");
        assert_eq!(pkg.version, "1");
        assert_eq!(pkg.nevra(), "runtime/org.example.Mini/x86_64/1");

        // Symlinks are objects in their own right: a header and a target,
        // no content. Both must survive replay and re-encoding.
        let bundle = read_bundle(bytes).unwrap();
        let targets: Vec<&str> = bundle
            .objects
            .iter()
            .filter_map(|o| match &o.body {
                Body::File { meta, .. } if meta.is_symlink() => Some(meta.symlink_target.as_str()),
                _ => None,
            })
            .collect();
        assert!(targets.contains(&"tool"), "{targets:?}");
        assert!(targets.contains(&"../lib/sub"), "{targets:?}");

        for object in &bundle.objects {
            let encoded = archive::encode(object).unwrap();
            let sum = archive::checksum_of(object.ty, &encoded, 1 << 20).unwrap();
            assert_eq!(sum, object.checksum);
        }

        let form =
            render_flatpakref("Mini", &pkg.nevra(), "http://silo/r/c/ostree", None, None).unwrap();
        assert!(form.contains("IsRuntime=true"), "{form}");
    }

    #[test]
    fn the_ref_file_and_index_live_where_the_server_serves_them() {
        let pkg = FlatpakFormat.parse(HELLO).unwrap();
        assert_eq!(
            FlatpakFormat.storage_key("myrepo", "stable", &pkg),
            "myrepo/stable/ostree/refs/heads/app/org.example.Hello/x86_64/stable"
        );
        assert_eq!(
            FlatpakFormat.index_prefix("myrepo", "stable", ""),
            "myrepo/stable/ostree"
        );
        assert_eq!(FlatpakFormat.index_group(&pkg), "");
    }

    #[test]
    fn garbage_is_not_a_bundle() {
        assert!(FlatpakFormat.parse(b"").is_err());
        assert!(FlatpakFormat.parse(b"not a flatpak").is_err());
        assert!(FlatpakFormat.parse(&HELLO[..HELLO.len() / 2]).is_err());
    }

    fn record(pkg: &ParsedPackage, published_at: i64) -> PackageRecord {
        PackageRecord {
            format: PackageFormat::Flatpak,
            name: pkg.name.clone(),
            epoch: 0,
            version: pkg.version.clone(),
            release: String::new(),
            arch: pkg.arch.clone(),
            filename: pkg.filename.clone(),
            storage_key: FlatpakFormat.storage_key("r", "c", pkg),
            size_bytes: pkg.payload.len() as i64,
            sha256: String::new(),
            metadata: pkg.metadata.clone(),
            published_at,
        }
    }

    struct FixedSigner;
    impl IndexSigner for FixedSigner {
        fn key_name(&self) -> &str {
            "test"
        }
        fn sign(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
            Ok(format!("sig-of-{}", data.len()).into_bytes())
        }
    }

    #[tokio::test]
    async fn the_index_is_summary_config_and_a_signature() {
        let pkg = FlatpakFormat.parse(HELLO).unwrap();
        let records = [record(&pkg, 1_700_000_000)];
        let objects = FlatpakFormat
            .build_index(&IndexContext {
                repo: "r",
                channel: "c",
                group: "",
                records: &records,
                public_base_url: None,
                signer: Some(&FixedSigner),
            })
            .await
            .unwrap();
        let names: Vec<_> = objects.iter().map(|o| o.name.as_str()).collect();
        assert!(names.contains(&"summary"));
        assert!(names.contains(&"summary.sig"));
        assert!(names.contains(&"config"));

        let summary = objects.iter().find(|o| o.name == "summary").unwrap();
        let view = View::new("(a(s(taya{sv}))a{sv})", &summary.bytes).unwrap();
        let refs = view.child(0).unwrap();
        assert_eq!(refs.len().unwrap(), 1);
        assert_eq!(
            refs.at(0).unwrap().child(0).unwrap().as_str().unwrap(),
            "app/org.example.Hello/x86_64/stable"
        );

        // The signature is over the summary exactly as served.
        let sig_file = objects.iter().find(|o| o.name == "summary.sig").unwrap();
        let sigs = View::new("a{sv}", &sig_file.bytes).unwrap();
        let sigs = sigs.dict_get("ostree.gpgsigs").unwrap().unwrap();
        assert_eq!(
            sigs.at(0).unwrap().as_byte_array().unwrap(),
            format!("sig-of-{}", summary.bytes.len()).as_bytes()
        );
    }

    #[tokio::test]
    async fn without_a_key_the_index_is_unsigned() {
        let pkg = FlatpakFormat.parse(HELLO).unwrap();
        let records = [record(&pkg, 1)];
        let objects = FlatpakFormat
            .build_index(&IndexContext {
                repo: "r",
                channel: "c",
                group: "",
                records: &records,
                public_base_url: None,
                signer: None,
            })
            .await
            .unwrap();
        assert!(objects.iter().all(|o| o.name != "summary.sig"));
    }

    #[tokio::test]
    async fn an_empty_channel_still_renders_a_summary() {
        let objects = FlatpakFormat
            .build_index(&IndexContext {
                repo: "r",
                channel: "c",
                group: "",
                records: &[],
                public_base_url: None,
                signer: None,
            })
            .await
            .unwrap();
        assert!(objects.iter().any(|o| o.name == "summary"));
    }

    #[test]
    fn a_commit_is_signed_into_a_commitmeta_object() {
        let pkg = FlatpakFormat.parse(HELLO).unwrap();
        let extra = FlatpakFormat
            .companion_objects(&pkg, Some(&FixedSigner))
            .unwrap();
        assert_eq!(extra.len(), 1);
        assert!(extra[0].key.ends_with(".commitmeta"));
        assert!(FlatpakFormat
            .companion_objects(&pkg, None)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn refs_split_into_row_fields_and_back() {
        let (name, arch, branch) = split_ref("runtime/org.example.Platform/aarch64/24.08").unwrap();
        assert_eq!(name, "runtime/org.example.Platform");
        assert_eq!(arch, "aarch64");
        assert_eq!(branch, "24.08");
        assert_eq!(
            join_ref(&name, &arch, &branch),
            "runtime/org.example.Platform/aarch64/24.08"
        );
        assert!(split_ref("app/../x/y").is_err());
    }

    #[test]
    fn a_flatpakrepo_names_the_remote_and_its_key() {
        let signed =
            render_flatpakrepo("Silo", "https://silo.example/r/c/ostree", Some(b"\x01\x02"));
        assert!(signed.starts_with("[Flatpak Repo]\n"));
        assert!(signed.contains("Url=https://silo.example/r/c/ostree\n"));
        assert!(signed.contains("GPGKey=AQI=\n"));
        assert!(!signed.contains("GPGVerify"));

        let unsigned = render_flatpakrepo("Silo", "http://silo/r/c/ostree", None);
        assert!(unsigned.contains("GPGVerify=false"));
        assert!(!unsigned.contains("GPGKey"));
    }

    #[test]
    fn a_title_cannot_inject_keyfile_lines() {
        let repo = render_flatpakrepo("Evil\nGPGVerify=false", "http://x/ostree", Some(b"k"));
        assert!(repo.lines().all(|l| !l.starts_with("GPGVerify")), "{repo}");
        assert_eq!(repo.lines().count(), 4, "{repo}");
    }

    #[test]
    fn a_flatpakref_names_the_app_branch_and_remote() {
        let r = render_flatpakref(
            "Hello",
            "app/org.example.Hello/x86_64/stable",
            "http://silo/r/c/ostree",
            Some(b"k"),
            Some("http://silo/r/c/silo.flatpakrepo"),
        )
        .unwrap();
        assert!(r.starts_with("[Flatpak Ref]\n"));
        assert!(r.contains("RuntimeRepo=http://silo/r/c/silo.flatpakrepo\n"));
        assert!(r.contains("Name=org.example.Hello\n"));
        assert!(r.contains("Branch=stable\n"));
        assert!(r.contains("IsRuntime=false\n"));
        assert!(r.contains("GPGKey=aw==\n"));

        let runtime = render_flatpakref(
            "RT",
            "runtime/org.example.Platform/x86_64/1",
            "http://silo/r/c/ostree",
            None,
            None,
        )
        .unwrap();
        assert!(runtime.contains("IsRuntime=true"));
        assert!(!runtime.contains("GPGKey"));
        assert!(!runtime.contains("RuntimeRepo"));
        assert!(render_flatpakref("x", "bogus", "http://x", None, None).is_err());
    }

    #[test]
    fn an_apps_runtime_is_read_from_its_metadata() {
        assert_eq!(
            runtime_ref(
                "[Application]\nname=org.example.Hello\nruntime=org.example.Platform/x86_64/24.08\nsdk=org.example.Sdk/x86_64/24.08\n"
            )
            .as_deref(),
            Some("runtime/org.example.Platform/x86_64/24.08")
        );
        // Only the Application group counts: an extension or context
        // section can carry keys with the same name.
        assert_eq!(
            runtime_ref("[Context]\nruntime=org.x.Y/x86_64/1\n[Application]\nname=a\n"),
            None
        );
        assert_eq!(runtime_ref(""), None);
        assert_eq!(
            runtime_ref("[Application]\nruntime=../../etc/x86_64/1\n"),
            None,
            "a value that is not a ref is not followed"
        );
    }

    #[test]
    fn the_bundles_app_names_the_runtime_it_needs() {
        let pkg = FlatpakFormat.parse(HELLO).unwrap();
        assert_eq!(
            runtime_ref(pkg.metadata["metadata"].as_str().unwrap()).as_deref(),
            Some("runtime/org.freedesktop.Platform/x86_64/24.08")
        );
    }

    #[test]
    fn branches_order_stably() {
        assert_eq!(version_cmp("stable", "stable"), std::cmp::Ordering::Equal);
        assert_eq!(version_cmp("23.08", "24.08"), std::cmp::Ordering::Less);
    }

    #[tokio::test]
    async fn a_flatpak_remote_is_not_an_upstream() {
        let http = UpstreamHttp::new(reqwest::Client::new(), "http://127.0.0.1:1");
        let err = FlatpakUpstream
            .fetch_index(&http, &UpstreamFetchOptions::default())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("flatpak"), "{err}");
    }
}
