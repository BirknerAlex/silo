//! `silo publish-ostree`: pushing refs from a local OSTree repository.
//!
//! The client does the walking, so the server needs no libostree and an
//! interrupted push resumes where it stopped:
//!
//! 1. Read each ref's commit from the local repository and walk its tree,
//!    collecting every object the commit needs.
//! 2. Ask the server which of them it lacks.
//! 3. Upload exactly those, a few at a time.
//! 4. Move the refs. Only now does anything become visible, and the server
//!    checks the whole tree is present before it agrees.
//!
//! The local repository has to be in `archive` mode (what `flatpak
//! build-export` and `flatpak-builder --repo` produce), because that is the
//! form the server stores and serves: its objects are uploaded byte for byte.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context};
use serde::Deserialize;
use silo_pkg::ostree::delta::validate_ref;
use silo_pkg::ostree::object::{Checksum, Commit, ObjType};
use silo_pkg::ostree::tree::TreeWalk;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// Objects uploaded at once.
const UPLOAD_CONCURRENCY: usize = 16;

/// Object names sent per `missing` request.
const MISSING_BATCH: usize = 20_000;

/// What the server answers a ref update with.
#[derive(Deserialize)]
struct RefResponse {
    signed: bool,
}

#[derive(Deserialize)]
struct MissingResponse {
    missing: Vec<String>,
}

/// A ref to push and the commit it points at locally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRef {
    pub name: String,
    pub commit: Checksum,
}

/// A local `archive`-mode repository.
pub struct LocalRepo {
    root: PathBuf,
}

impl LocalRepo {
    /// Opens a repository, refusing one the server could not take
    /// objects from.
    pub fn open(root: &Path) -> anyhow::Result<LocalRepo> {
        let config = std::fs::read_to_string(root.join("config")).with_context(|| {
            format!(
                "{} is not an OSTree repository (no config file)",
                root.display()
            )
        })?;
        let mode = config
            .lines()
            .find_map(|l| l.trim().strip_prefix("mode="))
            .map(str::trim)
            .unwrap_or("bare");
        if mode != "archive" && mode != "archive-z2" {
            bail!(
                "{} is a `{mode}` repository; publishing needs `archive` mode.\n\
                 Convert it with:\n  \
                 ostree --repo=archive-repo init --mode=archive-z2\n  \
                 ostree --repo=archive-repo pull-local {} <ref>",
                root.display(),
                root.display()
            );
        }
        Ok(LocalRepo {
            root: root.to_path_buf(),
        })
    }

    /// The refs under `refs/heads`, which is where a build leaves them.
    pub fn local_refs(&self) -> anyhow::Result<Vec<LocalRef>> {
        let heads = self.root.join("refs/heads");
        let mut found = Vec::new();
        collect_refs(&heads, &heads, &mut found)?;
        found.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(found)
    }

    /// Resolves a named ref: a local branch, or one pulled from a remote
    /// (`refs/remotes/<remote>/<ref>`).
    pub fn resolve(&self, name: &str) -> anyhow::Result<LocalRef> {
        let direct = self.root.join("refs/heads").join(name);
        if direct.is_file() {
            return read_ref(name, &direct);
        }
        let remotes = self.root.join("refs/remotes");
        if let Ok(entries) = std::fs::read_dir(&remotes) {
            for remote in entries.flatten() {
                let candidate = remote.path().join(name);
                if candidate.is_file() {
                    return read_ref(name, &candidate);
                }
            }
        }
        bail!("{name} is not a ref in {}", self.root.display())
    }

    fn object_path(&self, ty: ObjType, checksum: &Checksum) -> PathBuf {
        self.root.join(ty.archive_path(checksum))
    }

    fn read_object(&self, ty: ObjType, checksum: &Checksum) -> anyhow::Result<Vec<u8>> {
        let path = self.object_path(ty, checksum);
        std::fs::read(&path).with_context(|| {
            format!(
                "the repository lacks {ty:?} object {checksum} ({})",
                path.display()
            )
        })
    }

    /// Every object a commit needs, commit included, as the paths the
    /// server names them by.
    pub fn objects_of(
        &self,
        commit: &Checksum,
    ) -> anyhow::Result<BTreeMap<String, (ObjType, Checksum)>> {
        let commit_bytes = self.read_object(ObjType::Commit, commit)?;
        let parsed = Commit::parse(&commit_bytes)
            .map_err(|e| anyhow::anyhow!("commit {commit} is malformed: {e}"))?;

        let mut objects = BTreeMap::new();
        objects.insert(
            ObjType::Commit.archive_path(commit),
            (ObjType::Commit, *commit),
        );

        let mut walk = TreeWalk::new(&parsed);
        while let Some(want) = walk.next_wanted() {
            if want.ty == ObjType::File {
                if !self.object_path(want.ty, &want.checksum).is_file() {
                    bail!("the repository lacks file object {}", want.checksum);
                }
            } else {
                let bytes = self.read_object(want.ty, &want.checksum)?;
                walk.provide(&want, &bytes).map_err(|e| {
                    anyhow::anyhow!("{:?} {} is malformed: {e}", want.ty, want.checksum)
                })?;
            }
            objects.insert(
                want.ty.archive_path(&want.checksum),
                (want.ty, want.checksum),
            );
        }
        Ok(objects)
    }
}

fn collect_refs(base: &Path, dir: &Path, out: &mut Vec<LocalRef>) -> anyhow::Result<()> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_refs(base, &path, out)?;
        } else if let Ok(rel) = path.strip_prefix(base) {
            let name = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            out.push(read_ref(&name, &path)?);
        }
    }
    Ok(())
}

fn read_ref(name: &str, path: &Path) -> anyhow::Result<LocalRef> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("failed to read ref {name}"))?;
    let commit = Checksum::from_hex(text.trim())
        .map_err(|e| anyhow::anyhow!("ref {name} does not hold a commit checksum: {e}"))?;
    Ok(LocalRef {
        name: name.to_string(),
        commit,
    })
}

/// What a push did.
#[derive(Debug, Default)]
pub struct PushSummary {
    pub refs: Vec<String>,
    pub skipped: Vec<String>,
    pub objects_total: usize,
    pub objects_uploaded: usize,
    pub signed: bool,
}

/// Pushes refs from `repo_dir` to `server`'s `repo`/`channel`.
///
/// An empty `names` pushes every app and runtime ref under `refs/heads`.
pub async fn push(
    server: &str,
    token: &str,
    repo: &str,
    channel: &str,
    repo_dir: &Path,
    names: &[String],
) -> anyhow::Result<PushSummary> {
    let local = LocalRepo::open(repo_dir)?;

    let mut summary = PushSummary::default();
    let mut refs = Vec::new();
    if names.is_empty() {
        for r in local.local_refs()? {
            // Appstream metadata and the like are refs too, but only apps
            // and runtimes are things a client installs.
            if validate_ref(&r.name).is_ok() {
                refs.push(r);
            } else {
                summary.skipped.push(r.name);
            }
        }
    } else {
        for name in names {
            validate_ref(name).map_err(|e| anyhow::anyhow!("{e}"))?;
            refs.push(local.resolve(name)?);
        }
    }
    if refs.is_empty() {
        bail!(
            "{} has no app or runtime refs to publish{}",
            repo_dir.display(),
            if summary.skipped.is_empty() {
                String::new()
            } else {
                format!(" (skipped: {})", summary.skipped.join(", "))
            }
        );
    }

    let mut wanted: BTreeMap<String, (ObjType, Checksum)> = BTreeMap::new();
    for r in &refs {
        wanted.extend(local.objects_of(&r.commit)?);
    }
    summary.objects_total = wanted.len();

    let base = format!("{}/{repo}/{channel}/ostree", server.trim_end_matches('/'));
    let http = reqwest::Client::builder()
        .build()
        .context("failed to build the HTTP client")?;

    let paths: Vec<&String> = wanted.keys().collect();
    let mut missing: BTreeSet<String> = BTreeSet::new();
    for batch in paths.chunks(MISSING_BATCH) {
        let response = http
            .post(format!("{base}/missing"))
            .bearer_auth(token)
            .json(&serde_json::json!({ "objects": batch }))
            .send()
            .await
            .context("failed to ask the server which objects it lacks")?;
        let response: MissingResponse = ok_json(response, "asking for missing objects").await?;
        missing.extend(response.missing);
    }

    let semaphore = Arc::new(Semaphore::new(UPLOAD_CONCURRENCY));
    let mut uploads = JoinSet::new();
    for path in &missing {
        let Some((ty, checksum)) = wanted.get(path).copied() else {
            bail!("the server asked for {path}, which this push did not offer");
        };
        let file = local.object_path(ty, &checksum);
        let url = format!("{base}/{path}");
        let http = http.clone();
        let token = token.to_string();
        let permit = semaphore.clone().acquire_owned().await?;
        uploads.spawn(async move {
            let _permit = permit;
            let bytes = tokio::fs::read(&file)
                .await
                .with_context(|| format!("failed to read {}", file.display()))?;
            let response = http
                .put(&url)
                .bearer_auth(&token)
                .body(bytes)
                .send()
                .await
                .with_context(|| format!("failed to upload {url}"))?;
            ok_status(response, &url).await
        });
    }
    while let Some(done) = uploads.join_next().await {
        done.context("an upload task panicked")??;
        summary.objects_uploaded += 1;
    }

    for r in &refs {
        let response = http
            .post(format!("{base}/refs"))
            .bearer_auth(token)
            .json(&serde_json::json!({ "ref": r.name, "commit": r.commit.hex() }))
            .send()
            .await
            .with_context(|| format!("failed to publish {}", r.name))?;
        let result: RefResponse = ok_json(response, &format!("publishing {}", r.name)).await?;
        summary.signed = result.signed;
        summary.refs.push(r.name.clone());
    }
    Ok(summary)
}

/// Turns a non-success response into an error carrying the server's
/// explanation.
async fn ok_status(response: reqwest::Response, what: &str) -> anyhow::Result<()> {
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    let body = response.text().await.unwrap_or_default();
    let detail = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v["error"].as_str().map(str::to_string))
        .unwrap_or(body);
    bail!("{what}: the server answered {status}: {detail}")
}

async fn ok_json<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
    what: &str,
) -> anyhow::Result<T> {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        let detail = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v["error"].as_str().map(str::to_string))
            .unwrap_or(body);
        bail!("{what}: the server answered {status}: {detail}");
    }
    serde_json::from_str(&body).with_context(|| format!("{what}: unreadable response"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A repository on disk holding the objects of the test bundle.
    fn fixture_repo(mode: &str) -> tempfile::TempDir {
        use silo_pkg::ostree::archive;
        use silo_pkg::ostree::delta::read_bundle;

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("config"),
            format!("[core]\nrepo_version=1\nmode={mode}\n"),
        )
        .unwrap();
        let bundle = read_bundle(include_bytes!(
            "../../silo-pkg/tests/fixtures/hello.flatpak"
        ))
        .unwrap();
        for object in &bundle.objects {
            let path = dir.path().join(object.ty.archive_path(&object.checksum));
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, archive::encode(object).unwrap()).unwrap();
        }
        let ref_path = dir.path().join("refs/heads").join(&bundle.reference);
        std::fs::create_dir_all(ref_path.parent().unwrap()).unwrap();
        std::fs::write(ref_path, format!("{}\n", bundle.commit_checksum)).unwrap();
        dir
    }

    #[test]
    fn a_local_repository_yields_its_refs_and_every_object() {
        let dir = fixture_repo("archive-z2");
        let repo = LocalRepo::open(dir.path()).unwrap();
        let refs = repo.local_refs().unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].name, "app/org.example.Hello/x86_64/stable");

        // The commit plus seven objects.
        let objects = repo.objects_of(&refs[0].commit).unwrap();
        assert_eq!(objects.len(), 8);
        assert!(objects.keys().all(|p| p.starts_with("objects/")));
    }

    #[test]
    fn a_repository_that_is_not_archive_mode_is_refused_with_the_fix() {
        let dir = fixture_repo("bare-user");
        let err = LocalRepo::open(dir.path()).err().unwrap().to_string();
        assert!(err.contains("archive"), "{err}");
        assert!(err.contains("pull-local"), "{err}");
    }

    #[test]
    fn a_directory_that_is_not_a_repository_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(LocalRepo::open(dir.path()).is_err());
    }

    #[test]
    fn a_missing_object_stops_the_walk() {
        let dir = fixture_repo("archive");
        let repo = LocalRepo::open(dir.path()).unwrap();
        let commit = repo.local_refs().unwrap()[0].commit;
        let objects = repo.objects_of(&commit).unwrap();
        let (path, _) = objects
            .iter()
            .find(|(_, (ty, _))| *ty == ObjType::File)
            .unwrap();
        std::fs::remove_file(dir.path().join(path)).unwrap();
        let err = repo.objects_of(&commit).unwrap_err().to_string();
        assert!(err.contains("lacks file object"), "{err}");
    }

    #[test]
    fn a_ref_pulled_from_a_remote_resolves_by_name() {
        let dir = fixture_repo("archive-z2");
        let heads = dir.path().join("refs/heads/app");
        let commit = std::fs::read_to_string(
            dir.path()
                .join("refs/heads/app/org.example.Hello/x86_64/stable"),
        )
        .unwrap();
        std::fs::remove_dir_all(heads).unwrap();
        let remote = dir
            .path()
            .join("refs/remotes/flathub/app/org.example.Hello/x86_64");
        std::fs::create_dir_all(&remote).unwrap();
        std::fs::write(remote.join("stable"), commit).unwrap();

        let repo = LocalRepo::open(dir.path()).unwrap();
        assert!(repo.local_refs().unwrap().is_empty());
        let resolved = repo.resolve("app/org.example.Hello/x86_64/stable").unwrap();
        assert_eq!(resolved.name, "app/org.example.Hello/x86_64/stable");
        assert!(repo.resolve("app/org.example.Nope/x86_64/stable").is_err());
    }

    mod push {
        use super::*;
        use wiremock::matchers::{method, path, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        const REF: &str = "app/org.example.Hello/x86_64/stable";

        fn missing_response(paths: &[String]) -> ResponseTemplate {
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "missing": paths }))
        }

        async fn requests(server: &MockServer, verb: &str) -> Vec<String> {
            server
                .received_requests()
                .await
                .unwrap()
                .into_iter()
                .filter(|r| r.method.as_str() == verb)
                .map(|r| r.url.path().to_string())
                .collect()
        }

        #[tokio::test]
        async fn only_the_objects_the_server_lacks_are_uploaded_and_then_the_ref_moves() {
            let dir = fixture_repo("archive-z2");
            let repo = LocalRepo::open(dir.path()).unwrap();
            let commit = repo.local_refs().unwrap()[0].commit;
            let all: Vec<String> = repo.objects_of(&commit).unwrap().into_keys().collect();
            // The server already has all but two.
            let lacking = all[..2].to_vec();

            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/r/c/ostree/missing"))
                .respond_with(missing_response(&lacking))
                .mount(&server)
                .await;
            Mock::given(method("PUT"))
                .and(path_regex("^/r/c/ostree/objects/"))
                .respond_with(ResponseTemplate::new(201))
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/r/c/ostree/refs"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({ "signed": true })),
                )
                .mount(&server)
                .await;

            let summary = push(&server.uri(), "tok", "r", "c", dir.path(), &[])
                .await
                .unwrap();
            assert_eq!(summary.objects_total, all.len());
            assert_eq!(summary.objects_uploaded, 2);
            assert_eq!(summary.refs, vec![REF.to_string()]);
            assert!(summary.signed);

            let mut put = requests(&server, "PUT").await;
            put.sort();
            let mut expected: Vec<String> =
                lacking.iter().map(|p| format!("/r/c/ostree/{p}")).collect();
            expected.sort();
            assert_eq!(put, expected);

            // The ref moves last, once, naming the commit.
            let all_requests = server.received_requests().await.unwrap();
            let last = all_requests.last().unwrap();
            assert_eq!(last.url.path(), "/r/c/ostree/refs");
            let body: serde_json::Value = serde_json::from_slice(&last.body).unwrap();
            assert_eq!(body["ref"], REF);
            assert_eq!(body["commit"], commit.hex());
            // Every request carries the credential.
            assert!(all_requests
                .iter()
                .all(|r| r.headers.get("authorization").unwrap() == "Bearer tok"));
        }

        #[tokio::test]
        async fn a_push_with_nothing_missing_still_moves_the_ref() {
            let dir = fixture_repo("archive");
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/r/c/ostree/missing"))
                .respond_with(missing_response(&[]))
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/r/c/ostree/refs"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({ "signed": false })),
                )
                .mount(&server)
                .await;

            let summary = push(
                &format!("{}/", server.uri()),
                "tok",
                "r",
                "c",
                dir.path(),
                &[REF.to_string()],
            )
            .await
            .unwrap();
            assert_eq!(summary.objects_uploaded, 0);
            assert!(!summary.signed);
            assert!(requests(&server, "PUT").await.is_empty());
        }

        #[tokio::test]
        async fn the_servers_explanation_reaches_the_user_when_an_upload_is_refused() {
            let dir = fixture_repo("archive");
            let repo = LocalRepo::open(dir.path()).unwrap();
            let commit = repo.local_refs().unwrap()[0].commit;
            let all: Vec<String> = repo.objects_of(&commit).unwrap().into_keys().collect();

            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/r/c/ostree/missing"))
                .respond_with(missing_response(&all[..1]))
                .mount(&server)
                .await;
            Mock::given(method("PUT"))
                .respond_with(ResponseTemplate::new(400).set_body_json(
                    serde_json::json!({ "error": "invalid ostree request: bad object" }),
                ))
                .mount(&server)
                .await;

            let err = push(&server.uri(), "tok", "r", "c", dir.path(), &[])
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("400"), "{err}");
            assert!(err.contains("bad object"), "{err}");
            assert!(
                requests(&server, "POST")
                    .await
                    .iter()
                    .all(|p| !p.ends_with("/refs")),
                "a failed upload must not move the ref"
            );
        }

        #[tokio::test]
        async fn a_refused_ref_update_is_reported() {
            let dir = fixture_repo("archive");
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/r/c/ostree/missing"))
                .respond_with(missing_response(&[]))
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/r/c/ostree/refs"))
                .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
                .mount(&server)
                .await;
            let err = push(&server.uri(), "tok", "r", "c", dir.path(), &[])
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("403"), "{err}");
            assert!(err.contains(REF), "{err}");
        }

        #[tokio::test]
        async fn the_server_cannot_ask_for_an_object_that_was_not_offered() {
            let dir = fixture_repo("archive");
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/r/c/ostree/missing"))
                .respond_with(missing_response(&[
                    "objects/00/0000000000000000000000000000000000000000000000000000000000.filez"
                        .to_string(),
                ]))
                .mount(&server)
                .await;
            let err = push(&server.uri(), "tok", "r", "c", dir.path(), &[])
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("did not offer"), "{err}");
            assert!(requests(&server, "PUT").await.is_empty());
        }

        #[tokio::test]
        async fn a_repository_with_nothing_to_publish_is_refused_before_any_request() {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join("config"), "[core]\nmode=archive-z2\n").unwrap();
            let heads = dir.path().join("refs/heads/appstream");
            std::fs::create_dir_all(&heads).unwrap();
            let commit = "6bff8a2710a3eb3d2124d3804230e388836e089e9e4761293f6c0d160e38151e";
            std::fs::write(heads.join("x86_64"), format!("{commit}\n")).unwrap();

            let server = MockServer::start().await;
            let err = push(&server.uri(), "tok", "r", "c", dir.path(), &[])
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("no app or runtime refs"), "{err}");
            assert!(err.contains("appstream/x86_64"), "{err}");
            assert!(server.received_requests().await.unwrap().is_empty());
        }

        #[tokio::test]
        async fn a_named_ref_that_is_not_a_flatpak_ref_is_refused() {
            let dir = fixture_repo("archive");
            let server = MockServer::start().await;
            let err = push(
                &server.uri(),
                "tok",
                "r",
                "c",
                dir.path(),
                &["appstream/x86_64".to_string()],
            )
            .await
            .unwrap_err()
            .to_string();
            assert!(err.contains("flatpak ref"), "{err}");
        }

        #[tokio::test]
        async fn an_unreachable_server_is_an_error_not_a_hang() {
            let dir = fixture_repo("archive");
            let err = push("http://127.0.0.1:1", "tok", "r", "c", dir.path(), &[])
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("which objects it lacks"), "{err}");
        }
    }

    #[test]
    fn a_ref_file_that_is_not_a_checksum_is_an_error() {
        let dir = fixture_repo("archive");
        std::fs::write(
            dir.path()
                .join("refs/heads/app/org.example.Hello/x86_64/stable"),
            "nonsense\n",
        )
        .unwrap();
        let repo = LocalRepo::open(dir.path()).unwrap();
        assert!(repo.local_refs().is_err());
    }
}
