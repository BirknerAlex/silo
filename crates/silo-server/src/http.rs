//! The plain-HTTP surface: what `dnf`, `apk` and `npm` actually talk to.
//!
//! Each client speaks its own protocol and none of them can be taught a
//! new one, so this module is three thin adapters over the same storage
//! and the same auth:
//!
//! | client | reads | credential |
//! |---|---|---|
//! | `dnf`/`yum` | `/{repo}/{ch}/repodata/*`, `/{repo}/{ch}/Packages/*` | Basic (`.repo` `username=`/`password=`) |
//! | `apk` | `/{repo}/{ch}/apk/{arch}/{APKINDEX.tar.gz,*.apk}` | Basic (credentials in the URL) |
//! | `npm` | `/{repo}/{ch}/npm/{name}`, `.../{name}/-/{file}.tgz` | Bearer (`.npmrc` `_authToken`) |
//!
//! Index files (repodata, APKINDEX, packuments) are proxied through the
//! server: they're small and polled constantly. Package downloads
//! 302-redirect to a presigned URL when the backend supports presigning,
//! keeping bulk bandwidth off the server, and fall back to proxying bytes
//! otherwise (e.g. the in-memory backend used in tests).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use base64::Engine;
use serde::Deserialize;
use silo_core::repo::{classify_publish_error, PublishErrorKind, MAX_PACKAGE_BYTES};
use silo_db::audit::{self, AuditEntry};
use silo_db::tokens::Permission;
use silo_pkg::PackageFormat;

use crate::auth::{self, Authenticated};
use crate::AppState;

/// Ceiling on the JSON body of an `npm publish` request, enforced by hand
/// in [`publish_npm`] (see its doc comment for why it can't just be a
/// [`axum::extract::DefaultBodyLimit`] layer). The tarball inside the body
/// is base64-encoded (~33% overhead), so this has to be larger than
/// [`MAX_PACKAGE_BYTES`] itself; the extra 1 MiB covers the envelope
/// (manifest, dist-tags, etc.) around the attachment.
const NPM_PUBLISH_BODY_LIMIT: usize = MAX_PACKAGE_BYTES * 4 / 3 + 1024 * 1024;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .route("/version", get(version))
        // Unauthenticated on purpose — see `gpg_public_key`.
        .route("/RPM-GPG-KEY-silo", get(gpg_public_key))
        // Unauthenticated on purpose — see `pacman_public_key`.
        .route("/pacman-signing-key", get(pacman_public_key))
        // dnf/yum
        .route("/:repo/:channel/repodata/*file", get(get_repodata))
        .route("/:repo/:channel/Packages/*file", get(get_rpm_package))
        // apk
        .route("/:repo/:channel/apk/:arch/*file", get(get_apk_file))
        // pacman
        .route("/:repo/:channel/pacman/:arch/*file", get(get_pacman_file))
        // npm — one catch-all because scoped names (`@acme/widget`) put a
        // slash inside what npm considers a single path segment. `PUT` is
        // how `npm publish`/`yarn publish` send a new version.
        .route("/:repo/:channel/npm/*path", get(get_npm).put(publish_npm))
        .with_state(state)
}

async fn healthz() -> Response {
    (StatusCode::OK, "ok").into_response()
}

/// Readiness depends on the database, since a replica that can't reach it
/// can neither authenticate nor publish.
async fn readyz(State(state): State<Arc<AppState>>) -> Response {
    match state.db.ping().await {
        Ok(()) => {
            state.metrics.database_up.set(1);
            (StatusCode::OK, "ready").into_response()
        }
        Err(e) => {
            state.metrics.database_up.set(0);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("database unavailable: {e}"),
            )
                .into_response()
        }
    }
}

/// The same build info the `GetVersion` RPC returns, over HTTP.
///
/// Duplicated onto this surface because the two are reached differently in
/// practice: gRPC is what the CLI speaks, but an operator debugging a
/// deployment has a shell and `curl`, not necessarily a `silo` binary, and
/// the HTTP port is the one already exposed through the ingress.
async fn version() -> Response {
    let info = silo_core::BuildInfo::current();
    let body = serde_json::json!({
        "version": info.version,
        "commit": info.commit,
        "built_at": info.built_at,
        "formats": PackageFormat::ALL.iter().map(|f| f.as_str()).collect::<Vec<_>>(),
    });
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

/// The armored public half of the configured `signing.gpg` key.
///
/// Named the way every other RPM repository names it, so a `.repo` file
/// reads exactly like a distribution's:
///
/// ```ini
/// gpgkey=https://silo.example.com/RPM-GPG-KEY-silo
/// ```
///
/// Global rather than per-repo because `signing.gpg` is: one key signs
/// every repo this server serves, and a per-repo path would imply a
/// choice that does not exist.
///
/// Unauthenticated, and deliberately so. It is a public key — publishing
/// it is the entire point — and dnf fetches `gpgkey=` outside the
/// credentialed repo session, so requiring a token here would break
/// `repo_gpgcheck=1` for exactly the people it is meant to protect.
async fn gpg_public_key(State(state): State<Arc<AppState>>) -> Response {
    let Some(gpg) = &state.publish.signers.gpg else {
        return (StatusCode::NOT_FOUND, "no signing key is configured").into_response();
    };
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/pgp-keys")],
        gpg.armored_public_key().to_string(),
    )
        .into_response()
}

/// The armored public half of the configured `signing.pacman` key, for
/// `pacman-key --add <(curl .../pacman-signing-key) && pacman-key --lsign-key <fingerprint>`.
///
/// Unauthenticated for the same reason as `gpg_public_key`: it is a public
/// key, and requiring a token here would defeat the point of publishing it.
async fn pacman_public_key(State(state): State<Arc<AppState>>) -> Response {
    let Some(pacman) = &state.publish.signers.pacman else {
        return (StatusCode::NOT_FOUND, "no signing key is configured").into_response();
    };
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/pgp-keys")],
        pacman.armored_public_key().to_string(),
    )
        .into_response()
}

async fn metrics(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !state.config.metrics.enabled {
        return (StatusCode::NOT_FOUND, "metrics are disabled").into_response();
    }
    if state.config.metrics.require_auth {
        // `authenticate_http` no longer errors on a missing credential —
        // that's an anonymous caller now, not a failure — so the gate has
        // to check for an actual token rather than just success.
        let has_token = auth::authenticate_http(&state, &headers, None)
            .await
            .is_ok_and(|a| a.token.is_some());
        if !has_token {
            return unauthorized();
        }
    }

    match state.metrics.render() {
        Ok((content_type, body)) => {
            (StatusCode::OK, [(header::CONTENT_TYPE, content_type)], body).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        // dnf and apk only send credentials after being challenged, so the
        // challenge header is what makes `username=`/`password=` work at all.
        [(header::WWW_AUTHENTICATE, "Basic realm=\"silo\"")],
        "unauthorized",
    )
        .into_response()
}

/// Authenticates a read against one repo, or returns the response to send.
async fn authorize_read(
    state: &AppState,
    headers: &HeaderMap,
    remote_addr: Option<String>,
    repo: &str,
) -> Result<Authenticated, Response> {
    let authenticated = auth::authenticate_http(state, headers, remote_addr)
        .await
        .map_err(|e| {
            let reason = match &e {
                silo_db::tokens::AuthError::Expired(_) => "expired",
                silo_db::tokens::AuthError::Revoked => "revoked",
                silo_db::tokens::AuthError::UserDisabled => "user_disabled",
                silo_db::tokens::AuthError::Db(_) => "database",
                _ => "unknown",
            };
            state
                .metrics
                .auth_failures
                .with_label_values(&[reason])
                .inc();
            unauthorized()
        })?;

    if !authenticated.allows(repo, Permission::Read) {
        let public = state.db.is_repo_public(repo).await.map_err(|e| {
            tracing::error!(error = %e, repo, "failed to look up repo visibility");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        })?;
        if !public {
            // 404 rather than 403: a token scoped to other repos shouldn't
            // be able to enumerate which repos exist by watching status
            // codes, and neither should an unauthenticated caller learn
            // that a private repo exists.
            return Err((StatusCode::NOT_FOUND, "not found").into_response());
        }
    }
    Ok(authenticated)
}

/// Authenticates a write against one repo, or returns the response to
/// send. Unlike [`authorize_read`], a repo's public bit never widens this
/// — write access always has to come from the token's own scope, mirroring
/// `auth::require_repo(..., Permission::Write)` on the gRPC side. Errors
/// are npm's expected JSON shape rather than a bare status, since npm/yarn
/// print the `error` field verbatim.
async fn authorize_write(
    state: &AppState,
    headers: &HeaderMap,
    remote_addr: Option<String>,
    repo: &str,
) -> Result<Authenticated, Response> {
    let authenticated = auth::authenticate_http(state, headers, remote_addr)
        .await
        .map_err(|e| {
            let reason = match &e {
                silo_db::tokens::AuthError::Expired(_) => "expired",
                silo_db::tokens::AuthError::Revoked => "revoked",
                silo_db::tokens::AuthError::UserDisabled => "user_disabled",
                silo_db::tokens::AuthError::Db(_) => "database",
                _ => "unknown",
            };
            state
                .metrics
                .auth_failures
                .with_label_values(&[reason])
                .inc();
            npm_error(StatusCode::UNAUTHORIZED, "authentication required")
        })?;

    if !authenticated.allows(repo, Permission::Write) {
        return Err(npm_error(
            StatusCode::FORBIDDEN,
            "insufficient permission to publish to this repo",
        ));
    }
    Ok(authenticated)
}

/// Serves an index object straight through. Always proxied — these are
/// small, cache-sensitive, and fetched on every `makecache`/`apk update`.
async fn serve_index(state: &AppState, key: &str, content_type: &str, surface: &str) -> Response {
    let result = match state.storage.get(key).await {
        Ok(Some(bytes)) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, content_type.to_string())],
            bytes,
        )
            .into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, key, "failed to read index object");
            (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
        }
    };
    state
        .metrics
        .http_requests
        .with_label_values(&[surface, result.status().as_str()])
        .inc();
    result
}

/// Serves package bytes, preferring a presigned redirect so the download
/// itself never crosses this process.
async fn serve_package(
    state: &AppState,
    key: &str,
    format: PackageFormat,
    auth: &Authenticated,
    repo: &str,
    channel: &str,
) -> Response {
    match state.storage.presigned_get_url(key).await {
        Ok(Some(url)) => {
            state
                .metrics
                .downloads
                .with_label_values(&[format.as_str(), "redirect"])
                .inc();
            audit_download(state, auth, repo, channel, key, format).await;
            return found_redirect(&url);
        }
        Ok(None) => {}
        Err(e) => {
            tracing::error!(error = %e, key, "failed to presign a download URL");
            return (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response();
        }
    }

    match state.storage.get(key).await {
        Ok(Some(bytes)) => {
            state
                .metrics
                .downloads
                .with_label_values(&[format.as_str(), "proxy"])
                .inc();
            audit_download(state, auth, repo, channel, key, format).await;
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/octet-stream")],
                bytes,
            )
                .into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, key, "failed to read package");
            (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
        }
    }
}

/// A 302 redirect to a presigned URL.
///
/// Deliberately 302 rather than axum's `Redirect::temporary` (307).
/// apk-tools' built-in fetcher does not follow 307 — `apk add` fails with
/// "package mentioned in index not found", which reads like a broken
/// index rather than a redirect it declined to follow. Every route that
/// reaches here is GET-only, so 307's method-preservation guarantee buys
/// nothing, and 302 is the status every package manager understands.
fn found_redirect(url: &str) -> Response {
    match axum::http::HeaderValue::from_str(url) {
        Ok(location) => (StatusCode::FOUND, [(header::LOCATION, location)]).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "presigned URL is not a valid header value");
            (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
        }
    }
}

/// Records who downloaded what, when `audit.log_downloads` is on.
///
/// Index fetches are never audited — `dnf makecache` on a fleet of a
/// thousand hosts would write a thousand rows an hour that say nothing.
async fn audit_download(
    state: &AppState,
    auth: &Authenticated,
    repo: &str,
    channel: &str,
    key: &str,
    format: PackageFormat,
) {
    if !state.config.audit.log_downloads {
        return;
    }
    let target = key.rsplit('/').next().unwrap_or(key).to_string();
    state
        .db
        .record_audit(
            AuditEntry::new(audit::action::PACKAGE_DOWNLOAD, &auth.actor)
                .repo(repo)
                .channel(channel)
                .target(target)
                .detail(serde_json::json!({
                    "format": format.as_str(),
                    "storage_key": key,
                })),
        )
        .await;
}

fn remote_addr(connect_info: Option<&ConnectInfo<std::net::SocketAddr>>) -> Option<String> {
    connect_info.map(|ConnectInfo(addr)| addr.ip().to_string())
}

// ---------------------------------------------------------------- dnf/yum

async fn get_repodata(
    State(state): State<Arc<AppState>>,
    Path((repo, channel, file)): Path<(String, String, String)>,
    connect_info: Option<ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) =
        authorize_read(&state, &headers, remote_addr(connect_info.as_ref()), &repo).await
    {
        return resp;
    }
    if let Err(resp) = reject_traversal(&file) {
        return resp;
    }

    let key = format!(
        "{}/{file}",
        silo_core::repo::repodata_prefix(&repo, &channel)
    );
    serve_index(&state, &key, content_type_for(&file), "rpm-index").await
}

async fn get_rpm_package(
    State(state): State<Arc<AppState>>,
    Path((repo, channel, file)): Path<(String, String, String)>,
    connect_info: Option<ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
) -> Response {
    let auth =
        match authorize_read(&state, &headers, remote_addr(connect_info.as_ref()), &repo).await {
            Ok(auth) => auth,
            Err(resp) => return resp,
        };
    if let Err(resp) = reject_traversal(&file) {
        return resp;
    }

    let key = format!(
        "{}/{file}",
        silo_core::repo::packages_prefix(&repo, &channel)
    );
    serve_package(&state, &key, PackageFormat::Rpm, &auth, &repo, &channel).await
}

// -------------------------------------------------------------------- apk

async fn get_apk_file(
    State(state): State<Arc<AppState>>,
    Path((repo, channel, arch, file)): Path<(String, String, String, String)>,
    connect_info: Option<ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
) -> Response {
    let auth =
        match authorize_read(&state, &headers, remote_addr(connect_info.as_ref()), &repo).await {
            Ok(auth) => auth,
            Err(resp) => return resp,
        };
    if let Err(resp) = reject_traversal(&file) {
        return resp;
    }
    if let Err(resp) = reject_traversal(&arch) {
        return resp;
    }

    let key = apk_key(&state, &repo, &channel, &arch, &file).await;
    if file == "APKINDEX.tar.gz" {
        return serve_index(&state, &key, "application/gzip", "apk-index").await;
    }
    serve_package(&state, &key, PackageFormat::Apk, &auth, &repo, &channel).await
}

/// Resolves an apk request to a storage key, falling back to `noarch`.
///
/// apk-tools only ever asks for `$repo/$hostarch/...` — it will not look in
/// a `noarch` directory of its own accord — so silo has to answer for
/// `noarch` content under whichever architecture the client happens to be.
/// Two things live under an architecture, and both fall back:
///
/// * **Package files.** A noarch package is stored once, under `noarch`,
///   rather than copied into every architecture's prefix.
/// * **The index.** Every architecture's APKINDEX already lists the
///   channel's noarch packages, but a channel that contains *only* noarch
///   packages has no per-architecture index at all — and the index it
///   would have had is exactly the noarch one.
///
/// A storage error is treated as "not there", which degrades to the
/// originally requested key and lets the real handler produce the error.
async fn apk_key(
    state: &Arc<AppState>,
    repo: &str,
    channel: &str,
    arch: &str,
    file: &str,
) -> String {
    let key = format!("{}/{file}", silo_pkg::apk::arch_prefix(repo, channel, arch));
    if arch == silo_pkg::apk::NOARCH || state.storage.head(&key).await.unwrap_or(false) {
        return key;
    }

    let noarch = format!(
        "{}/{file}",
        silo_pkg::apk::arch_prefix(repo, channel, silo_pkg::apk::NOARCH)
    );
    if state.storage.head(&noarch).await.unwrap_or(false) {
        return noarch;
    }
    key
}

// ----------------------------------------------------------------- pacman

async fn get_pacman_file(
    State(state): State<Arc<AppState>>,
    Path((repo, channel, arch, file)): Path<(String, String, String, String)>,
    connect_info: Option<ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
) -> Response {
    let auth =
        match authorize_read(&state, &headers, remote_addr(connect_info.as_ref()), &repo).await {
            Ok(auth) => auth,
            Err(resp) => return resp,
        };
    if let Err(resp) = reject_traversal(&file) {
        return resp;
    }
    if let Err(resp) = reject_traversal(&arch) {
        return resp;
    }

    if let Some(object) = pacman_db_object(&file) {
        let key = pacman_key(&state, &repo, &channel, &arch, object).await;
        let content_type = if object.ends_with(".sig") {
            "application/octet-stream"
        } else {
            "application/gzip"
        };
        return serve_index(&state, &key, content_type, "pacman-db").await;
    }

    let key = pacman_key(&state, &repo, &channel, &arch, &file).await;
    serve_package(&state, &key, PackageFormat::Pacman, &auth, &repo, &channel).await
}

/// Maps a requested filename to the fixed database (or signature) object
/// name, regardless of what `[section]` name a client's `pacman.conf`
/// happens to use.
///
/// pacman always requests `$section.db` (occasionally `$section.db.tar.gz`
/// / `.tar.zst` / `.tar.xz` depending on client version), and `$section`
/// is a name only the client's config knows — silo cannot predict it, so
/// any filename with the right shape is treated as "the database".
fn pacman_db_object(file: &str) -> Option<&'static str> {
    let (base, is_sig) = match file.strip_suffix(".sig") {
        Some(base) => (base, true),
        None => (file, false),
    };
    let is_db = base.ends_with(".db")
        || base.ends_with(".db.tar.gz")
        || base.ends_with(".db.tar.zst")
        || base.ends_with(".db.tar.xz");
    if !is_db {
        return None;
    }
    Some(if is_sig {
        silo_pkg::pacman::DB_SIG_OBJECT
    } else {
        silo_pkg::pacman::DB_OBJECT
    })
}

/// Resolves a pacman request to a storage key, falling back to `any` —
/// the same reasoning as [`apk_key`], since pacman never asks for an
/// `any` tree of its own accord any more than apk asks for `noarch`.
async fn pacman_key(
    state: &Arc<AppState>,
    repo: &str,
    channel: &str,
    arch: &str,
    file: &str,
) -> String {
    let key = format!(
        "{}/{file}",
        silo_pkg::pacman::arch_prefix(repo, channel, arch)
    );
    if arch == silo_pkg::pacman::ANY || state.storage.head(&key).await.unwrap_or(false) {
        return key;
    }

    let any = format!(
        "{}/{file}",
        silo_pkg::pacman::arch_prefix(repo, channel, silo_pkg::pacman::ANY)
    );
    if state.storage.head(&any).await.unwrap_or(false) {
        return any;
    }
    key
}

// -------------------------------------------------------------------- npm

async fn get_npm(
    State(state): State<Arc<AppState>>,
    Path((repo, channel, path)): Path<(String, String, String)>,
    connect_info: Option<ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
) -> Response {
    let auth =
        match authorize_read(&state, &headers, remote_addr(connect_info.as_ref()), &repo).await {
            Ok(auth) => auth,
            Err(resp) => return resp,
        };
    if let Err(resp) = reject_traversal(&path) {
        return resp;
    }

    // npm URL-encodes the slash in a scoped name (`@acme%2fwidget`) when
    // requesting a packument, but not when requesting a tarball. Decoding
    // it here makes both spellings address the same package.
    let path = path.replace("%2f", "/").replace("%2F", "/");

    match parse_npm_path(&path) {
        Some(NpmRequest::Packument { name }) => {
            let key = format!(
                "{}/{}",
                silo_pkg::npm::package_prefix(&repo, &channel, &name),
                silo_pkg::npm::PACKUMENT_OBJECT
            );
            match state.storage.get(&key).await {
                Ok(Some(bytes)) => {
                    // Stored packuments carry a placeholder where the
                    // tarball host belongs; only now do we know what this
                    // client should be told to fetch from.
                    let base = state.base_url_for(&headers);
                    let bytes = silo_pkg::npm::substitute_base_url(&bytes, &base);
                    state
                        .metrics
                        .http_requests
                        .with_label_values(&["npm-index", "200"])
                        .inc();
                    (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "application/json")],
                        bytes,
                    )
                        .into_response()
                }
                Ok(None) => npm_not_found(&state),
                Err(e) => {
                    tracing::error!(error = %e, key, "failed to read packument");
                    (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
                }
            }
        }
        Some(NpmRequest::Tarball { name, file }) => {
            let key = format!(
                "{}/-/{file}",
                silo_pkg::npm::package_prefix(&repo, &channel, &name)
            );
            serve_package(&state, &key, PackageFormat::Npm, &auth, &repo, &channel).await
        }
        None => npm_not_found(&state),
    }
}

/// npm expects a JSON body on 404s and prints the `error` field verbatim.
fn npm_not_found(state: &AppState) -> Response {
    state
        .metrics
        .http_requests
        .with_label_values(&["npm-index", "404"])
        .inc();
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "application/json")],
        r#"{"error":"Not found"}"#,
    )
        .into_response()
}

/// npm's error envelope — the client prints `error` verbatim.
fn npm_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::json!({ "error": message }).to_string(),
    )
        .into_response()
}

/// The publish JSON body `npm publish`/`yarn publish` PUT to a package's
/// URL. Only `_attachments` is read — everything else (manifest fields,
/// `dist-tags`, `_id`) is re-derived from the tarball itself by
/// [`silo_pkg::npm::NpmFormat::parse`], so trusting client-sent copies of
/// it would just be an extra way for the two to disagree.
///
/// `data` borrows from the request body rather than owning a `String`: at
/// the size ceiling this envelope allows, an owned copy would mean two
/// multi-gigabyte buffers (the raw body and the copy) alive at once for no
/// reason, on top of the decoded bytes built from it a moment later.
#[derive(Deserialize)]
struct NpmPublishRequest<'a> {
    #[serde(default, rename = "_attachments", borrow)]
    attachments: BTreeMap<String, NpmAttachment<'a>>,
}

#[derive(Deserialize)]
struct NpmAttachment<'a> {
    #[serde(borrow)]
    data: &'a str,
}

/// Handles `PUT /:repo/:channel/npm/*path` — the wire protocol
/// `npm publish`/`yarn publish` speak. `path` is the package name (npm
/// puts it in the URL); it isn't otherwise consulted since the tarball's
/// own `package.json` is the source of truth for name and version, exactly
/// as it is for a publish that arrives over gRPC.
///
/// The body is read by hand with [`Request`], rather than a `Json<T>`
/// extractor, deliberately: extractors all run before the handler body
/// does, so a `Json<T>` argument would buffer and deserialize the whole
/// request — up to [`NPM_PUBLISH_BODY_LIMIT`] of it — before
/// `authorize_write` below ever runs, letting an unauthenticated caller
/// force that work on every request. Reading the body explicitly, after
/// the permission check, keeps that cost behind authorization the way the
/// gRPC handler's own check does before it reads a single byte off its
/// stream (`grpc.rs`).
async fn publish_npm(
    State(state): State<Arc<AppState>>,
    Path((repo, channel, path)): Path<(String, String, String)>,
    connect_info: Option<ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let auth =
        match authorize_write(&state, &headers, remote_addr(connect_info.as_ref()), &repo).await {
            Ok(auth) => auth,
            Err(resp) => return resp,
        };
    if let Err(resp) = reject_traversal(&path) {
        return resp;
    }

    let body_bytes = match axum::body::to_bytes(request.into_body(), NPM_PUBLISH_BODY_LIMIT).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return npm_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body exceeds the publish size limit",
            )
        }
    };
    let body: NpmPublishRequest = match serde_json::from_slice(&body_bytes) {
        Ok(body) => body,
        Err(_) => return npm_error(StatusCode::BAD_REQUEST, "invalid publish request body"),
    };

    let mut attachments = body.attachments.into_values();
    let attachment = match (attachments.next(), attachments.next()) {
        (Some(attachment), None) => attachment,
        (None, _) => return npm_error(StatusCode::BAD_REQUEST, "no attachment in publish request"),
        (Some(_), Some(_)) => {
            return npm_error(
                StatusCode::BAD_REQUEST,
                "only one attachment per publish is supported",
            )
        }
    };
    let bytes = match base64::engine::general_purpose::STANDARD.decode(attachment.data.as_bytes()) {
        Ok(bytes) => bytes,
        Err(_) => {
            return npm_error(
                StatusCode::BAD_REQUEST,
                "attachment data is not valid base64",
            )
        }
    };
    // The body-size layer only bounds the base64 text, which is ~33%
    // larger than what it decodes to — so a body under that ceiling can
    // still decode past `MAX_PACKAGE_BYTES`. Check the decoded size too,
    // same ceiling gRPC enforces on its raw chunks.
    if bytes.len() > MAX_PACKAGE_BYTES {
        return npm_error(
            StatusCode::BAD_REQUEST,
            &format!(
                "package exceeds the {} GiB upload limit",
                MAX_PACKAGE_BYTES / (1024 * 1024 * 1024)
            ),
        );
    }

    let started = Instant::now();
    let outcome = silo_core::repo::publish(
        &state.publish,
        &repo,
        &channel,
        PackageFormat::Npm,
        bytes,
        &auth.actor,
    )
    .await;

    let elapsed = started.elapsed().as_secs_f64();
    state
        .metrics
        .record_publish(PackageFormat::Npm.as_str(), outcome.is_ok(), elapsed);

    match outcome {
        Ok(outcome) => {
            state
                .metrics
                .http_requests
                .with_label_values(&["npm-publish", "200"])
                .inc();
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::json!({ "ok": true, "id": outcome.name, "rev": outcome.sha256 })
                    .to_string(),
            )
                .into_response()
        }
        Err(e) => {
            // A rejected publish leaves no other trace, so the audit log
            // is the only place it can be seen afterwards — mirrors the
            // gRPC handler's failure path.
            state
                .db
                .record_audit(
                    AuditEntry::new(audit::action::PACKAGE_PUBLISH, &auth.actor)
                        .repo(&repo)
                        .channel(&channel)
                        .detail(serde_json::json!({ "format": PackageFormat::Npm.as_str() }))
                        .failed(&e),
                )
                .await;
            publish_error_response(e)
        }
    }
}

/// Maps a [`classify_publish_error`] verdict to an HTTP status, same
/// classification the gRPC handler uses to pick a `Status`.
fn publish_error_response(error: anyhow::Error) -> Response {
    match classify_publish_error(&error) {
        PublishErrorKind::InvalidArgument => npm_error(StatusCode::BAD_REQUEST, &error.to_string()),
        PublishErrorKind::Timeout => npm_error(StatusCode::GATEWAY_TIMEOUT, &error.to_string()),
        // Unlike the two branches above, this one isn't the client's own
        // mistake — it's a storage/database failure, and its `Display`
        // can carry backend detail (connection strings, paths) a caller
        // has no business seeing. Full detail still reaches the log.
        PublishErrorKind::Internal => {
            tracing::error!(error = %error, "publish failed");
            npm_error(StatusCode::INTERNAL_SERVER_ERROR, "internal publish error")
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum NpmRequest {
    Packument { name: String },
    Tarball { name: String, file: String },
}

/// Splits an npm path into a packument or tarball request.
///
/// `/-/` is the separator npm puts between a package name and its tarball,
/// and it can't appear in a package name, so it's an unambiguous split
/// point even for scoped names.
fn parse_npm_path(path: &str) -> Option<NpmRequest> {
    let path = path.trim_matches('/');
    if path.is_empty() {
        return None;
    }

    if let Some((name, file)) = path.split_once("/-/") {
        if name.is_empty() || file.is_empty() || file.contains('/') {
            return None;
        }
        return Some(NpmRequest::Tarball {
            name: name.to_string(),
            file: file.to_string(),
        });
    }

    // A packument path is either `name` or `@scope/name`; anything deeper
    // is a registry API Silo doesn't implement.
    let segments: Vec<&str> = path.split('/').collect();
    match segments.as_slice() {
        [name] if !name.starts_with('@') => Some(NpmRequest::Packument {
            name: name.to_string(),
        }),
        [scope, name] if scope.starts_with('@') => Some(NpmRequest::Packument {
            name: format!("{scope}/{name}"),
        }),
        _ => None,
    }
}

/// Rejects path segments that would escape their prefix.
///
/// `object_store`'s `Path` normalizes away `..`, so this is defence in
/// depth rather than the only guard — but a request that contains `..` is
/// never legitimate, and refusing it outright is cheaper than reasoning
/// about what the normalizer does with it.
#[allow(clippy::result_large_err)]
fn reject_traversal(path: &str) -> Result<(), Response> {
    if path
        .split('/')
        .any(|segment| segment == ".." || segment == ".")
        || path.contains('\\')
    {
        return Err((StatusCode::BAD_REQUEST, "invalid path").into_response());
    }
    Ok(())
}

fn content_type_for(file: &str) -> &'static str {
    if file.ends_with(".xml") {
        "application/xml"
    } else if file.ends_with(".gz") {
        "application/gzip"
    } else if file.ends_with(".zst") {
        "application/zstd"
    } else if file.ends_with(".bz2") {
        "application/x-bzip2"
    } else if file.ends_with(".asc") {
        "text/plain"
    } else {
        "application/octet-stream"
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::metrics::Metrics;
    use axum::body::Body;
    use axum::http::Request;
    use base64::Engine;
    use silo_core::config::{
        AuditConfig, AuthConfig, Config, DatabaseConfig, MetricsConfig, SigningConfig,
        StorageConfig,
    };
    use silo_core::Storage;
    use tower::ServiceExt;

    /// A state whose database handle is never used.
    ///
    /// The routing, path-parsing, content-type and traversal logic tested
    /// here is entirely independent of the database; wiring one up would
    /// mean every one of these tests needed a live Postgres. Behaviour
    /// that *does* touch the database is covered by the integration tests,
    /// which take one.
    pub(crate) fn test_state_with(tweak: impl FnOnce(&mut Config)) -> AppState {
        let mut config = Config {
            addr: "127.0.0.1:0".into(),
            public_base_url: None,
            database: DatabaseConfig {
                url: "postgres://unused".into(),
                max_connections: 1,
                connect_timeout_seconds: 1,
            },
            storage: StorageConfig {
                bucket: "test".into(),
                endpoint: None,
                region: "us-east-1".into(),
                access_key_id: "x".into(),
                secret_access_key: "x".into(),
                allow_http: false,
            },
            auth: AuthConfig::default(),
            oidc: None,
            signing: SigningConfig::default(),
            audit: AuditConfig::default(),
            metrics: MetricsConfig::default(),
        };
        tweak(&mut config);

        let storage = Storage::in_memory();
        let db = silo_db::Db::from_pool(
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                // Never connected to: `connect_lazy` builds the pool
                // without touching the network, and no test in this module
                // issues a query.
                .connect_lazy("postgres://silo:silo@127.0.0.1:1/silo")
                .expect("build a lazy pool"),
        );

        AppState {
            publish: silo_core::PublishContext {
                storage: storage.clone(),
                db: db.clone(),
                signers: Default::default(),
                public_base_url: config.public_base_url.clone(),
            },
            config,
            storage,
            db,
            oidc: None,
            metrics: Metrics::new().expect("build metrics"),
        }
    }

    /// Like `test_state_with`, but with a real signing key loaded, so the
    /// key-serving endpoint is exercised against the same derivation the
    /// server does at startup rather than a stub.
    fn test_state_with_gpg(tweak: impl FnOnce(&mut Config)) -> AppState {
        let mut state = test_state_with(tweak);
        let signers = silo_core::Signers::from_config(&SigningConfig {
            gpg: Some(silo_core::config::GpgConfig {
                key: Some(silo_core::signing::TEST_GPG_SECRET_KEY.to_string()),
                key_path: None,
                passphrase: None,
            }),
            apk: None,
            pacman: None,
        })
        .expect("load the test signing key");
        state.publish.signers = signers;
        state
    }

    /// Like `test_state_with_gpg`, but loads the key under `signing.pacman`
    /// instead, so the pacman key-serving endpoint is exercised against a
    /// real key rather than a stub.
    fn test_state_with_pacman_key(tweak: impl FnOnce(&mut Config)) -> AppState {
        let mut state = test_state_with(tweak);
        let signers = silo_core::Signers::from_config(&SigningConfig {
            gpg: None,
            apk: None,
            pacman: Some(silo_core::config::GpgConfig {
                key: Some(silo_core::signing::TEST_GPG_SECRET_KEY.to_string()),
                key_path: None,
                passphrase: None,
            }),
        })
        .expect("load the test signing key");
        state.publish.signers = signers;
        state
    }

    /// A state that never touches the database — fine for routes that
    /// answer without a repo-level authorization check at all
    /// (`/healthz`, `/version`, the gpg key, `/metrics`).
    fn anonymous_state() -> Arc<AppState> {
        Arc::new(test_state_with(|cfg| {
            // The audit write would need a database; downloads in these
            // tests are about serving bytes, not about auditing.
            cfg.audit.log_downloads = false;
        }))
    }

    /// A state backed by a real database, with `myrepo` marked public.
    ///
    /// Every `/{repo}/{channel}/...` route now asks the database whether
    /// the repo is public before serving an unauthenticated request, so
    /// the tests that exercise that serving logic (content types, path
    /// traversal, redirect fallbacks, 404 shapes) need one — unlike the
    /// rest of this module, which deliberately never does (see
    /// `test_state_with`). The repo name is fixed and shared across
    /// tests: they only ever mark it public (idempotent), never private,
    /// and each test gets its own in-memory storage, so concurrent tests
    /// sharing the one test database can't interfere with each other.
    async fn test_db() -> Option<silo_db::Db> {
        let url = std::env::var("SILO_TEST_DATABASE_URL")
            .ok()
            .filter(|u| !u.trim().is_empty())?;
        Some(
            silo_db::Db::connect(&silo_db::DbConfig {
                url,
                max_connections: 4,
                connect_timeout: std::time::Duration::from_secs(30),
                token_pepper: None,
            })
            .await
            .expect("connect to the test database"),
        )
    }

    async fn public_myrepo_state() -> Option<Arc<AppState>> {
        let db = test_db().await?;
        db.set_repo_public("myrepo", true)
            .await
            .expect("mark the test repo public");

        let mut state = test_state_with(|cfg| cfg.audit.log_downloads = false);
        state.db = db.clone();
        state.publish.db = db;
        Some(Arc::new(state))
    }

    /// Skips (rather than fails) when there's no database to connect to,
    /// consistent with the integration suite's `require_db!`.
    macro_rules! require_public_repo_state {
        () => {
            match public_myrepo_state().await {
                Some(state) => state,
                None => {
                    eprintln!(
                        "skipping: set SILO_TEST_DATABASE_URL to run this database-backed test"
                    );
                    return;
                }
            }
        };
    }

    macro_rules! require_test_db {
        () => {
            match test_db().await {
                Some(db) => db,
                None => {
                    eprintln!(
                        "skipping: set SILO_TEST_DATABASE_URL to run this database-backed test"
                    );
                    return;
                }
            }
        };
    }

    async fn get(state: Arc<AppState>, uri: &str) -> Response {
        router(state)
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn body_string(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[tokio::test]
    async fn healthz_needs_no_credential() {
        let resp = get(anonymous_state(), "/healthz").await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn version_is_served_without_a_credential() {
        // An operator has to be able to ask what is running before they
        // have a token, and a `curl` against a locked-down registry is
        // exactly that situation — this route takes no credential at all,
        // regardless of any repo's mode.
        let state = Arc::new(test_state_with(|_| {}));
        let resp = get(state, "/version").await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
        assert_eq!(body["version"], silo_core::version::VERSION);
        assert!(!body["commit"].as_str().unwrap().is_empty());
        assert!(!body["built_at"].as_str().unwrap().is_empty());
        assert_eq!(
            body["formats"].as_array().unwrap().len(),
            PackageFormat::ALL.len(),
            "a client uses this to refuse a publish the server cannot index"
        );
    }

    #[tokio::test]
    async fn the_gpg_public_key_is_served_without_a_credential() {
        // dnf fetches `gpgkey=` outside the credentialed repo session, so
        // this endpoint has to answer before the client has proved
        // anything — it takes no credential at all.
        let state = Arc::new(test_state_with_gpg(|_| {}));

        let resp = get(state, "/RPM-GPG-KEY-silo").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/pgp-keys"
        );

        let body = body_string(resp).await;
        assert!(body.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        // The endpoint that hands out key material is the one place a
        // private-key leak would be catastrophic and silent.
        assert!(!body.contains("PRIVATE KEY"));
    }

    #[tokio::test]
    async fn the_gpg_public_key_is_404_when_no_key_is_configured() {
        // Not a 500 and not an empty 200: `gpgkey=` pointing at a server
        // that signs nothing is a misconfiguration the client should see
        // as "not there", which is what dnf reports usefully.
        let resp = get(anonymous_state(), "/RPM-GPG-KEY-silo").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn the_pacman_public_key_is_served_without_a_credential() {
        let state = Arc::new(test_state_with_pacman_key(|_| {}));

        let resp = get(state, "/pacman-signing-key").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/pgp-keys"
        );

        let body = body_string(resp).await;
        assert!(body.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assert!(!body.contains("PRIVATE KEY"));
    }

    #[tokio::test]
    async fn the_pacman_public_key_is_404_when_no_key_is_configured() {
        let resp = get(anonymous_state(), "/pacman-signing-key").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn metrics_are_served_when_enabled_and_hidden_when_not() {
        let resp = get(anonymous_state(), "/metrics").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_string(resp).await.contains("silo_"));

        let disabled = Arc::new(test_state_with(|cfg| cfg.metrics.enabled = false));
        let resp = get(disabled, "/metrics").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn metrics_can_be_put_behind_a_credential() {
        let state = Arc::new(test_state_with(|cfg| {
            cfg.metrics.require_auth = true;
        }));
        let resp = get(state, "/metrics").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_credential_less_read_of_a_private_repo_is_404_not_401() {
        // No credential is never an auth error by itself now — it's an
        // anonymous caller, and what an anonymous caller can reach is
        // decided per repo. A private repo has to look exactly like one
        // that doesn't exist, which rules out both 401 (that would
        // confirm "a credential would help here, so this repo is real")
        // and 403.
        let db = require_test_db!();
        let mut state = test_state_with(|cfg| cfg.audit.log_downloads = false);
        state.db = db.clone();
        state.publish.db = db;
        let repo = format!("private-{}", uuid::Uuid::new_v4().simple());

        let resp = get(
            Arc::new(state),
            &format!("/{repo}/stable/repodata/repomd.xml"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(!resp.headers().contains_key(header::WWW_AUTHENTICATE));
    }

    #[tokio::test]
    async fn a_bad_basic_password_is_rejected_before_touching_storage() {
        let state = Arc::new(test_state_with(|_| {}));
        let encoded = base64::engine::general_purpose::STANDARD.encode("silo:not-a-token");
        let resp = router(state)
            .oneshot(
                Request::builder()
                    .uri("/myrepo/stable/repodata/repomd.xml")
                    .header(header::AUTHORIZATION, format!("Basic {encoded}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Malformed token strings never reach the database.
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn an_unsupported_auth_scheme_is_rejected_not_treated_as_anonymous() {
        // This is rejected in `authenticate_http` itself, before any repo
        // is looked up — so unlike the rest of this module's repo-content
        // tests, no database is needed here. A header that was presented
        // but couldn't be understood must never be silently downgraded to
        // anonymous, which would hide a client's broken auth setup behind
        // a misleadingly successful response on a public repo.
        let state = Arc::new(test_state_with(|_| {}));
        let resp = router(state)
            .oneshot(
                Request::builder()
                    .uri("/myrepo/stable/repodata/repomd.xml")
                    .header(header::AUTHORIZATION, "Digest whatever")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn repodata_is_proxied_with_the_right_content_type() {
        let state = require_public_repo_state!();
        state
            .storage
            .put("myrepo/stable/repodata/repomd.xml", b"<repomd/>".to_vec())
            .await
            .unwrap();

        let resp = get(state, "/myrepo/stable/repodata/repomd.xml").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/xml"
        );
        assert_eq!(body_string(resp).await, "<repomd/>");
    }

    #[tokio::test]
    async fn missing_objects_are_404() {
        let state = require_public_repo_state!();
        let resp = get(state, "/myrepo/stable/repodata/repomd.xml").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn rpm_packages_fall_back_to_proxying_without_a_signer() {
        // The in-memory backend can't presign, which exercises the
        // proxy fallback that real S3 never takes.
        let state = require_public_repo_state!();
        state
            .storage
            .put(
                "myrepo/stable/Packages/foo-1.0-1.x86_64.rpm",
                b"rpmbytes".to_vec(),
            )
            .await
            .unwrap();

        let resp = get(state, "/myrepo/stable/Packages/foo-1.0-1.x86_64.rpm").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await, "rpmbytes");
    }

    #[tokio::test]
    async fn apk_index_and_packages_are_served_per_arch() {
        let state = require_public_repo_state!();
        state
            .storage
            .put(
                "myrepo/edge/apk/x86_64/APKINDEX.tar.gz",
                b"indexbytes".to_vec(),
            )
            .await
            .unwrap();
        state
            .storage
            .put(
                "myrepo/edge/apk/x86_64/hello-1.0-r0.apk",
                b"apkbytes".to_vec(),
            )
            .await
            .unwrap();

        let resp = get(state.clone(), "/myrepo/edge/apk/x86_64/APKINDEX.tar.gz").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/gzip"
        );
        assert_eq!(body_string(resp).await, "indexbytes");

        let resp = get(state.clone(), "/myrepo/edge/apk/x86_64/hello-1.0-r0.apk").await;
        assert_eq!(body_string(resp).await, "apkbytes");

        // A different arch is a different index and must not be served.
        let resp = get(state, "/myrepo/edge/apk/aarch64/APKINDEX.tar.gz").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn noarch_apk_content_is_served_under_whatever_arch_asks_for_it() {
        // apk-tools only ever requests $repo/$hostarch/..., so noarch
        // content has to answer under every architecture even though it is
        // stored once.
        let state = require_public_repo_state!();
        for (key, body) in [
            ("myrepo/edge/apk/noarch/APKINDEX.tar.gz", "noarch-index"),
            ("myrepo/edge/apk/noarch/portable-1.0-r0.apk", "noarch-apk"),
        ] {
            state
                .storage
                .put(key, body.as_bytes().to_vec())
                .await
                .unwrap();
        }

        // A channel with only noarch packages has no per-architecture
        // index, and the one it would have had is exactly the noarch one.
        let resp = get(state.clone(), "/myrepo/edge/apk/x86_64/APKINDEX.tar.gz").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await, "noarch-index");

        // The package itself is stored once, not copied per architecture.
        let resp = get(state.clone(), "/myrepo/edge/apk/x86_64/portable-1.0-r0.apk").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await, "noarch-apk");

        // The fallback must not invent content that exists nowhere.
        let resp = get(state.clone(), "/myrepo/edge/apk/x86_64/absent-1.0-r0.apk").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn an_architectures_own_index_wins_over_the_noarch_one() {
        // The fallback is a fallback: once an architecture has its own
        // index — which already includes the noarch packages — serving the
        // noarch one instead would hide that architecture's packages.
        let state = require_public_repo_state!();
        for (key, body) in [
            ("myrepo/edge/apk/noarch/APKINDEX.tar.gz", "noarch-index"),
            ("myrepo/edge/apk/x86_64/APKINDEX.tar.gz", "x86_64-index"),
        ] {
            state
                .storage
                .put(key, body.as_bytes().to_vec())
                .await
                .unwrap();
        }

        let resp = get(state.clone(), "/myrepo/edge/apk/x86_64/APKINDEX.tar.gz").await;
        assert_eq!(body_string(resp).await, "x86_64-index");

        // ...and noarch still serves itself.
        let resp = get(state, "/myrepo/edge/apk/noarch/APKINDEX.tar.gz").await;
        assert_eq!(body_string(resp).await, "noarch-index");
    }

    #[tokio::test]
    async fn pacman_db_and_packages_are_served_per_arch() {
        let state = require_public_repo_state!();
        state
            .storage
            .put("myrepo/edge/pacman/x86_64/db.tar.gz", b"dbbytes".to_vec())
            .await
            .unwrap();
        state
            .storage
            .put(
                "myrepo/edge/pacman/x86_64/hello-1.0-1-x86_64.pkg.tar.zst",
                b"pkgbytes".to_vec(),
            )
            .await
            .unwrap();

        // Whatever `[section]` name a client's pacman.conf uses, the fixed
        // database object answers for it.
        for requested in ["myrepo.db", "myrepo.db.tar.gz", "myrepo.db.tar.zst"] {
            let resp = get(
                state.clone(),
                &format!("/myrepo/edge/pacman/x86_64/{requested}"),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK, "{requested}");
            assert_eq!(
                resp.headers().get(header::CONTENT_TYPE).unwrap(),
                "application/gzip"
            );
            assert_eq!(body_string(resp).await, "dbbytes");
        }

        let resp = get(
            state.clone(),
            "/myrepo/edge/pacman/x86_64/hello-1.0-1-x86_64.pkg.tar.zst",
        )
        .await;
        assert_eq!(body_string(resp).await, "pkgbytes");

        // A different arch is a different database and must not be served.
        let resp = get(state, "/myrepo/edge/pacman/aarch64/myrepo.db").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn pacman_db_signature_is_served_alongside_the_database() {
        let state = require_public_repo_state!();
        state
            .storage
            .put(
                "myrepo/edge/pacman/x86_64/db.tar.gz.sig",
                b"sigbytes".to_vec(),
            )
            .await
            .unwrap();

        let resp = get(state, "/myrepo/edge/pacman/x86_64/myrepo.db.sig").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/octet-stream"
        );
        assert_eq!(body_string(resp).await, "sigbytes");
    }

    #[tokio::test]
    async fn any_pacman_content_is_served_under_whatever_arch_asks_for_it() {
        // Mirrors apk's `noarch` fallback: pacman only ever requests
        // $repo/$hostarch/..., so `any` content has to answer under every
        // architecture even though it is stored once.
        let state = require_public_repo_state!();
        for (key, body) in [
            ("myrepo/edge/pacman/any/db.tar.gz", "any-db"),
            (
                "myrepo/edge/pacman/any/portable-1.0-1-any.pkg.tar.zst",
                "any-pkg",
            ),
        ] {
            state
                .storage
                .put(key, body.as_bytes().to_vec())
                .await
                .unwrap();
        }

        let resp = get(state.clone(), "/myrepo/edge/pacman/x86_64/myrepo.db").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await, "any-db");

        let resp = get(
            state.clone(),
            "/myrepo/edge/pacman/x86_64/portable-1.0-1-any.pkg.tar.zst",
        )
        .await;
        assert_eq!(body_string(resp).await, "any-pkg");

        let resp = get(
            state,
            "/myrepo/edge/pacman/x86_64/absent-1.0-1-any.pkg.tar.zst",
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn npm_packument_gets_its_tarball_urls_rewritten() {
        let state = require_public_repo_state!();
        state
            .storage
            .put(
                "myrepo/stable/npm/widget/packument.json",
                br#"{"name":"widget","versions":{"1.0.0":{"dist":{"tarball":"__SILO_BASE_URL__/myrepo/stable/npm/widget/-/widget-1.0.0.tgz"}}}}"#.to_vec(),
            )
            .await
            .unwrap();

        let resp = router(state)
            .oneshot(
                Request::builder()
                    .uri("/myrepo/stable/npm/widget")
                    .header(header::HOST, "packages.example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(
            body.contains(
                "http://packages.example.com/myrepo/stable/npm/widget/-/widget-1.0.0.tgz"
            ),
            "got: {body}"
        );
        assert!(!body.contains("__SILO_BASE_URL__"));
    }

    #[tokio::test]
    async fn npm_scoped_packuments_work_encoded_and_unencoded() {
        let state = require_public_repo_state!();
        state
            .storage
            .put(
                "myrepo/stable/npm/@acme/widget/packument.json",
                br#"{"name":"@acme/widget"}"#.to_vec(),
            )
            .await
            .unwrap();

        for uri in [
            "/myrepo/stable/npm/@acme/widget",
            "/myrepo/stable/npm/@acme%2fwidget",
        ] {
            let resp = get(state.clone(), uri).await;
            assert_eq!(resp.status(), StatusCode::OK, "failed for {uri}");
            assert!(body_string(resp).await.contains("@acme/widget"));
        }
    }

    #[tokio::test]
    async fn npm_tarballs_are_served_from_the_dash_path() {
        let state = require_public_repo_state!();
        state
            .storage
            .put(
                "myrepo/stable/npm/@acme/widget/-/widget-1.0.0.tgz",
                b"tgzbytes".to_vec(),
            )
            .await
            .unwrap();

        let resp = get(state, "/myrepo/stable/npm/@acme/widget/-/widget-1.0.0.tgz").await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await, "tgzbytes");
    }

    #[tokio::test]
    async fn npm_404s_are_json_because_npm_parses_them() {
        let state = require_public_repo_state!();
        let resp = get(state, "/myrepo/stable/npm/nope").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert!(body_string(resp).await.contains("Not found"));
    }

    #[tokio::test]
    async fn path_traversal_is_refused() {
        let state = require_public_repo_state!();
        for uri in [
            "/myrepo/stable/repodata/../../../etc/passwd",
            "/myrepo/stable/Packages/..%2f..%2fsecret",
            "/myrepo/edge/apk/x86_64/../../other/APKINDEX.tar.gz",
        ] {
            let resp = get(state.clone(), uri).await;
            assert!(
                resp.status() == StatusCode::BAD_REQUEST || resp.status() == StatusCode::NOT_FOUND,
                "{uri} returned {}",
                resp.status()
            );
        }
    }

    #[test]
    fn package_redirects_are_302_not_307() {
        // apk-tools' fetcher does not follow 307, and the failure it
        // produces ("package mentioned in index not found") points at the
        // index rather than at the redirect. Pinning the status code here
        // keeps a future refactor to `Redirect::temporary` from silently
        // breaking `apk add`.
        let response = found_redirect("https://example.com/signed?sig=abc");
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "https://example.com/signed?sig=abc"
        );
    }

    #[test]
    fn a_presigned_url_that_cannot_be_a_header_fails_loudly() {
        let response = found_redirect("https://example.com/\nInjected: header");
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn npm_paths_split_into_packuments_and_tarballs() {
        assert_eq!(
            parse_npm_path("widget"),
            Some(NpmRequest::Packument {
                name: "widget".into()
            })
        );
        assert_eq!(
            parse_npm_path("@acme/widget"),
            Some(NpmRequest::Packument {
                name: "@acme/widget".into()
            })
        );
        assert_eq!(
            parse_npm_path("@acme/widget/-/widget-1.0.0.tgz"),
            Some(NpmRequest::Tarball {
                name: "@acme/widget".into(),
                file: "widget-1.0.0.tgz".into()
            })
        );
        assert_eq!(
            parse_npm_path("widget/-/widget-1.0.0.tgz"),
            Some(NpmRequest::Tarball {
                name: "widget".into(),
                file: "widget-1.0.0.tgz".into()
            })
        );
    }

    #[test]
    fn unsupported_npm_registry_paths_are_rejected() {
        assert_eq!(parse_npm_path(""), None);
        assert_eq!(parse_npm_path("/"), None);
        // `-/v1/search` and friends: real registry APIs Silo doesn't serve.
        assert_eq!(parse_npm_path("a/b/c"), None);
        assert_eq!(parse_npm_path("widget/-/nested/path.tgz"), None);
        assert_eq!(parse_npm_path("widget/-/"), None);
    }

    #[test]
    fn traversal_detection_covers_dot_segments_and_backslashes() {
        assert!(reject_traversal("repomd.xml").is_ok());
        assert!(reject_traversal("a/b/c.xml").is_ok());
        assert!(reject_traversal("../etc/passwd").is_err());
        assert!(reject_traversal("a/../../b").is_err());
        assert!(reject_traversal("./a").is_err());
        assert!(reject_traversal("a\\b").is_err());
    }

    #[test]
    fn content_types_match_what_dnf_expects() {
        assert_eq!(content_type_for("repomd.xml"), "application/xml");
        assert_eq!(content_type_for("primary.xml.gz"), "application/gzip");
        assert_eq!(content_type_for("primary.xml.zst"), "application/zstd");
        assert_eq!(content_type_for("repomd.xml.asc"), "text/plain");
        assert_eq!(content_type_for("mystery"), "application/octet-stream");
    }
}
