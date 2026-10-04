//! The Flatpak surface: an OSTree remote under `/{repo}/{ch}/ostree/`, the
//! `.flatpakrepo` and `.flatpakref` files that point clients at it, and the
//! write side a pushing client uses.
//!
//! Reads, which is all `flatpak` and `ostree` ever do:
//!
//! | path | what |
//! |---|---|
//! | `ostree/config`, `summary`, `summary.sig` | the index, proxied |
//! | `ostree/refs/heads/{ref}` | one ref's commit checksum, proxied |
//! | `ostree/objects/ab/cdef….{filez,dirtree,dirmeta,commit,commitmeta}` | an object, redirected to storage |
//! | `silo.flatpakrepo` | `flatpak remote-add` input |
//! | `flatpakref/{id}.flatpakref` | `flatpak install` input |
//!
//! Writes, which need a write credential:
//!
//! | request | what |
//! |---|---|
//! | `PUT ostree/objects/ab/cdef….ext` | upload one object, verified against its name |
//! | `POST ostree/missing` | which of these objects does the server lack |
//! | `POST ostree/refs` | point a ref at an uploaded commit |
//!
//! Only paths of exactly these shapes are served. An OSTree client asks for
//! plenty of things this server has no answer to — `summary.idx`, static
//! deltas, `summaries/` — and each of those is a plain 404, which clients
//! treat as "not available" and fall back from.
//!
//! Object downloads are neither audited nor counted individually: one app
//! install is thousands of requests, and a row each would bury everything
//! else in the audit log. The ref update that made them visible is audited.

use super::*;
use silo_pkg::flatpak;
use silo_pkg::ostree::delta::validate_ref;

/// Ceiling on the JSON body of `POST ostree/missing`. A listing of a large
/// runtime is a few hundred thousand names; this holds a few million.
const MISSING_BODY_LIMIT: usize = 256 * 1024 * 1024;

/// Ceiling on the JSON body of `POST ostree/refs`.
const REF_BODY_LIMIT: usize = 64 * 1024;

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found").into_response()
}

fn json_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::json!({ "error": message }).to_string(),
    )
        .into_response()
}

fn count(state: &AppState, surface: &str, response: &Response) {
    state
        .metrics
        .http_requests
        .with_label_values(&[surface, response.status().as_str()])
        .inc();
}

/// The address clients reach this server on: the configured public URL,
/// or failing that the `Host` they used.
fn public_base(state: &AppState, headers: &HeaderMap) -> String {
    if let Some(url) = &state.publish.public_base_url {
        return url.trim_end_matches('/').to_string();
    }
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");
    format!("http://{host}")
}

pub(super) async fn get_ostree(
    State(state): State<Arc<AppState>>,
    Path((repo, channel, file)): Path<(String, String, String)>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = validate_repo_path(&repo, &channel) {
        return resp;
    }
    if let Err(resp) = authorize_read(&state, &headers, remote_addr(&connect_info), &repo).await {
        return resp;
    }
    if let Err(resp) = reject_traversal(&file) {
        return resp;
    }

    let prefix = flatpak::ostree_prefix(&repo, &channel);
    let key = format!("{prefix}/{file}");
    let response = match file.as_str() {
        "summary" | "summary.sig" => {
            serve_mutable(&state, &key, "application/octet-stream", "flatpak-index").await
        }
        "config" => serve_mutable(&state, &key, "text/plain", "flatpak-index").await,
        f if f
            .strip_prefix("refs/heads/")
            .is_some_and(|r| validate_ref(r).is_ok()) =>
        {
            serve_mutable(&state, &key, "text/plain", "flatpak-ref").await
        }
        f if silo_core::ostree::is_served_object(f) => serve_object(&state, &key).await,
        _ => {
            let response = not_found();
            count(&state, "flatpak-index", &response);
            response
        }
    };
    response
}

/// Serves a file that changes when a ref moves: proxied, and never cached
/// past a revalidation, so a client sees a new commit as soon as there is
/// one.
async fn serve_mutable(state: &AppState, key: &str, content_type: &str, surface: &str) -> Response {
    let mut response = serve_index(state, key, content_type, surface).await;
    if response.status() == StatusCode::OK {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, "no-cache".parse().expect("static"));
    }
    response
}

/// Serves an immutable object: a redirect to a presigned URL when the
/// backend can sign one, the bytes otherwise.
async fn serve_object(state: &AppState, key: &str) -> Response {
    let response = match state.storage.head(key).await {
        Ok(true) => match state.storage.presigned_get_url(key).await {
            Ok(Some(url)) => {
                state
                    .metrics
                    .downloads
                    .with_label_values(&["flatpak", "redirect"])
                    .inc();
                found_redirect(&url)
            }
            Ok(None) => match state.storage.get(key).await {
                Ok(Some(bytes)) => {
                    state
                        .metrics
                        .downloads
                        .with_label_values(&["flatpak", "proxy"])
                        .inc();
                    (
                        StatusCode::OK,
                        [
                            (header::CONTENT_TYPE, "application/octet-stream"),
                            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
                        ],
                        bytes,
                    )
                        .into_response()
                }
                Ok(None) => not_found(),
                Err(e) => {
                    tracing::error!(error = %e, key, "failed to read an ostree object");
                    (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
                }
            },
            Err(e) => {
                tracing::error!(error = %e, key, "failed to presign an ostree object");
                (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
            }
        },
        Ok(false) => not_found(),
        Err(e) => {
            tracing::error!(error = %e, key, "failed to check an ostree object");
            (StatusCode::INTERNAL_SERVER_ERROR, "storage error").into_response()
        }
    };
    count(state, "flatpak-object", &response);
    response
}

pub(super) async fn put_ostree(
    State(state): State<Arc<AppState>>,
    Path((repo, channel, file)): Path<(String, String, String)>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
    request: Request,
) -> Response {
    if let Err(resp) = validate_repo_path(&repo, &channel) {
        return resp;
    }
    if let Err(resp) = authorize_write(&state, &headers, remote_addr(&connect_info), &repo).await {
        return resp;
    }
    let Some((ty, checksum)) = silo_core::ostree::object_from_path(&file) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "not the path of an uploadable object",
        );
    };
    let bytes = match axum::body::to_bytes(request.into_body(), MAX_PACKAGE_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "the object exceeds the upload limit",
            )
        }
    };

    let response = match silo_core::ostree::stage_object(
        &state.publish,
        &repo,
        &channel,
        ty,
        checksum,
        bytes.to_vec(),
    )
    .await
    {
        Ok(true) => StatusCode::CREATED.into_response(),
        Ok(false) => StatusCode::OK.into_response(),
        Err(e) => publish_error_response(e),
    };
    count(&state, "flatpak-upload", &response);
    response
}

#[derive(Deserialize)]
struct MissingRequest {
    objects: Vec<String>,
}

#[derive(Deserialize)]
struct RefRequest {
    #[serde(rename = "ref")]
    reference: String,
    commit: String,
}

pub(super) async fn post_ostree(
    State(state): State<Arc<AppState>>,
    Path((repo, channel, file)): Path<(String, String, String)>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
    request: Request,
) -> Response {
    if let Err(resp) = validate_repo_path(&repo, &channel) {
        return resp;
    }
    let auth = match authorize_write(&state, &headers, remote_addr(&connect_info), &repo).await {
        Ok(auth) => auth,
        Err(resp) => return resp,
    };
    match file.as_str() {
        "missing" => post_missing(&state, &repo, &channel, request).await,
        "refs" => post_ref(&state, &repo, &channel, &auth, request).await,
        _ => not_found(),
    }
}

async fn post_missing(state: &AppState, repo: &str, channel: &str, request: Request) -> Response {
    let body = match axum::body::to_bytes(request.into_body(), MISSING_BODY_LIMIT).await {
        Ok(body) => body,
        Err(_) => return json_error(StatusCode::PAYLOAD_TOO_LARGE, "the request is too large"),
    };
    let Ok(parsed) = serde_json::from_slice::<MissingRequest>(&body) else {
        return json_error(StatusCode::BAD_REQUEST, "invalid request body");
    };
    let mut wanted = Vec::with_capacity(parsed.objects.len());
    for path in &parsed.objects {
        match silo_core::ostree::object_from_path(path) {
            Some(object) => wanted.push(object),
            None => return json_error(StatusCode::BAD_REQUEST, "invalid object path in request"),
        }
    }

    let response =
        match silo_core::ostree::missing_objects(&state.publish, repo, channel, wanted).await {
            Ok(missing) => {
                let missing: Vec<String> = missing
                    .into_iter()
                    .map(|(ty, checksum)| ty.archive_path(&checksum))
                    .collect();
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/json")],
                    serde_json::json!({ "missing": missing }).to_string(),
                )
                    .into_response()
            }
            Err(e) => publish_error_response(e),
        };
    count(state, "flatpak-missing", &response);
    response
}

async fn post_ref(
    state: &AppState,
    repo: &str,
    channel: &str,
    auth: &Authenticated,
    request: Request,
) -> Response {
    let body = match axum::body::to_bytes(request.into_body(), REF_BODY_LIMIT).await {
        Ok(body) => body,
        Err(_) => return json_error(StatusCode::PAYLOAD_TOO_LARGE, "the request is too large"),
    };
    let Ok(parsed) = serde_json::from_slice::<RefRequest>(&body) else {
        return json_error(StatusCode::BAD_REQUEST, "invalid request body");
    };

    let started = Instant::now();
    let outcome = silo_core::ostree::publish_ref(
        &state.publish,
        repo,
        channel,
        &parsed.reference,
        &parsed.commit,
        &auth.actor,
    )
    .await;
    state.metrics.record_publish(
        PackageFormat::Flatpak.as_str(),
        outcome.is_ok(),
        started.elapsed().as_secs_f64(),
    );

    let response = match outcome {
        Ok(outcome) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::json!({
                "ref": parsed.reference,
                "commit": parsed.commit,
                "signed": outcome.signed,
                "index_objects": outcome.index_objects,
            })
            .to_string(),
        )
            .into_response(),
        Err(e) => {
            state
                .db
                .record_audit(
                    AuditEntry::new(audit::action::PACKAGE_PUBLISH, &auth.actor)
                        .repo(repo)
                        .channel(channel)
                        .target(&parsed.reference)
                        .detail(serde_json::json!({ "format": PackageFormat::Flatpak.as_str() }))
                        .failed(&e),
                )
                .await;
            publish_error_response(e)
        }
    };
    count(state, "flatpak-ref-update", &response);
    response
}

/// The public key a remote's signatures verify against, as the raw bytes
/// the `.flatpakrepo` format carries — `None` when no key is configured.
fn signing_key(state: &AppState) -> Option<&[u8]> {
    state
        .publish
        .signers
        .ostree
        .as_deref()
        .map(|s| s.binary_public_key())
}

pub(super) async fn get_flatpakrepo(
    State(state): State<Arc<AppState>>,
    Path((repo, channel)): Path<(String, String)>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = validate_repo_path(&repo, &channel) {
        return resp;
    }
    if let Err(resp) = authorize_read(&state, &headers, remote_addr(&connect_info), &repo).await {
        return resp;
    }
    let url = format!("{}/{repo}/{channel}/ostree", public_base(&state, &headers));
    let body =
        flatpak::render_flatpakrepo(&format!("silo {repo}/{channel}"), &url, signing_key(&state));
    let response = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/vnd.flatpak.repo")],
        body,
    )
        .into_response();
    count(&state, "flatpak-repo-file", &response);
    response
}

#[derive(Deserialize)]
pub(super) struct RefQuery {
    arch: Option<String>,
    branch: Option<String>,
}

pub(super) async fn get_flatpakref(
    State(state): State<Arc<AppState>>,
    Path((repo, channel, file)): Path<(String, String, String)>,
    axum::extract::Query(query): axum::extract::Query<RefQuery>,
    connect_info: MaybeConnectInfo,
    headers: HeaderMap,
) -> Response {
    if let Err(resp) = validate_repo_path(&repo, &channel) {
        return resp;
    }
    if let Err(resp) = authorize_read(&state, &headers, remote_addr(&connect_info), &repo).await {
        return resp;
    }
    let Some(id) = file.strip_suffix(".flatpakref") else {
        return not_found();
    };

    let rows = match state
        .db
        .list_packages(&repo, &channel, Some(PackageFormat::Flatpak))
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(error = %e, "failed to list flatpak refs");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
        }
    };

    // An id can be an app or a runtime, in several arches and branches.
    // A request narrows by `?arch=` and `?branch=`; left open it prefers
    // `stable`, then whatever sorts first.
    let wanted = [format!("app/{id}"), format!("runtime/{id}")];
    let mut candidates: Vec<_> = rows
        .iter()
        .filter(|r| wanted.contains(&r.name))
        .filter(|r| query.arch.as_deref().is_none_or(|a| r.arch == a))
        .filter(|r| query.branch.as_deref().is_none_or(|b| r.version == b))
        .collect();
    candidates.sort_by_key(|r| {
        (
            r.version != "stable",
            r.name.clone(),
            r.arch.clone(),
            r.version.clone(),
        )
    });
    let Some(row) = candidates.first() else {
        let response = not_found();
        count(&state, "flatpak-ref-file", &response);
        return response;
    };

    let reference = flatpak::join_ref(&row.name, &row.arch, &row.version);
    let base = public_base(&state, &headers);
    let url = format!("{base}/{repo}/{channel}/ostree");

    // When the app's runtime is published in this same remote, point the
    // ref at it: flatpak will not look for a runtime in the remote the ref
    // names, only in ones already configured or at `RuntimeRepo`.
    let runtime = flatpak::runtime_ref(row.metadata["metadata"].as_str().unwrap_or_default());
    let runtime_here = runtime.is_some_and(|r| {
        rows.iter()
            .any(|other| flatpak::join_ref(&other.name, &other.arch, &other.version) == r)
    });
    let runtime_repo = runtime_here.then(|| format!("{base}/{repo}/{channel}/silo.flatpakrepo"));

    let response = match flatpak::render_flatpakref(
        id,
        &reference,
        &url,
        signing_key(&state),
        runtime_repo.as_deref(),
    ) {
        Ok(body) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/vnd.flatpak.ref")],
            body,
        )
            .into_response(),
        Err(_) => not_found(),
    };
    count(&state, "flatpak-ref-file", &response);
    response
}
