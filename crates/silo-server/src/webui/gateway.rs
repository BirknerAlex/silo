//! `POST /admin/api/rpc/{Method}`: the gRPC services, as JSON.
//!
//! The body is the request message as JSON and the response is the
//! response message as JSON, with the field names and enum integers the
//! `.proto` files define. Failures come back as the matching HTTP status
//! and `{"code": "<grpc code>", "message": "..."}`.
//!
//! Each call builds a `tonic::Request` carrying the caller's
//! `Authorization` header and peer address and invokes the service trait
//! method directly. There is no separate authorization layer here, by
//! design: the service implementations already decide who may do what, and
//! a second opinion would be a second thing to keep in step with them.
//!
//! Only unary methods are exposed. `Publish` streams a package upload and
//! is not part of the console.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::de::DeserializeOwned;
use serde::Serialize;
use silo_proto::v1::admin_service_server::AdminService;
use silo_proto::v1::auth_service_server::AuthService;
use silo_proto::v1::read_service_server::ReadService;
use tonic::Code;

use crate::admin::AdminServiceImpl;
use crate::grpc::ReadServiceImpl;
use crate::grpc_auth::AuthServiceImpl;
use crate::AppState;

/// Ceiling on a request body. The largest legitimate message is an
/// upstream definition or a handful of repo names.
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// How long a client has to send the request body.
const BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub(super) async fn rpc(
    State(state): State<Arc<AppState>>,
    Path(method): Path<String>,
    request: Request,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| *addr);
    let headers = request.headers().clone();
    let body = match tokio::time::timeout(
        BODY_TIMEOUT,
        axum::body::to_bytes(request.into_body(), MAX_BODY_BYTES),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(_)) => {
            return error(
                Code::InvalidArgument,
                format!("request body exceeds {MAX_BODY_BYTES} bytes"),
            )
        }
        Err(_) => {
            return error(
                Code::DeadlineExceeded,
                "timed out reading the request".into(),
            )
        }
    };

    match dispatch(&state, &method, &headers, peer, &body).await {
        Ok(json) => no_store(json),
        Err(status) => error(status.code(), status.message().to_string()),
    }
}

pub(super) fn no_store(body: Vec<u8>) -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}

pub(super) fn error(code: Code, message: String) -> Response {
    let body = serde_json::json!({ "code": code_name(code), "message": message });
    (
        http_status(code),
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body.to_string(),
    )
        .into_response()
}

/// The conventional gRPC-to-HTTP mapping.
pub(crate) fn http_status(code: Code) -> StatusCode {
    match code {
        Code::Ok => StatusCode::OK,
        Code::InvalidArgument | Code::FailedPrecondition | Code::OutOfRange => {
            StatusCode::BAD_REQUEST
        }
        Code::Unauthenticated => StatusCode::UNAUTHORIZED,
        Code::PermissionDenied => StatusCode::FORBIDDEN,
        Code::NotFound => StatusCode::NOT_FOUND,
        Code::AlreadyExists | Code::Aborted => StatusCode::CONFLICT,
        Code::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
        Code::Cancelled => StatusCode::from_u16(499).unwrap_or(StatusCode::BAD_REQUEST),
        Code::Unimplemented => StatusCode::NOT_IMPLEMENTED,
        Code::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        Code::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
        Code::Unknown | Code::Internal | Code::DataLoss => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn code_name(code: Code) -> &'static str {
    match code {
        Code::Ok => "ok",
        Code::Cancelled => "cancelled",
        Code::Unknown => "unknown",
        Code::InvalidArgument => "invalid_argument",
        Code::DeadlineExceeded => "deadline_exceeded",
        Code::NotFound => "not_found",
        Code::AlreadyExists => "already_exists",
        Code::PermissionDenied => "permission_denied",
        Code::ResourceExhausted => "resource_exhausted",
        Code::FailedPrecondition => "failed_precondition",
        Code::Aborted => "aborted",
        Code::OutOfRange => "out_of_range",
        Code::Unimplemented => "unimplemented",
        Code::Internal => "internal",
        Code::Unavailable => "unavailable",
        Code::DataLoss => "data_loss",
        Code::Unauthenticated => "unauthenticated",
    }
}

/// Builds the `tonic::Request` a gRPC client would have sent.
///
/// The peer address goes in as the extension tonic's own transport would
/// set, so the audit log records the browser's address exactly as it
/// records the CLI's.
#[allow(clippy::result_large_err)]
fn build_request<T: DeserializeOwned>(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    body: &Bytes,
) -> Result<tonic::Request<T>, tonic::Status> {
    let message: T = if body.iter().all(u8::is_ascii_whitespace) {
        serde_json::from_slice(b"{}").expect("an empty object is a valid message")
    } else {
        serde_json::from_slice(body)
            .map_err(|e| tonic::Status::invalid_argument(format!("malformed request: {e}")))?
    };

    let mut request = tonic::Request::new(message);
    if let Some(value) = headers.get(header::AUTHORIZATION) {
        // `to_str` rejects non-visible-ASCII, which tonic metadata would
        // refuse as well.
        let value = value
            .to_str()
            .ok()
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| tonic::Status::unauthenticated("malformed Authorization header"))?;
        request.metadata_mut().insert("authorization", value);
    }
    if let Some(addr) = peer {
        request
            .extensions_mut()
            .insert(tonic::transport::server::TcpConnectInfo {
                local_addr: None,
                remote_addr: Some(addr),
            });
    }
    Ok(request)
}

#[allow(clippy::result_large_err)]
fn encode<T: Serialize>(response: tonic::Response<T>) -> Result<Vec<u8>, tonic::Status> {
    serde_json::to_vec(response.get_ref())
        .map_err(|e| tonic::Status::internal(format!("could not encode the response: {e}")))
}

/// Routes one method name to its service. A macro because the three
/// service traits share no common type to be generic over.
macro_rules! call {
    ($svc:expr, $method:ident, $headers:expr, $peer:expr, $body:expr) => {{
        let request = build_request($headers, $peer, $body)?;
        encode($svc.$method(request).await?)
    }};
}

async fn dispatch(
    state: &Arc<AppState>,
    method: &str,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    body: &Bytes,
) -> Result<Vec<u8>, tonic::Status> {
    let auth = AuthServiceImpl {
        state: state.clone(),
    };
    let read = ReadServiceImpl {
        state: state.clone(),
    };
    let admin = AdminServiceImpl {
        state: state.clone(),
    };

    match method {
        // AuthService
        "GetAuthInfo" => call!(auth, get_auth_info, headers, peer, body),
        "GetVersion" => call!(auth, get_version, headers, peer, body),
        "Login" => call!(auth, login, headers, peer, body),
        "LoginOidc" => call!(auth, login_oidc, headers, peer, body),
        "WhoAmI" => call!(auth, who_am_i, headers, peer, body),
        // ReadService
        "ListRepos" => call!(read, list_repos, headers, peer, body),
        "ListPackages" => call!(read, list_packages, headers, peer, body),
        // AdminService
        "CreateToken" => call!(admin, create_token, headers, peer, body),
        "ListTokens" => call!(admin, list_tokens, headers, peer, body),
        "RevokeToken" => call!(admin, revoke_token, headers, peer, body),
        "CreateUser" => call!(admin, create_user, headers, peer, body),
        "ListUsers" => call!(admin, list_users, headers, peer, body),
        "SetUserDisabled" => call!(admin, set_user_disabled, headers, peer, body),
        "DeleteUser" => call!(admin, delete_user, headers, peer, body),
        "SetUserPassword" => call!(admin, set_user_password, headers, peer, body),
        "QueryAudit" => call!(admin, query_audit, headers, peer, body),
        "RebuildIndex" => call!(admin, rebuild_index, headers, peer, body),
        "DeletePackage" => call!(admin, delete_package, headers, peer, body),
        "SetRepoMode" => call!(admin, set_repo_mode, headers, peer, body),
        "CreateRepo" => call!(admin, create_repo, headers, peer, body),
        "DeleteRepo" => call!(admin, delete_repo, headers, peer, body),
        "SetPruneRule" => call!(admin, set_prune_rule, headers, peer, body),
        "ClearPruneRule" => call!(admin, clear_prune_rule, headers, peer, body),
        "GetPruneRule" => call!(admin, get_prune_rule, headers, peer, body),
        "SetPruneExemption" => call!(admin, set_prune_exemption, headers, peer, body),
        "ListPruneExemptions" => call!(admin, list_prune_exemptions, headers, peer, body),
        "RunPrune" => call!(admin, run_prune, headers, peer, body),
        "AddUpstream" => call!(admin, add_upstream, headers, peer, body),
        "UpdateUpstream" => call!(admin, update_upstream, headers, peer, body),
        "RemoveUpstream" => call!(admin, remove_upstream, headers, peer, body),
        "ListUpstreams" => call!(admin, list_upstreams, headers, peer, body),
        "SyncUpstream" => call!(admin, sync_upstream, headers, peer, body),
        "GetStats" => call!(admin, get_stats, headers, peer, body),
        "GetServerInfo" => call!(admin, get_server_info, headers, peer, body),
        other => Err(tonic::Status::not_found(format!(
            "no such method `{other}`"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grpc_codes_map_onto_the_conventional_http_statuses() {
        assert_eq!(http_status(Code::Unauthenticated), StatusCode::UNAUTHORIZED);
        assert_eq!(http_status(Code::PermissionDenied), StatusCode::FORBIDDEN);
        assert_eq!(http_status(Code::NotFound), StatusCode::NOT_FOUND);
        assert_eq!(http_status(Code::AlreadyExists), StatusCode::CONFLICT);
        assert_eq!(
            http_status(Code::ResourceExhausted),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(http_status(Code::InvalidArgument), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn an_empty_body_is_an_empty_message() {
        let request: tonic::Request<silo_proto::v1::ListUsersRequest> =
            build_request(&HeaderMap::new(), None, &Bytes::new()).unwrap();
        assert_eq!(request.get_ref(), &silo_proto::v1::ListUsersRequest {});
    }

    #[test]
    fn omitted_fields_take_their_protobuf_defaults() {
        let body = Bytes::from_static(br#"{"name":"ci","permission":"read"}"#);
        let request: tonic::Request<silo_proto::v1::CreateTokenRequest> =
            build_request(&HeaderMap::new(), None, &body).unwrap();
        let message = request.into_inner();
        assert_eq!(message.name, "ci");
        assert!(message.repos.is_empty());
        assert_eq!(message.expires_at, 0);
    }

    #[test]
    fn the_authorization_header_becomes_grpc_metadata() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer abc".parse().unwrap());
        let request: tonic::Request<silo_proto::v1::WhoAmIRequest> =
            build_request(&headers, None, &Bytes::new()).unwrap();
        assert_eq!(
            request.metadata().get("authorization").unwrap(),
            "Bearer abc"
        );
    }

    #[test]
    fn the_peer_address_reaches_the_service() {
        let peer: SocketAddr = "192.0.2.7:4000".parse().unwrap();
        let request: tonic::Request<silo_proto::v1::WhoAmIRequest> =
            build_request(&HeaderMap::new(), Some(peer), &Bytes::new()).unwrap();
        assert_eq!(request.remote_addr(), Some(peer));
    }

    #[test]
    fn a_malformed_body_is_an_invalid_argument() {
        let err = build_request::<silo_proto::v1::CreateTokenRequest>(
            &HeaderMap::new(),
            None,
            &Bytes::from_static(b"{not json"),
        )
        .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }
}
