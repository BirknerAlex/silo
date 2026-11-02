//! The OIDC device authorization grant, relayed for the browser.
//!
//! `silo login --oidc` runs this flow from the CLI directly against the
//! identity provider. A page served from silo cannot: providers do not
//! send CORS headers on their device and token endpoints. So the console
//! asks silo to make the two requests, and silo makes them with the
//! `client_id` and endpoints it already holds for ID-token verification,
//! and with the `client_secret` when the provider needs one.
//!
//! What this relay never does is take the user's word for who they are.
//! The person signs in at the provider; the ID token that comes back goes
//! through `AuthService::LoginOidc`, which verifies its signature, issuer,
//! audience and expiry and provisions the user exactly as it does for the
//! CLI.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, Request, State};
use axum::response::Response;
use serde::{Deserialize, Serialize};
use silo_proto::v1::auth_service_server::AuthService;
use tokio::sync::Semaphore;
use tonic::Code;

use super::gateway::{error, no_store};
use crate::grpc_auth::AuthServiceImpl;
use crate::AppState;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How many relay requests may be in flight to the identity provider at
/// once. The routes take no credential, so without a ceiling anyone who can
/// reach the port could hold an unbounded number of outbound connections
/// open for the full request timeout. Past it, callers get 429 and the
/// console retries on its next poll.
const MAX_IN_FLIGHT: usize = 16;
static IN_FLIGHT: Semaphore = Semaphore::const_new(MAX_IN_FLIGHT);

fn busy() -> Response {
    error(
        Code::ResourceExhausted,
        "too many sign-in requests are in progress; try again shortly".into(),
    )
}
const MAX_BODY_BYTES: usize = 16 * 1024;

#[derive(Debug, Deserialize)]
struct DeviceAuthorization {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    interval: Option<u64>,
}

/// What the browser needs to show the code and poll for completion.
#[derive(Debug, Serialize)]
struct DeviceStart {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    expires_in: u64,
    interval: u64,
}

#[derive(Debug, Deserialize)]
struct PollRequest {
    device_code: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Pending,
    SlowDown,
    Done(String),
    Failed(String),
}

/// Interprets one poll of the token endpoint. `authorization_pending` and
/// `slow_down` mean "keep going"; any other error ends the flow.
fn classify(response: &TokenResponse) -> Outcome {
    if let Some(error) = &response.error {
        return match error.as_str() {
            "authorization_pending" => Outcome::Pending,
            "slow_down" => Outcome::SlowDown,
            other => Outcome::Failed(
                response
                    .error_description
                    .clone()
                    .unwrap_or_else(|| other.to_string()),
            ),
        };
    }
    match &response.id_token {
        Some(token) => Outcome::Done(token.clone()),
        None => Outcome::Failed(
            "the identity provider returned no id_token; is the `openid` scope configured?"
                .to_string(),
        ),
    }
}

fn json<T: Serialize>(value: &T) -> Response {
    no_store(serde_json::to_vec(value).unwrap_or_default())
}

/// `POST /admin/api/oidc/device`
pub(super) async fn start(State(state): State<Arc<AppState>>) -> Response {
    let Ok(_permit) = IN_FLIGHT.try_acquire() else {
        return busy();
    };
    let Some(verifier) = state.oidc.as_ref() else {
        return error(
            Code::FailedPrecondition,
            "this server has no OIDC configured".into(),
        );
    };
    let Some(endpoint) = verifier.discovery().device_authorization_endpoint.clone() else {
        return error(
            Code::FailedPrecondition,
            "this server's identity provider does not advertise a device authorization \
             endpoint, so the console cannot offer single sign-on. Sign in with a password \
             or an API token instead."
                .into(),
        );
    };
    let config = verifier.config();
    let scopes = if config.scopes.is_empty() {
        "openid".to_string()
    } else {
        config.scopes.join(" ")
    };

    let mut form = vec![
        ("client_id", config.client_id.as_str()),
        ("scope", scopes.as_str()),
    ];
    // A confidential client authenticates at the device endpoint too.
    if let Some(secret) = config.client_secret.as_deref() {
        form.push(("client_secret", secret));
    }
    let response = state
        .upstream_http
        .post(&endpoint)
        .timeout(REQUEST_TIMEOUT)
        .form(&form)
        .send()
        .await;
    let response = match response {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            tracing::warn!(status = %r.status(), "the identity provider rejected a device request");
            return error(
                Code::Unavailable,
                format!(
                    "the identity provider rejected the device request (HTTP {})",
                    r.status()
                ),
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "device authorization request failed");
            return error(
                Code::Unavailable,
                "could not reach the identity provider".into(),
            );
        }
    };
    let authorization: DeviceAuthorization = match response.json().await {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(error = %e, "device authorization response was malformed");
            return error(
                Code::Unavailable,
                "the device authorization response was malformed".into(),
            );
        }
    };

    json(&DeviceStart {
        device_code: authorization.device_code,
        user_code: authorization.user_code,
        verification_uri: authorization.verification_uri,
        verification_uri_complete: authorization.verification_uri_complete,
        expires_in: authorization.expires_in.unwrap_or(600),
        interval: authorization.interval.unwrap_or(5),
    })
}

/// `POST /admin/api/oidc/token` with `{"device_code": "..."}`.
///
/// Answers `{"status": "pending" | "slow_down"}` while the person has not
/// finished, `{"status": "ok", "session": {...}}` once they have, and an
/// ordinary error body otherwise.
pub(super) async fn poll(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let Ok(_permit) = IN_FLIGHT.try_acquire() else {
        return busy();
    };
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| *addr);
    let body = match axum::body::to_bytes(request.into_body(), MAX_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => return error(Code::InvalidArgument, "request body is too large".into()),
    };
    let poll: PollRequest = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return error(Code::InvalidArgument, format!("malformed request: {e}")),
    };
    if poll.device_code.is_empty() {
        return error(Code::InvalidArgument, "device_code is required".into());
    }

    let Some(verifier) = state.oidc.as_ref() else {
        return error(
            Code::FailedPrecondition,
            "this server has no OIDC configured".into(),
        );
    };
    let config = verifier.config();
    let mut form = vec![
        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ("device_code", poll.device_code.as_str()),
        ("client_id", config.client_id.as_str()),
    ];
    if let Some(secret) = config.client_secret.as_deref() {
        form.push(("client_secret", secret));
    }
    let response = state
        .upstream_http
        .post(&verifier.discovery().token_endpoint)
        .timeout(REQUEST_TIMEOUT)
        .form(&form)
        .send()
        .await;
    let token: TokenResponse = match response {
        // Providers answer a still-pending poll with HTTP 400 and a JSON
        // body, so the status code carries no information here.
        Ok(r) => match r.json().await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(error = %e, "token response was malformed");
                return error(Code::Unavailable, "the token response was malformed".into());
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, "token request failed");
            return error(
                Code::Unavailable,
                "could not reach the identity provider".into(),
            );
        }
    };

    match classify(&token) {
        Outcome::Pending => json(&serde_json::json!({ "status": "pending" })),
        Outcome::SlowDown => json(&serde_json::json!({ "status": "slow_down" })),
        Outcome::Failed(message) => error(Code::Unauthenticated, message),
        Outcome::Done(id_token) => {
            let mut login = tonic::Request::new(silo_proto::v1::LoginOidcRequest { id_token });
            if let Some(addr) = peer {
                login
                    .extensions_mut()
                    .insert(tonic::transport::server::TcpConnectInfo {
                        local_addr: None,
                        remote_addr: Some(addr),
                    });
            }
            let service = AuthServiceImpl {
                state: state.clone(),
            };
            match service.login_oidc(login).await {
                Ok(session) => json(&serde_json::json!({
                    "status": "ok",
                    "session": session.into_inner(),
                })),
                Err(status) => error(status.code(), status.message().to_string()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(error: Option<&str>, id_token: Option<&str>) -> TokenResponse {
        TokenResponse {
            id_token: id_token.map(String::from),
            error: error.map(String::from),
            error_description: None,
        }
    }

    #[test]
    fn pending_and_slow_down_mean_keep_polling() {
        assert_eq!(
            classify(&response(Some("authorization_pending"), None)),
            Outcome::Pending
        );
        assert_eq!(
            classify(&response(Some("slow_down"), None)),
            Outcome::SlowDown
        );
    }

    #[test]
    fn an_id_token_completes_the_flow() {
        assert_eq!(
            classify(&response(None, Some("jwt"))),
            Outcome::Done("jwt".into())
        );
    }

    #[test]
    fn terminal_errors_stop_the_flow_and_prefer_the_description() {
        assert!(matches!(
            classify(&response(Some("access_denied"), None)),
            Outcome::Failed(_)
        ));
        let described = TokenResponse {
            id_token: None,
            error: Some("invalid_client".into()),
            error_description: Some("device flow is not enabled".into()),
        };
        assert_eq!(
            classify(&described),
            Outcome::Failed("device flow is not enabled".into())
        );
    }

    #[test]
    fn a_success_without_an_id_token_names_the_likely_cause() {
        let Outcome::Failed(message) = classify(&response(None, None)) else {
            panic!("expected a failure");
        };
        assert!(message.contains("openid"), "{message}");
    }
}
