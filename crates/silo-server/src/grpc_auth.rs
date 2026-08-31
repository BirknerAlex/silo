//! The auth gRPC service: login and identity introspection.

use std::sync::Arc;

use silo_db::audit::{self, Actor, ActorKind, AuditEntry};
use silo_db::tokens::{NewToken, Permission, Scope, TokenKind};
use silo_db::users::{LoginError, OidcLoginError, User};
use silo_proto::v1::auth_service_server::AuthService;
use silo_proto::v1::{
    GetAuthInfoRequest, GetAuthInfoResponse, GetVersionRequest, GetVersionResponse,
    LoginOidcRequest, LoginOidcResponse, LoginRequest, LoginResponse, WhoAmIRequest,
    WhoAmIResponse,
};
use tonic::{Request, Response, Status};

use crate::auth;
use crate::AppState;

pub struct AuthServiceImpl {
    pub state: Arc<AppState>,
}

/// How long the login throttle's window is, and how many attempts it
/// tolerates within one. Set well above what a person fumbling a password
/// produces and far below what makes a dictionary attack worthwhile. A
/// successful sign-in clears the count, so only *failures* accumulate in
/// practice.
pub(crate) const LOGIN_FAILURE_WINDOW_MINUTES: i64 = 15;
const MAX_LOGIN_ATTEMPTS: i64 = 25;

/// Maps an OIDC provisioning failure onto a gRPC status.
///
/// The split is what the type exists for: a refusal was composed for the
/// person signing in and naming the blocking account is the only way they
/// can act on it, whereas a database failure is not their doing and its
/// `Display` carries whatever sqlx said — endpoints, connection strings.
/// Only the latter is redacted, and it still reaches the log in full.
#[allow(clippy::result_large_err)]
fn oidc_error_to_status(error: OidcLoginError) -> Status {
    match error {
        OidcLoginError::Db(e) => {
            tracing::error!(error = %e, "OIDC provisioning failed against the database");
            Status::unavailable("sign-in is temporarily unavailable")
        }
        refused => Status::permission_denied(refused.to_string()),
    }
}

/// This server's version, in wire form. Shared with the HTTP `/version`
/// endpoint so the two can't drift.
pub fn version_response() -> GetVersionResponse {
    let info = silo_core::BuildInfo::current();
    GetVersionResponse {
        version: info.version,
        commit: info.commit,
        built_at: info.built_at,
        formats: silo_pkg::PackageFormat::ALL
            .iter()
            .map(|f| f.as_str().to_string())
            .collect(),
    }
}

#[tonic::async_trait]
impl AuthService for AuthServiceImpl {
    /// Unauthenticated by design: the client has to be able to ask how to
    /// authenticate before it has a credential. The response contains only
    /// public OIDC client configuration — nothing here is a secret, and a
    /// client secret is deliberately never included.
    async fn get_auth_info(
        &self,
        _request: Request<GetAuthInfoRequest>,
    ) -> Result<Response<GetAuthInfoResponse>, Status> {
        let oidc = self.state.oidc.as_ref();
        let exclusive = oidc.map(|v| v.config().exclusive).unwrap_or(false);

        let result = Ok(Response::new(GetAuthInfoResponse {
            password_login_enabled: !exclusive,
            oidc_enabled: oidc.is_some(),
            oidc_issuer: oidc.map(|v| v.config().issuer.clone()).unwrap_or_default(),
            oidc_client_id: oidc
                .map(|v| v.config().client_id.clone())
                .unwrap_or_default(),
            oidc_scopes: oidc.map(|v| v.config().scopes.clone()).unwrap_or_default(),
            oidc_device_authorization_endpoint: oidc
                .and_then(|v| v.discovery().device_authorization_endpoint.clone())
                .unwrap_or_default(),
            oidc_token_endpoint: oidc
                .map(|v| v.discovery().token_endpoint.clone())
                .unwrap_or_default(),
            // Deprecated: the global switch this described has been
            // replaced by per-repo public/private mode. See
            // `ReadService::ListRepos`'s `RepoInfo.mode`.
            #[allow(deprecated)]
            anonymous_read_enabled: false,
        }));
        self.state.metrics.record_grpc("get_auth_info", &result);
        result
    }

    /// Also unauthenticated. Nothing here is sensitive: the version is
    /// already inferable from the server's behaviour, and hiding it buys
    /// no security while making version skew — a common cause of confusing
    /// failures — much harder to diagnose.
    async fn get_version(
        &self,
        _request: Request<GetVersionRequest>,
    ) -> Result<Response<GetVersionResponse>, Status> {
        let result = Ok(Response::new(version_response()));
        self.state.metrics.record_grpc("get_version", &result);
        result
    }

    async fn login(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<LoginResponse>, Status> {
        let result = self.login_inner(request).await;
        self.state.metrics.record_grpc("login", &result);
        result
    }

    async fn login_oidc(
        &self,
        request: Request<LoginOidcRequest>,
    ) -> Result<Response<LoginOidcResponse>, Status> {
        let result = self.login_oidc_inner(request).await;
        self.state.metrics.record_grpc("login_oidc", &result);
        result
    }

    async fn who_am_i(
        &self,
        request: Request<WhoAmIRequest>,
    ) -> Result<Response<WhoAmIResponse>, Status> {
        let result = self.who_am_i_inner(request).await;
        self.state.metrics.record_grpc("who_am_i", &result);
        result
    }
}

impl AuthServiceImpl {
    async fn login_inner(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<LoginResponse>, Status> {
        let remote_addr = request.remote_addr().map(|a| a.ip().to_string());
        let req = request.into_inner();

        if self
            .state
            .oidc
            .as_ref()
            .map(|v| v.config().exclusive)
            .unwrap_or(false)
        {
            return Err(Status::failed_precondition(
                "this server accepts only OIDC logins; run `silo login` without --password",
            ));
        }

        // Lowercased and trimmed to match what `find_user_by_username`
        // looks up. Counting the raw string instead would make `Alice`
        // and `alice` separate throttle keys for one account, and varying
        // the case is a one-line bypass.
        let username = req.username.trim().to_lowercase();

        // Password guessing is the one credential path in silo that a
        // brute force can actually make progress against — tokens carry
        // 256 bits of entropy, passwords do not — so the attempt rate has
        // to be bounded somewhere.
        //
        // Keyed on the username, which does mean someone can park a
        // targeted user at the ceiling and keep them out. That is the
        // better failure: the window is short and self-healing, an admin
        // token is unaffected, and the alternative (keying on client
        // address) is bypassed by the first attacker with more than one.
        // The attempt is *reserved* before the password is checked, not
        // counted afterwards. Counting after the fact bounds nothing under
        // concurrency: a thousand simultaneous attempts would each read
        // the same under-limit total, each spend argon2, and only then
        // record a thousand failures.
        match self
            .state
            .db
            .reserve_login_attempt(&username, LOGIN_FAILURE_WINDOW_MINUTES)
            .await
        {
            Ok(attempts) if attempts > MAX_LOGIN_ATTEMPTS => {
                self.state
                    .metrics
                    .auth_failures
                    .with_label_values(&["throttled"])
                    .inc();
                return Err(Status::resource_exhausted(
                    "too many failed sign-in attempts for this account; try again shortly",
                ));
            }
            Ok(_) => {}
            // A throttle that fails closed would turn a database blip into
            // a total sign-in outage. The attempt itself is still
            // authenticated normally below.
            Err(e) => tracing::warn!(error = %e, "could not reserve a login attempt"),
        }

        let user = match self
            .state
            .db
            .authenticate_password(&req.username, &req.password)
            .await
        {
            Ok(user) => user,
            Err(e) => {
                // Recorded under the same normalized name the throttle
                // counts, so the two agree. The audit entry keeps the
                // real reason; the client does not get it.
                self.record_failed_login(&username, &e.to_string(), remote_addr)
                    .await;
                return Err(match e {
                    LoginError::Db(e) => {
                        tracing::error!(error = %e, "login failed against the database");
                        Status::internal("login is temporarily unavailable")
                    }
                    // One message for every rejection. "No such user",
                    // "wrong password", "account disabled" and "this
                    // account is SSO-only" are all username oracles —
                    // the last two just less obviously so, since they
                    // confirm an account exists. A client that needs to
                    // know whether SSO is available asks `GetAuthInfo`,
                    // which answers without naming anybody.
                    _ => Status::unauthenticated("invalid username or password"),
                });
            }
        };

        // Proving you know the password clears the count, so a few typos
        // before a correct entry don't leave someone carrying reservations
        // for the rest of the window. Best-effort: failing to forget an
        // attempt must not fail a sign-in that already succeeded.
        if let Err(e) = self.state.db.clear_login_attempts(&username).await {
            tracing::warn!(error = %e, "could not clear the login attempt count");
        }

        Ok(Response::new(
            self.issue_session(user, "password", remote_addr).await?,
        ))
    }

    async fn login_oidc_inner(
        &self,
        request: Request<LoginOidcRequest>,
    ) -> Result<Response<LoginOidcResponse>, Status> {
        let remote_addr = request.remote_addr().map(|a| a.ip().to_string());
        let req = request.into_inner();

        let verifier = self
            .state
            .oidc
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("this server has no OIDC configured"))?;

        let claims = match verifier.verify(&req.id_token).await {
            Ok(claims) => claims,
            Err(e) => {
                self.record_failed_login("(oidc)", &e.to_string(), remote_addr)
                    .await;
                return Err(Status::unauthenticated(e.to_string()));
            }
        };

        let username = claims.username(&verifier.config().username_claim);
        let user = self
            .state
            .db
            .upsert_oidc_user(
                &claims.sub,
                &username,
                claims.is_admin(verifier.config()),
                verifier.config().allow_username_linking,
            )
            .await
            .map_err(|e| {
                self.state
                    .metrics
                    .auth_failures
                    .with_label_values(&["oidc_provisioning"])
                    .inc();
                oidc_error_to_status(e)
            })?;

        // The same session, reported through this flow's own message. The
        // two are field-identical today; keeping them separate is what
        // lets either grow a field later without imposing it on the other.
        let session = self.issue_session(user, "oidc", remote_addr).await?;
        Ok(Response::new(LoginOidcResponse {
            token: session.token,
            username: session.username,
            is_admin: session.is_admin,
            expires_at: session.expires_at,
        }))
    }

    async fn who_am_i_inner(
        &self,
        request: Request<WhoAmIRequest>,
    ) -> Result<Response<WhoAmIResponse>, Status> {
        let authenticated = auth::authenticate_grpc(&self.state, &request).await?;
        let token = authenticated
            .token
            .as_ref()
            .ok_or_else(|| Status::unauthenticated("no token presented"))?;

        let (all_repos, repos) = match &token.scope {
            Scope::All => (true, Vec::new()),
            Scope::Repos(repos) => (false, repos.clone()),
        };

        Ok(Response::new(WhoAmIResponse {
            token_name: token.name.clone(),
            username: if authenticated.actor.kind == ActorKind::User {
                authenticated.actor.name.clone()
            } else {
                String::new()
            },
            permission: token.permission.as_str().to_string(),
            repos,
            all_repos,
            expires_at: token.expires_at.map(|t| t.timestamp()).unwrap_or(0),
            is_admin: authenticated.is_admin(),
        }))
    }

    /// Mints the session token a successful login hands back.
    ///
    /// Session tokens are scoped to all repos and carry the user's own
    /// permission level, so `silo login` gives a person exactly what they
    /// have rather than a second, independently-managed grant. They expire
    /// on their own — that's what keeps a laptop's stale credential from
    /// being valid forever.
    async fn issue_session(
        &self,
        user: User,
        method: &str,
        remote_addr: Option<String>,
    ) -> Result<LoginResponse, Status> {
        let ttl = chrono::Duration::hours(self.state.config.auth.session_ttl_hours);
        let expires_at = chrono::Utc::now() + ttl;

        let issued = self
            .state
            .db
            .create_token(
                NewToken {
                    name: format!("session:{}", user.username),
                    permission: if user.is_admin {
                        Permission::Admin
                    } else {
                        Permission::Write
                    },
                    kind: TokenKind::Session,
                    scope: Scope::All,
                    user_id: Some(user.id),
                    created_by: Some(user.id),
                    expires_at: Some(expires_at),
                },
                self.state.config.auth.token_pepper.as_deref(),
            )
            .await
            .map_err(|e| Status::internal(format!("failed to issue a session token: {e}")))?;

        let actor = Actor {
            kind: ActorKind::User,
            name: user.username.clone(),
            token_id: Some(issued.token.id),
            user_id: Some(user.id),
            remote_addr,
        };
        self.state
            .db
            .record_audit(
                AuditEntry::new(audit::action::AUTH_LOGIN, &actor)
                    .target(&user.username)
                    .detail(serde_json::json!({
                        "method": method,
                        "expires_at": expires_at.to_rfc3339(),
                    })),
            )
            .await;

        Ok(LoginResponse {
            token: issued.secret,
            username: user.username,
            is_admin: user.is_admin,
            expires_at: expires_at.timestamp(),
        })
    }

    async fn record_failed_login(&self, username: &str, reason: &str, remote_addr: Option<String>) {
        self.state
            .metrics
            .auth_failures
            .with_label_values(&["login"])
            .inc();
        self.state
            .db
            .record_audit(
                AuditEntry::new(audit::action::AUTH_FAILED, &Actor::anonymous(remote_addr))
                    .target(username)
                    .failed(reason),
            )
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn service() -> AuthServiceImpl {
        AuthServiceImpl {
            state: Arc::new(crate::http::tests::test_state_with(|_| {})),
        }
    }

    #[tokio::test]
    async fn a_successful_rpc_is_counted_by_method_and_ok() {
        let svc = service();
        let resp = svc.get_version(Request::new(GetVersionRequest {})).await;
        assert!(resp.is_ok());
        assert_eq!(
            svc.state
                .metrics
                .grpc_requests
                .with_label_values(&["get_version", "ok"])
                .get(),
            1
        );
    }

    #[tokio::test]
    async fn a_rejected_rpc_is_counted_by_method_and_error() {
        // `who_am_i` needs no database for an anonymous (no-credential)
        // caller — it's rejected in-process by `authenticate_grpc` before
        // any lookup, which is what keeps this test DB-free.
        let svc = service();
        let resp = svc.who_am_i(Request::new(WhoAmIRequest {})).await;
        assert_eq!(resp.unwrap_err().code(), tonic::Code::Unauthenticated);
        assert_eq!(
            svc.state
                .metrics
                .grpc_requests
                .with_label_values(&["who_am_i", "error"])
                .get(),
            1
        );
    }

    #[test]
    fn a_database_failure_during_oidc_provisioning_is_not_described_to_the_caller() {
        // `sqlx::Error`'s Display routinely names the host, the database,
        // and sometimes the credentials used to reach it. A caller who
        // merely tried to sign in must not receive any of it.
        let status = oidc_error_to_status(OidcLoginError::Db(sqlx::Error::PoolTimedOut));
        assert_eq!(status.code(), tonic::Code::Unavailable);
        assert_eq!(status.message(), "sign-in is temporarily unavailable");
    }

    #[test]
    fn a_refused_link_still_tells_the_caller_what_to_do_about_it() {
        // The other half: these messages exist to be read. Redacting them
        // too would leave someone locked out with nothing to act on.
        let status = oidc_error_to_status(OidcLoginError::UsernameTaken("admin".into()));
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert!(status.message().contains("admin"), "{}", status.message());
        assert!(
            status.message().contains("allow_username_linking"),
            "the refusal has to name the setting that changes it"
        );

        let status = oidc_error_to_status(OidcLoginError::AlreadyLinked("alice".into()));
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert!(status.message().contains("already linked"));

        // A race is transient, so it says to retry rather than reading as
        // a permanent refusal.
        let status = oidc_error_to_status(OidcLoginError::RacedAnotherLogin("bob".into()));
        assert!(
            status.message().contains("try again"),
            "{}",
            status.message()
        );
    }
}
