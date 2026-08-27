//! The auth gRPC service: login and identity introspection.

use std::sync::Arc;

use silo_db::audit::{self, Actor, ActorKind, AuditEntry};
use silo_db::tokens::{NewToken, Permission, Scope, TokenKind};
use silo_db::users::{LoginError, User};
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

        Ok(Response::new(GetAuthInfoResponse {
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
            anonymous_read_enabled: self.state.config.auth.allow_anonymous_read,
        }))
    }

    /// Also unauthenticated. Nothing here is sensitive: the version is
    /// already inferable from the server's behaviour, and hiding it buys
    /// no security while making version skew — a common cause of confusing
    /// failures — much harder to diagnose.
    async fn get_version(
        &self,
        _request: Request<GetVersionRequest>,
    ) -> Result<Response<GetVersionResponse>, Status> {
        Ok(Response::new(version_response()))
    }

    async fn login(
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

        let user = match self
            .state
            .db
            .authenticate_password(&req.username, &req.password)
            .await
        {
            Ok(user) => user,
            Err(e) => {
                self.record_failed_login(&req.username, &e.to_string(), remote_addr)
                    .await;
                return Err(match e {
                    LoginError::Db(e) => {
                        tracing::error!(error = %e, "login failed against the database");
                        Status::internal("login is temporarily unavailable")
                    }
                    // Deliberately not distinguishing "no such user" from
                    // "wrong password" — that difference is a username
                    // oracle and nothing legitimate needs it.
                    other => Status::unauthenticated(other.to_string()),
                });
            }
        };

        Ok(Response::new(
            self.issue_session(user, "password", remote_addr).await?,
        ))
    }

    async fn login_oidc(
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
            .upsert_oidc_user(&claims.sub, &username, claims.is_admin(verifier.config()))
            .await
            .map_err(|e| Status::permission_denied(e.to_string()))?;

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

    async fn who_am_i(
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
}

impl AuthServiceImpl {
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
