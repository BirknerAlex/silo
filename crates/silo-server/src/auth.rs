//! Request authentication and authorization.
//!
//! One credential type — the database-backed token — reaches the server
//! through two different envelopes, because the clients Silo serves can't
//! agree on one:
//!
//! - **gRPC and npm** send `Authorization: Bearer <token>`.
//! - **dnf and apk** can only do HTTP Basic (`.repo` files have
//!   `username=`/`password=` fields; apk takes credentials in the URL).
//!   The token goes in the password field and the username is ignored.
//!
//! Both paths converge on [`authenticate`], so scope, permission, and
//! expiry are evaluated in exactly one place regardless of how the
//! credential arrived.

use std::sync::Arc;

use axum::http::{header, HeaderMap};
use base64::Engine;
use silo_db::audit::{Actor, ActorKind};
use silo_db::tokens::{AuthError, Permission, Token};
use tonic::{Request, Status};

use crate::AppState;

/// A successfully authenticated caller.
#[derive(Debug, Clone)]
pub struct Authenticated {
    /// `None` for anonymous readers, which only exist when
    /// `auth.allow_anonymous_read` is on.
    pub token: Option<Token>,
    pub actor: Actor,
}

impl Authenticated {
    pub fn anonymous(remote_addr: Option<String>) -> Self {
        Self {
            token: None,
            actor: Actor::anonymous(remote_addr),
        }
    }

    /// Whether this caller may act on `repo` at `required`.
    ///
    /// Anonymous callers can only ever read, and only because the operator
    /// turned that on — the anonymous branch never grants write, so a
    /// misconfiguration can't escalate past what it says on the tin.
    pub fn allows(&self, repo: &str, required: Permission) -> bool {
        match &self.token {
            Some(token) => token.allows(repo, required),
            None => required == Permission::Read,
        }
    }

    /// Admin permission is repo-independent — it governs tokens, users and
    /// the audit log, none of which belong to a repo.
    pub fn is_admin(&self) -> bool {
        self.token
            .as_ref()
            .map(|t| t.permission.satisfies(Permission::Admin))
            .unwrap_or(false)
    }

    pub fn describe(&self) -> String {
        match &self.token {
            Some(token) => token.name.clone(),
            None => "anonymous".to_string(),
        }
    }
}

/// Where a credential was found, so failures can say something useful.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialSource {
    Bearer,
    Basic,
    None,
}

/// Extracts a token from either envelope.
pub fn extract_credential(headers: &HeaderMap) -> (Option<String>, CredentialSource) {
    let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return (None, CredentialSource::None);
    };

    if let Some(token) = value.strip_prefix("Bearer ") {
        return (Some(token.trim().to_string()), CredentialSource::Bearer);
    }
    if let Some(encoded) = value.strip_prefix("Basic ") {
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
            return (None, CredentialSource::Basic);
        };
        let Ok(decoded) = String::from_utf8(decoded) else {
            return (None, CredentialSource::Basic);
        };
        // `user:password` — the username is decorative, the token is the
        // password. dnf and apk both send something in the username field
        // and neither lets you leave it out.
        let password = decoded.split_once(':').map(|(_, p)| p).unwrap_or("");
        if password.is_empty() {
            return (None, CredentialSource::Basic);
        }
        return (Some(password.to_string()), CredentialSource::Basic);
    }
    (None, CredentialSource::None)
}

/// Verifies a presented token and builds the [`Actor`] used for auditing.
pub async fn authenticate(
    state: &AppState,
    token: &str,
    remote_addr: Option<String>,
) -> Result<Authenticated, AuthError> {
    let pepper = state.config.auth.token_pepper.as_deref();
    let token = state.db.verify_token(token, pepper).await?;

    // Session tokens carry a user; API tokens don't. Naming the human in
    // the audit log rather than the token is worth the extra lookup on
    // what is, for session tokens, a low-frequency path.
    let (kind, name, user_id) = match token.user_id {
        Some(user_id) => {
            let username = state
                .db
                .find_user_by_id(user_id)
                .await
                .ok()
                .flatten()
                .map(|u| u.username)
                .unwrap_or_else(|| token.name.clone());
            (ActorKind::User, username, Some(user_id))
        }
        None => (ActorKind::Token, token.name.clone(), None),
    };

    Ok(Authenticated {
        actor: Actor {
            kind,
            name,
            token_id: Some(token.id),
            user_id,
            remote_addr,
        },
        token: Some(token),
    })
}

/// Authenticates an HTTP request, falling back to anonymous when the
/// server allows unauthenticated reads.
pub async fn authenticate_http(
    state: &AppState,
    headers: &HeaderMap,
    remote_addr: Option<String>,
) -> Result<Authenticated, AuthError> {
    let (credential, source) = extract_credential(headers);
    match credential {
        Some(token) => authenticate(state, &token, remote_addr).await,
        None if source == CredentialSource::None && state.config.auth.allow_anonymous_read => {
            Ok(Authenticated::anonymous(remote_addr))
        }
        None => Err(AuthError::Malformed),
    }
}

/// The credential and client address lifted out of a gRPC request.
///
/// Pulled out *before* awaiting anything, because a streaming request
/// isn't `Sync` — borrowing it across an `.await` would make every
/// handler's future non-`Send` and tonic wouldn't accept it.
pub struct GrpcCredential {
    token: String,
    remote_addr: Option<String>,
}

#[allow(clippy::result_large_err)]
pub fn extract_grpc_credential<T>(
    state: &AppState,
    request: &Request<T>,
) -> Result<GrpcCredential, Status> {
    let raw = request
        .metadata()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            state
                .metrics
                .auth_failures
                .with_label_values(&["missing"])
                .inc();
            Status::unauthenticated("missing authorization header")
        })?;

    let token = raw
        .strip_prefix("Bearer ")
        .ok_or_else(|| Status::unauthenticated("expected `Bearer <token>`"))?
        .trim()
        .to_string();

    Ok(GrpcCredential {
        token,
        remote_addr: request.remote_addr().map(|a| a.ip().to_string()),
    })
}

/// gRPC equivalent of [`authenticate_http`]. There is no anonymous branch:
/// every gRPC method either publishes, manages, or reads metadata, and
/// none of those are things an unauthenticated caller should reach.
pub async fn authenticate_grpc<T>(
    state: &Arc<AppState>,
    request: &Request<T>,
) -> Result<Authenticated, Status> {
    let credential = extract_grpc_credential(state, request)?;
    authenticate_credential(state, credential).await
}

pub async fn authenticate_credential(
    state: &Arc<AppState>,
    credential: GrpcCredential,
) -> Result<Authenticated, Status> {
    authenticate(state, &credential.token, credential.remote_addr)
        .await
        .map_err(|e| auth_error_to_status(state, e))
}

/// Maps an authentication failure onto a gRPC status, counting it by
/// reason on the way through. The messages distinguish *why* a token was
/// rejected — an expired token and an unknown one need very different
/// fixes, and neither reveals anything an attacker doesn't already know.
pub fn auth_error_to_status(state: &AppState, error: AuthError) -> Status {
    let reason = match &error {
        AuthError::Malformed => "malformed",
        AuthError::Unknown => "unknown",
        AuthError::Revoked => "revoked",
        AuthError::Expired(_) => "expired",
        AuthError::UserDisabled => "user_disabled",
        AuthError::Db(_) => "database",
    };
    state
        .metrics
        .auth_failures
        .with_label_values(&[reason])
        .inc();

    match error {
        AuthError::Db(e) => {
            tracing::error!(error = %e, "token verification failed against the database");
            Status::internal("authentication is temporarily unavailable")
        }
        other => Status::unauthenticated(other.to_string()),
    }
}

/// Enforces a permission on a repo, returning a gRPC status on refusal.
#[allow(clippy::result_large_err)] // Status is tonic's error type; boxing it here would just move the cost to callers
pub fn require_repo(auth: &Authenticated, repo: &str, required: Permission) -> Result<(), Status> {
    if auth.allows(repo, required) {
        return Ok(());
    }
    Err(Status::permission_denied(format!(
        "token `{}` lacks {required} access to repo `{repo}`",
        auth.describe()
    )))
}

#[allow(clippy::result_large_err)]
pub fn require_admin(auth: &Authenticated) -> Result<(), Status> {
    if auth.is_admin() {
        return Ok(());
    }
    Err(Status::permission_denied(
        "this operation requires an admin token",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use silo_db::tokens::{Scope, TokenKind};
    use uuid::Uuid;

    fn headers_with(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, value.parse().unwrap());
        headers
    }

    fn basic(user: &str, password: &str) -> String {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
        )
    }

    fn token(permission: Permission, scope: Scope) -> Token {
        Token {
            id: Uuid::nil(),
            name: "t".into(),
            prefix: "0".repeat(12),
            permission,
            kind: TokenKind::Api,
            scope,
            user_id: None,
            created_by: None,
            created_at: chrono::Utc::now(),
            expires_at: None,
            last_used_at: None,
            revoked_at: None,
        }
    }

    fn authed(permission: Permission, scope: Scope) -> Authenticated {
        Authenticated {
            token: Some(token(permission, scope)),
            actor: Actor::system(),
        }
    }

    #[test]
    fn bearer_credentials_are_extracted_verbatim() {
        let (token, source) = extract_credential(&headers_with("Bearer silo_abc_def"));
        assert_eq!(token.as_deref(), Some("silo_abc_def"));
        assert_eq!(source, CredentialSource::Bearer);
    }

    #[test]
    fn basic_credentials_take_the_password_and_ignore_the_username() {
        let (token, source) = extract_credential(&headers_with(&basic("silo", "silo_abc_def")));
        assert_eq!(token.as_deref(), Some("silo_abc_def"));
        assert_eq!(source, CredentialSource::Basic);

        // dnf users put anything in `username=`; it must not matter.
        let (other, _) = extract_credential(&headers_with(&basic("someone-else", "silo_abc_def")));
        assert_eq!(other.as_deref(), Some("silo_abc_def"));
    }

    #[test]
    fn a_basic_header_with_no_password_yields_no_credential() {
        let (token, source) = extract_credential(&headers_with(&basic("silo", "")));
        assert!(token.is_none());
        assert_eq!(source, CredentialSource::Basic);
    }

    #[test]
    fn malformed_and_missing_headers_yield_no_credential() {
        assert_eq!(
            extract_credential(&HeaderMap::new()).1,
            CredentialSource::None
        );
        assert!(extract_credential(&headers_with("Basic !!!not-base64"))
            .0
            .is_none());
        assert!(extract_credential(&headers_with("Digest whatever"))
            .0
            .is_none());
        assert!(extract_credential(&headers_with("Bearer "))
            .0
            .unwrap()
            .is_empty());
    }

    #[test]
    fn permission_and_scope_are_both_enforced() {
        let auth = authed(Permission::Write, Scope::Repos(vec!["myrepo".into()]));
        assert!(auth.allows("myrepo", Permission::Write));
        assert!(auth.allows("myrepo", Permission::Read));
        assert!(!auth.allows("myrepo", Permission::Admin));
        assert!(!auth.allows("other", Permission::Read));
    }

    #[test]
    fn anonymous_callers_can_only_ever_read() {
        let anon = Authenticated::anonymous(None);
        assert!(anon.allows("anything", Permission::Read));
        assert!(!anon.allows("anything", Permission::Write));
        assert!(!anon.allows("anything", Permission::Admin));
        assert!(!anon.is_admin());
        assert_eq!(anon.describe(), "anonymous");
    }

    #[test]
    fn admin_permission_is_repo_independent() {
        let admin = authed(Permission::Admin, Scope::Repos(vec!["only-this".into()]));
        assert!(admin.is_admin());
        // Scope still applies to repo operations even for an admin token.
        assert!(!admin.allows("other", Permission::Read));
        assert!(admin.allows("only-this", Permission::Admin));
    }

    #[test]
    fn require_helpers_produce_permission_denied() {
        let reader = authed(Permission::Read, Scope::All);
        assert!(require_repo(&reader, "r", Permission::Read).is_ok());

        let err = require_repo(&reader, "r", Permission::Write).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("write"));

        assert_eq!(
            require_admin(&reader).unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
        assert!(require_admin(&authed(Permission::Admin, Scope::All)).is_ok());
    }
}
