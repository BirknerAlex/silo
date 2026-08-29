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
    /// `None` for a caller that presented no credential at all. Any
    /// gRPC or HTTP request may arrive this way now; what an anonymous
    /// caller can actually do is decided per repo (see [`require_repo`]
    /// and `http::authorize_read`), not here.
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

    /// Whether this caller's *token* grants `required` on `repo`.
    ///
    /// This is scope-and-permission only — it says nothing about a repo's
    /// public bit. A caller with no token always gets `false` here; a
    /// public repo's unauthenticated-read allowance is layered on
    /// separately by [`require_repo`] and `http::authorize_read`, which
    /// both need a database lookup this method has no access to.
    pub fn allows(&self, repo: &str, required: Permission) -> bool {
        match &self.token {
            Some(token) => token.allows(repo, required),
            None => false,
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

/// Authenticates an HTTP request. A request with no credential at all
/// becomes an anonymous caller rather than an error — what that caller
/// can actually reach is decided per repo by the caller of this function
/// (see `authorize_read`), not here. A credential that *was* presented but
/// doesn't parse (garbled Basic, an empty Bearer) still errors: silently
/// downgrading that to anonymous would hide a client misconfiguration.
pub async fn authenticate_http(
    state: &AppState,
    headers: &HeaderMap,
    remote_addr: Option<String>,
) -> Result<Authenticated, AuthError> {
    let (credential, source) = extract_credential(headers);
    match credential {
        Some(token) => authenticate(state, &token, remote_addr).await,
        None if source == CredentialSource::None => Ok(Authenticated::anonymous(remote_addr)),
        None => Err(AuthError::Malformed),
    }
}

/// The credential and client address lifted out of a gRPC request.
///
/// Pulled out *before* awaiting anything, because a streaming request
/// isn't `Sync` — borrowing it across an `.await` would make every
/// handler's future non-`Send` and tonic wouldn't accept it.
pub struct GrpcCredential {
    /// `None` when the request carried no `authorization` metadata at
    /// all — that's an anonymous caller, not an error.
    token: Option<String>,
    remote_addr: Option<String>,
}

#[allow(clippy::result_large_err)]
pub fn extract_grpc_credential<T>(
    _state: &AppState,
    request: &Request<T>,
) -> Result<GrpcCredential, Status> {
    let remote_addr = request.remote_addr().map(|a| a.ip().to_string());
    let raw = request
        .metadata()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    let token = match raw {
        Some(raw) => Some(
            raw.strip_prefix("Bearer ")
                .ok_or_else(|| Status::unauthenticated("expected `Bearer <token>`"))?
                .trim()
                .to_string(),
        ),
        None => None,
    };

    Ok(GrpcCredential { token, remote_addr })
}

/// gRPC equivalent of [`authenticate_http`]. A request with no credential
/// becomes an anonymous caller rather than an error, same reasoning as
/// the HTTP side: what it can reach is decided per repo, downstream.
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
    match credential.token {
        Some(token) => authenticate(state, &token, credential.remote_addr)
            .await
            .map_err(|e| auth_error_to_status(state, e)),
        None => Ok(Authenticated::anonymous(credential.remote_addr)),
    }
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
///
/// A repo's public bit only ever widens `Read` for a caller whose token
/// wouldn't otherwise reach it — it never affects `Write`/`Admin`, and it
/// never *replaces* the token check for `Read` either, so a token with
/// real scope still gets the ordinary answer.
///
/// A `Read` refusal reports `NotFound` rather than `PermissionDenied`,
/// deliberately: a private repo and one that doesn't exist have to look
/// identical to a caller without access, or the status code itself would
/// leak which repos exist. `Write`/`Admin` refusals stay
/// `PermissionDenied`, unchanged.
#[allow(clippy::result_large_err)] // Status is tonic's error type; boxing it here would just move the cost to callers
pub async fn require_repo(
    state: &AppState,
    auth: &Authenticated,
    repo: &str,
    required: Permission,
) -> Result<(), Status> {
    if auth.allows(repo, required) {
        return Ok(());
    }
    if required == Permission::Read {
        let public = state
            .db
            .is_repo_public(repo)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        if public {
            return Ok(());
        }
        return Err(Status::not_found(format!("no repo `{repo}`")));
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
    fn a_token_less_caller_never_gets_a_yes_from_allows() {
        // `allows` is scope-and-permission only now; a public repo's
        // unauthenticated-read allowance is layered on separately by
        // `require_repo`, exercised below.
        let anon = Authenticated::anonymous(None);
        assert!(!anon.allows("anything", Permission::Read));
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

    #[tokio::test]
    async fn require_helpers_produce_permission_denied() {
        // Neither branch below reaches the database: a scoped `Read`
        // succeeds via `allows` alone, and a scoped-out `Write` is
        // rejected before any repo lookup — see `require_repo`.
        let state = crate::http::tests::test_state_with(|_| {});
        let reader = authed(Permission::Read, Scope::All);
        assert!(require_repo(&state, &reader, "r", Permission::Read)
            .await
            .is_ok());

        let err = require_repo(&state, &reader, "r", Permission::Write)
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(err.message().contains("write"));

        assert_eq!(
            require_admin(&reader).unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
        assert!(require_admin(&authed(Permission::Admin, Scope::All)).is_ok());
    }

    /// The database-backed half of `require_repo`'s behaviour: whether a
    /// repo is public. Needs a real database because it's the one branch
    /// that queries one.
    #[tokio::test]
    async fn require_repo_falls_back_to_the_public_bit_for_reads_only() {
        let Ok(url) = std::env::var("SILO_TEST_DATABASE_URL") else {
            eprintln!("skipping: set SILO_TEST_DATABASE_URL");
            return;
        };
        if url.trim().is_empty() {
            eprintln!("skipping: set SILO_TEST_DATABASE_URL");
            return;
        }
        let db = silo_db::Db::connect(&silo_db::DbConfig {
            url,
            max_connections: 4,
            connect_timeout: std::time::Duration::from_secs(30),
            token_pepper: None,
        })
        .await
        .expect("connect to the test database");

        let mut state = crate::http::tests::test_state_with(|_| {});
        state.db = db.clone();
        state.publish.db = db.clone();

        let repo = format!("require-repo-{}", uuid::Uuid::new_v4().simple());
        let outsider = authed(Permission::Read, Scope::Repos(vec!["other".into()]));

        // Private (no row at all yet): an out-of-scope read is refused as
        // NotFound, not PermissionDenied — it must be indistinguishable
        // from a repo that doesn't exist.
        let err = require_repo(&state, &outsider, &repo, Permission::Read)
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);

        // An out-of-scope write stays PermissionDenied regardless.
        let err = require_repo(&state, &outsider, &repo, Permission::Write)
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        db.set_repo_public(&repo, true).await.unwrap();

        // Public: the same out-of-scope reader can now read...
        assert!(require_repo(&state, &outsider, &repo, Permission::Read)
            .await
            .is_ok());
        // ...but still cannot write. Public never grants write.
        let err = require_repo(&state, &outsider, &repo, Permission::Write)
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        // A token that already had write scope keeps it, public or not.
        let writer = authed(Permission::Write, Scope::Repos(vec![repo.clone()]));
        assert!(require_repo(&state, &writer, &repo, Permission::Write)
            .await
            .is_ok());
    }
}
