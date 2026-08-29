//! The admin gRPC service: tokens, users, audit, and index repair.
//!
//! Every method requires an admin token. The service is exposed over gRPC
//! rather than a separate HTTP admin API so there is exactly one auth
//! path, one audit path, and one client (`silo`) to keep in sync.

use std::sync::Arc;

use silo_db::audit::{self, ActorKind, AuditEntry, AuditQuery};
use silo_db::tokens::{NewToken, Permission, Scope, TokenKind};
use silo_db::users::User;
use silo_db::Uuid;
use silo_pkg::PackageFormat;
use silo_proto::v1::admin_service_server::AdminService;
use silo_proto::v1::{
    AuditEntry as ProtoAuditEntry, CreateTokenRequest, CreateTokenResponse, CreateUserRequest,
    CreateUserResponse, DeletePackageRequest, DeletePackageResponse, DeleteUserRequest,
    DeleteUserResponse, ListTokensRequest, ListTokensResponse, ListUsersRequest, ListUsersResponse,
    QueryAuditRequest, QueryAuditResponse, RebuildIndexRequest, RebuildIndexResponse, RepoMode,
    RevokeTokenRequest, RevokeTokenResponse, SetRepoModeRequest, SetRepoModeResponse,
    SetUserDisabledRequest, SetUserDisabledResponse, SetUserPasswordRequest,
    SetUserPasswordResponse, TokenInfo, TokenScope as ProtoScope, UserInfo,
};
use tonic::{Request, Response, Status};

use crate::auth;
use crate::grpc::from_proto_format;
use crate::AppState;

pub struct AdminServiceImpl {
    pub state: Arc<AppState>,
}

#[tonic::async_trait]
impl AdminService for AdminServiceImpl {
    async fn create_token(
        &self,
        request: Request<CreateTokenRequest>,
    ) -> Result<Response<CreateTokenResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_admin(&caller)?;
        let req = request.into_inner();

        if req.name.trim().is_empty() {
            return Err(Status::invalid_argument("token name is required"));
        }
        let permission: Permission = req
            .permission
            .parse()
            .map_err(|e: anyhow::Error| Status::invalid_argument(e.to_string()))?;

        let scope = match ProtoScope::try_from(req.scope).unwrap_or(ProtoScope::Unspecified) {
            ProtoScope::All => Scope::All,
            // Requiring at least one repo is what stops `--scope repos`
            // with no `--repo` from quietly minting a token that can
            // reach nothing and looks broken later.
            ProtoScope::Repos | ProtoScope::Unspecified if !req.repos.is_empty() => {
                for repo in &req.repos {
                    silo_core::config::validate_repo_name("repo", repo)
                        .map_err(|e| Status::invalid_argument(e.to_string()))?;
                }
                Scope::Repos(req.repos.clone())
            }
            _ => {
                return Err(Status::invalid_argument(
                    "a repo-scoped token needs at least one repo; use scope=all for every repo",
                ))
            }
        };

        // An admin must not be able to hand out access they don't have
        // themselves — otherwise a repo-scoped admin token is a privilege
        // escalation waiting to happen.
        if let Some(caller_token) = &caller.token {
            let covered = match &scope {
                Scope::All => matches!(caller_token.scope, Scope::All),
                Scope::Repos(repos) => repos.iter().all(|r| caller_token.scope.covers(r)),
            };
            if !covered {
                return Err(Status::permission_denied(
                    "cannot create a token with a wider repo scope than your own",
                ));
            }
        }

        let expires_at = timestamp_to_datetime(req.expires_at);
        if let Some(expires_at) = expires_at {
            if expires_at <= chrono::Utc::now() {
                return Err(Status::invalid_argument("expiry is in the past"));
            }
        }

        let issued = self
            .state
            .db
            .create_token(
                NewToken {
                    name: req.name.trim().to_string(),
                    permission,
                    kind: TokenKind::Api,
                    scope,
                    user_id: None,
                    created_by: caller.actor.user_id,
                    expires_at,
                },
                self.state.config.auth.token_pepper.as_deref(),
            )
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        self.state
            .db
            .record_audit(
                AuditEntry::new(audit::action::TOKEN_CREATE, &caller.actor)
                    .target(&issued.token.name)
                    .detail(serde_json::json!({
                        "permission": permission.as_str(),
                        "scope": issued.token.scope.describe(),
                        "expires_at": expires_at.map(|t| t.to_rfc3339()),
                        "prefix": issued.token.prefix,
                    })),
            )
            .await;

        Ok(Response::new(CreateTokenResponse {
            token: issued.secret,
            info: Some(token_info(&issued.token)),
        }))
    }

    async fn list_tokens(
        &self,
        request: Request<ListTokensRequest>,
    ) -> Result<Response<ListTokensResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_admin(&caller)?;
        let req = request.into_inner();

        let tokens = self
            .state
            .db
            .list_tokens(req.include_revoked)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(ListTokensResponse {
            tokens: tokens.iter().map(token_info).collect(),
        }))
    }

    async fn revoke_token(
        &self,
        request: Request<RevokeTokenRequest>,
    ) -> Result<Response<RevokeTokenResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_admin(&caller)?;
        let req = request.into_inner();

        let token = if !req.id.is_empty() {
            let id = Uuid::parse_str(&req.id)
                .map_err(|_| Status::invalid_argument("id is not a valid UUID"))?;
            self.state
                .db
                .list_tokens(true)
                .await
                .map_err(|e| Status::internal(e.to_string()))?
                .into_iter()
                .find(|t| t.id == id)
        } else if !req.name.is_empty() {
            self.state
                .db
                .find_token_by_name(&req.name)
                .await
                .map_err(|e| Status::internal(e.to_string()))?
        } else {
            return Err(Status::invalid_argument("provide either an id or a name"));
        };

        let Some(token) = token else {
            return Ok(Response::new(RevokeTokenResponse { revoked: false }));
        };

        let revoked = self
            .state
            .db
            .revoke_token(token.id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        if revoked {
            self.state
                .db
                .record_audit(
                    AuditEntry::new(audit::action::TOKEN_REVOKE, &caller.actor)
                        .target(&token.name)
                        .detail(serde_json::json!({ "prefix": token.prefix })),
                )
                .await;
        }

        Ok(Response::new(RevokeTokenResponse { revoked }))
    }

    async fn create_user(
        &self,
        request: Request<CreateUserRequest>,
    ) -> Result<Response<CreateUserResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_admin(&caller)?;
        let req = request.into_inner();

        let password = Some(req.password.as_str()).filter(|p| !p.is_empty());
        let user = self
            .state
            .db
            .create_user(&req.username, password, req.is_admin)
            .await
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        self.state
            .db
            .record_audit(
                AuditEntry::new(audit::action::USER_CREATE, &caller.actor)
                    .target(&user.username)
                    .detail(serde_json::json!({
                        "is_admin": user.is_admin,
                        "oidc_only": user.is_oidc_only(),
                    })),
            )
            .await;

        Ok(Response::new(CreateUserResponse {
            user: Some(user_info(&user)),
        }))
    }

    async fn list_users(
        &self,
        request: Request<ListUsersRequest>,
    ) -> Result<Response<ListUsersResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_admin(&caller)?;

        let users = self
            .state
            .db
            .list_users()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(ListUsersResponse {
            users: users.iter().map(user_info).collect(),
        }))
    }

    async fn set_user_disabled(
        &self,
        request: Request<SetUserDisabledRequest>,
    ) -> Result<Response<SetUserDisabledResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_admin(&caller)?;
        let req = request.into_inner();

        self.guard_self_lockout(&caller, &req.username)?;

        let changed = self
            .state
            .db
            .set_user_disabled(&req.username, req.disabled)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        if !changed {
            return Err(Status::not_found(format!("no user `{}`", req.username)));
        }

        self.state
            .db
            .record_audit(
                AuditEntry::new(audit::action::USER_DISABLE, &caller.actor)
                    .target(&req.username)
                    .detail(serde_json::json!({ "disabled": req.disabled })),
            )
            .await;

        Ok(Response::new(SetUserDisabledResponse {
            user: Some(self.load_user(&req.username).await?),
        }))
    }

    async fn set_user_password(
        &self,
        request: Request<SetUserPasswordRequest>,
    ) -> Result<Response<SetUserPasswordResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_admin(&caller)?;
        let req = request.into_inner();

        let user = self
            .state
            .db
            .find_user_by_username(&req.username)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found(format!("no user `{}`", req.username)))?;

        self.state
            .db
            .set_password(user.id, &req.password)
            .await
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        self.state
            .db
            .record_audit(
                AuditEntry::new("user.set_password", &caller.actor).target(&user.username),
            )
            .await;

        Ok(Response::new(SetUserPasswordResponse {
            user: Some(self.load_user(&req.username).await?),
        }))
    }

    async fn delete_user(
        &self,
        request: Request<DeleteUserRequest>,
    ) -> Result<Response<DeleteUserResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_admin(&caller)?;
        let req = request.into_inner();

        self.guard_self_lockout(&caller, &req.username)?;

        let deleted = self
            .state
            .db
            .delete_user(&req.username)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        if deleted {
            self.state
                .db
                .record_audit(
                    AuditEntry::new(audit::action::USER_DELETE, &caller.actor)
                        .target(&req.username),
                )
                .await;
        }

        Ok(Response::new(DeleteUserResponse { deleted }))
    }

    async fn query_audit(
        &self,
        request: Request<QueryAuditRequest>,
    ) -> Result<Response<QueryAuditResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_admin(&caller)?;
        let req = request.into_inner();

        let rows = self
            .state
            .db
            .query_audit(&AuditQuery {
                action: non_empty(req.action),
                repo: non_empty(req.repo),
                actor: non_empty(req.actor),
                only_failures: req.only_failures,
                limit: if req.limit <= 0 { 50 } else { req.limit as i64 },
            })
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(QueryAuditResponse {
            entries: rows
                .into_iter()
                .map(|row| ProtoAuditEntry {
                    id: row.id,
                    at: row.at.timestamp(),
                    action: row.action,
                    actor_kind: row.actor_kind,
                    actor_name: row.actor_name.unwrap_or_default(),
                    repo: row.repo.unwrap_or_default(),
                    channel: row.channel.unwrap_or_default(),
                    target: row.target.unwrap_or_default(),
                    success: row.success,
                    remote_addr: row.remote_addr.unwrap_or_default(),
                    detail: row.detail.to_string(),
                })
                .collect(),
        }))
    }

    async fn rebuild_index(
        &self,
        request: Request<RebuildIndexRequest>,
    ) -> Result<Response<RebuildIndexResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_admin(&caller)?;
        let req = request.into_inner();

        auth::require_repo(&self.state, &caller, &req.repo, Permission::Write).await?;
        let format = from_proto_format(req.format)
            .ok_or_else(|| Status::invalid_argument("format is required"))?;

        // An empty group means "every group of this format", which is what
        // you want after a bucket restore: rebuilding one arch of a
        // multi-arch apk repo would leave the rest stale.
        let groups: Vec<String> = if req.index_group.is_empty() {
            let rows = self
                .state
                .db
                .list_packages(&req.repo, &req.channel, Some(format))
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
            let mut groups: Vec<String> = rows
                .into_iter()
                .map(|r| r.index_group)
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            // rpm's only group is the empty string, which an empty package
            // list would otherwise skip entirely.
            if groups.is_empty() && format == PackageFormat::Rpm {
                groups.push(String::new());
            }
            groups
        } else {
            vec![req.index_group.clone()]
        };

        let mut objects = Vec::new();
        for group in &groups {
            let written = silo_core::repo::regenerate_index(
                &self.state.publish,
                &req.repo,
                &req.channel,
                format,
                group,
                &caller.actor,
            )
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
            self.state
                .metrics
                .index_regenerations
                .with_label_values(&[format.as_str(), "ok"])
                .inc();
            objects.extend(written);
        }

        Ok(Response::new(RebuildIndexResponse {
            objects,
            groups_rebuilt: groups.len() as i32,
        }))
    }

    async fn delete_package(
        &self,
        request: Request<DeletePackageRequest>,
    ) -> Result<Response<DeletePackageResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_admin(&caller)?;
        let req = request.into_inner();

        let storage_path =
            silo_core::repo::delete_package(&self.state.publish, req.id, &caller.actor)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(DeletePackageResponse {
            deleted: storage_path.is_some(),
            storage_path: storage_path.unwrap_or_default(),
        }))
    }

    async fn set_repo_mode(
        &self,
        request: Request<SetRepoModeRequest>,
    ) -> Result<Response<SetRepoModeResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_admin(&caller)?;
        let req = request.into_inner();

        silo_core::config::validate_repo_name("repo", &req.repo)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        let public = match RepoMode::try_from(req.mode).unwrap_or(RepoMode::Unspecified) {
            RepoMode::Public => true,
            RepoMode::Private => false,
            RepoMode::Unspecified => {
                return Err(Status::invalid_argument("mode must be public or private"))
            }
        };

        self.state
            .db
            .set_repo_public(&req.repo, public)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        self.state
            .db
            .record_audit(
                AuditEntry::new(audit::action::REPO_SET_MODE, &caller.actor)
                    .repo(&req.repo)
                    .detail(serde_json::json!({ "public": public })),
            )
            .await;

        let mode = if public {
            RepoMode::Public
        } else {
            RepoMode::Private
        };
        Ok(Response::new(SetRepoModeResponse {
            repo: req.repo,
            mode: mode as i32,
        }))
    }
}

impl AdminServiceImpl {
    /// Re-reads a user after a mutation, so the response reflects what is
    /// actually stored rather than what the caller asked for.
    async fn load_user(&self, username: &str) -> Result<UserInfo, Status> {
        let user = self
            .state
            .db
            .find_user_by_username(username)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found(format!("no user `{username}`")))?;
        Ok(user_info(&user))
    }

    /// Refuses operations that would lock the caller out of their own
    /// registry. Recovering from that needs database access, which is
    /// exactly what an admin using the CLI is trying to avoid needing.
    #[allow(clippy::result_large_err)]
    fn guard_self_lockout(
        &self,
        caller: &auth::Authenticated,
        username: &str,
    ) -> Result<(), Status> {
        if caller.actor.kind == ActorKind::User
            && caller.actor.name.eq_ignore_ascii_case(username.trim())
        {
            return Err(Status::failed_precondition(
                "refusing to disable or delete the account you are signed in as",
            ));
        }
        Ok(())
    }
}

fn non_empty(value: String) -> Option<String> {
    Some(value).filter(|v| !v.is_empty())
}

/// Proto has no optional timestamp, so 0 is the sentinel for "unset".
fn timestamp_to_datetime(seconds: i64) -> Option<silo_db::DateTime> {
    if seconds <= 0 {
        return None;
    }
    chrono::DateTime::from_timestamp(seconds, 0)
}

fn token_info(token: &silo_db::tokens::Token) -> TokenInfo {
    let (all_repos, repos) = match &token.scope {
        Scope::All => (true, Vec::new()),
        Scope::Repos(repos) => (false, repos.clone()),
    };
    TokenInfo {
        id: token.id.to_string(),
        name: token.name.clone(),
        prefix: token.prefix.clone(),
        permission: token.permission.as_str().to_string(),
        all_repos,
        repos,
        created_at: token.created_at.timestamp(),
        expires_at: token.expires_at.map(|t| t.timestamp()).unwrap_or(0),
        last_used_at: token.last_used_at.map(|t| t.timestamp()).unwrap_or(0),
        revoked_at: token.revoked_at.map(|t| t.timestamp()).unwrap_or(0),
        kind: token.kind.as_str().to_string(),
    }
}

fn user_info(user: &User) -> UserInfo {
    UserInfo {
        id: user.id.to_string(),
        username: user.username.clone(),
        is_admin: user.is_admin,
        disabled: user.disabled,
        oidc_only: user.is_oidc_only(),
        created_at: user.created_at.timestamp(),
        last_login_at: user.last_login_at.map(|t| t.timestamp()).unwrap_or(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_timestamps_mean_unset() {
        assert!(timestamp_to_datetime(0).is_none());
        assert!(timestamp_to_datetime(-5).is_none());
        assert_eq!(
            timestamp_to_datetime(1_700_000_000).unwrap().timestamp(),
            1_700_000_000
        );
    }

    #[test]
    fn empty_filter_strings_become_no_filter() {
        assert_eq!(non_empty(String::new()), None);
        assert_eq!(non_empty("publish".into()), Some("publish".into()));
    }

    #[test]
    fn token_info_flattens_the_scope_into_wire_fields() {
        let mut token = silo_db::tokens::Token {
            id: Uuid::nil(),
            name: "ci".into(),
            prefix: "abc".into(),
            permission: Permission::Write,
            kind: TokenKind::Api,
            scope: Scope::All,
            user_id: None,
            created_by: None,
            created_at: chrono::Utc::now(),
            expires_at: None,
            last_used_at: None,
            revoked_at: None,
        };

        let info = token_info(&token);
        assert!(info.all_repos);
        assert!(info.repos.is_empty());
        assert_eq!(info.expires_at, 0, "never-expiring tokens report 0");
        assert_eq!(info.permission, "write");

        token.scope = Scope::Repos(vec!["a".into(), "b".into()]);
        let info = token_info(&token);
        assert!(!info.all_repos);
        assert_eq!(info.repos, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn user_info_reports_oidc_only_accounts() {
        let user = User {
            id: Uuid::nil(),
            username: "alice".into(),
            password_hash: None,
            oidc_subject: Some("sub".into()),
            is_admin: true,
            disabled: false,
            created_at: chrono::Utc::now(),
            last_login_at: None,
        };
        let info = user_info(&user);
        assert!(info.oidc_only);
        assert!(info.is_admin);
        assert_eq!(info.last_login_at, 0);
    }
}
