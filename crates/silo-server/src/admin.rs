//! The admin gRPC service: tokens, users, audit, and index repair.
//!
//! Every method requires an admin token, and the methods split in two by
//! what they act on:
//!
//! - **Repo operations** (prune, rebuild, delete a package, set a repo's
//!   mode) also take `require_repo`, so a repo-scoped admin token reaches
//!   exactly the repos it names.
//! - **Registry-wide operations** (users, and the audit log across every
//!   repo) take `require_global_admin` instead, because there is no repo
//!   to scope them against. Admin permission alone is not enough: a
//!   repo-scoped admin who could create an admin *user* would simply log
//!   in as them for a session scoped to everything.
//!
//! Tokens sit between the two — `create_token`, `list_tokens` and
//! `revoke_token` are allowed for a repo-scoped admin but only ever reach
//! tokens their own scope already covers (`covered_by`).
//!
//! The service is exposed over gRPC rather than a separate HTTP admin API
//! so there is exactly one auth path, one audit path, and one client
//! (`silo`) to keep in sync.

use std::sync::Arc;

use silo_db::audit::{self, ActorKind, AuditEntry, AuditQuery};
use silo_db::tokens::{NewToken, Permission, Scope, TokenKind};
use silo_db::users::User;
use silo_db::Uuid;
use silo_pkg::PackageFormat;
use silo_proto::v1::admin_service_server::AdminService;
use silo_proto::v1::{
    AddUpstreamRequest, AddUpstreamResponse, AuditEntry as ProtoAuditEntry, ClearPruneRuleRequest,
    ClearPruneRuleResponse, CreateRepoRequest, CreateRepoResponse, CreateTokenRequest,
    CreateTokenResponse, CreateUserRequest, CreateUserResponse, DeletePackageRequest,
    DeletePackageResponse, DeleteRepoRequest, DeleteRepoResponse, DeleteUserRequest,
    DeleteUserResponse, GetPruneRuleRequest, GetPruneRuleResponse, ListPruneExemptionsRequest,
    ListPruneExemptionsResponse, ListTokensRequest, ListTokensResponse, ListUpstreamsRequest,
    ListUpstreamsResponse, ListUsersRequest, ListUsersResponse, OriginScope as ProtoOriginScope,
    PruneCandidate as ProtoPruneCandidate, PruneRule as ProtoPruneRule, QueryAuditRequest,
    QueryAuditResponse, RebuildIndexRequest, RebuildIndexResponse, RemoveUpstreamRequest,
    RemoveUpstreamResponse, RepoMode, RevokeTokenRequest, RevokeTokenResponse, RunPruneRequest,
    RunPruneResponse, SetPruneExemptionRequest, SetPruneExemptionResponse, SetPruneRuleRequest,
    SetPruneRuleResponse, SetRepoModeRequest, SetRepoModeResponse, SetUserDisabledRequest,
    SetUserDisabledResponse, SetUserPasswordRequest, SetUserPasswordResponse, SyncUpstreamRequest,
    SyncUpstreamResponse, TokenInfo, TokenScope as ProtoScope, UpdateUpstreamRequest,
    UpdateUpstreamResponse, UpstreamCacheMode as ProtoCacheMode, UpstreamInfo, UserInfo,
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
        let result = self.create_token_inner(request).await;
        self.state.metrics.record_grpc("create_token", &result);
        result
    }

    async fn list_tokens(
        &self,
        request: Request<ListTokensRequest>,
    ) -> Result<Response<ListTokensResponse>, Status> {
        let result = self.list_tokens_inner(request).await;
        self.state.metrics.record_grpc("list_tokens", &result);
        result
    }

    async fn revoke_token(
        &self,
        request: Request<RevokeTokenRequest>,
    ) -> Result<Response<RevokeTokenResponse>, Status> {
        let result = self.revoke_token_inner(request).await;
        self.state.metrics.record_grpc("revoke_token", &result);
        result
    }

    async fn create_user(
        &self,
        request: Request<CreateUserRequest>,
    ) -> Result<Response<CreateUserResponse>, Status> {
        let result = self.create_user_inner(request).await;
        self.state.metrics.record_grpc("create_user", &result);
        result
    }

    async fn list_users(
        &self,
        request: Request<ListUsersRequest>,
    ) -> Result<Response<ListUsersResponse>, Status> {
        let result = self.list_users_inner(request).await;
        self.state.metrics.record_grpc("list_users", &result);
        result
    }

    async fn set_user_disabled(
        &self,
        request: Request<SetUserDisabledRequest>,
    ) -> Result<Response<SetUserDisabledResponse>, Status> {
        let result = self.set_user_disabled_inner(request).await;
        self.state.metrics.record_grpc("set_user_disabled", &result);
        result
    }

    async fn set_user_password(
        &self,
        request: Request<SetUserPasswordRequest>,
    ) -> Result<Response<SetUserPasswordResponse>, Status> {
        let result = self.set_user_password_inner(request).await;
        self.state.metrics.record_grpc("set_user_password", &result);
        result
    }

    async fn delete_user(
        &self,
        request: Request<DeleteUserRequest>,
    ) -> Result<Response<DeleteUserResponse>, Status> {
        let result = self.delete_user_inner(request).await;
        self.state.metrics.record_grpc("delete_user", &result);
        result
    }

    async fn query_audit(
        &self,
        request: Request<QueryAuditRequest>,
    ) -> Result<Response<QueryAuditResponse>, Status> {
        let result = self.query_audit_inner(request).await;
        self.state.metrics.record_grpc("query_audit", &result);
        result
    }

    async fn rebuild_index(
        &self,
        request: Request<RebuildIndexRequest>,
    ) -> Result<Response<RebuildIndexResponse>, Status> {
        let result = self.rebuild_index_inner(request).await;
        self.state.metrics.record_grpc("rebuild_index", &result);
        result
    }

    async fn delete_package(
        &self,
        request: Request<DeletePackageRequest>,
    ) -> Result<Response<DeletePackageResponse>, Status> {
        let result = self.delete_package_inner(request).await;
        self.state.metrics.record_grpc("delete_package", &result);
        result
    }

    async fn set_repo_mode(
        &self,
        request: Request<SetRepoModeRequest>,
    ) -> Result<Response<SetRepoModeResponse>, Status> {
        let result = self.set_repo_mode_inner(request).await;
        self.state.metrics.record_grpc("set_repo_mode", &result);
        result
    }

    async fn create_repo(
        &self,
        request: Request<CreateRepoRequest>,
    ) -> Result<Response<CreateRepoResponse>, Status> {
        let result = self.create_repo_inner(request).await;
        self.state.metrics.record_grpc("create_repo", &result);
        result
    }

    async fn delete_repo(
        &self,
        request: Request<DeleteRepoRequest>,
    ) -> Result<Response<DeleteRepoResponse>, Status> {
        let result = self.delete_repo_inner(request).await;
        self.state.metrics.record_grpc("delete_repo", &result);
        result
    }

    async fn set_prune_rule(
        &self,
        request: Request<SetPruneRuleRequest>,
    ) -> Result<Response<SetPruneRuleResponse>, Status> {
        let result = self.set_prune_rule_inner(request).await;
        self.state.metrics.record_grpc("set_prune_rule", &result);
        result
    }

    async fn clear_prune_rule(
        &self,
        request: Request<ClearPruneRuleRequest>,
    ) -> Result<Response<ClearPruneRuleResponse>, Status> {
        let result = self.clear_prune_rule_inner(request).await;
        self.state.metrics.record_grpc("clear_prune_rule", &result);
        result
    }

    async fn get_prune_rule(
        &self,
        request: Request<GetPruneRuleRequest>,
    ) -> Result<Response<GetPruneRuleResponse>, Status> {
        let result = self.get_prune_rule_inner(request).await;
        self.state.metrics.record_grpc("get_prune_rule", &result);
        result
    }

    async fn set_prune_exemption(
        &self,
        request: Request<SetPruneExemptionRequest>,
    ) -> Result<Response<SetPruneExemptionResponse>, Status> {
        let result = self.set_prune_exemption_inner(request).await;
        self.state
            .metrics
            .record_grpc("set_prune_exemption", &result);
        result
    }

    async fn list_prune_exemptions(
        &self,
        request: Request<ListPruneExemptionsRequest>,
    ) -> Result<Response<ListPruneExemptionsResponse>, Status> {
        let result = self.list_prune_exemptions_inner(request).await;
        self.state
            .metrics
            .record_grpc("list_prune_exemptions", &result);
        result
    }

    async fn run_prune(
        &self,
        request: Request<RunPruneRequest>,
    ) -> Result<Response<RunPruneResponse>, Status> {
        let result = self.run_prune_inner(request).await;
        self.state.metrics.record_grpc("run_prune", &result);
        result
    }

    async fn add_upstream(
        &self,
        request: Request<AddUpstreamRequest>,
    ) -> Result<Response<AddUpstreamResponse>, Status> {
        let result = self.add_upstream_inner(request).await;
        self.state.metrics.record_grpc("add_upstream", &result);
        result
    }

    async fn update_upstream(
        &self,
        request: Request<UpdateUpstreamRequest>,
    ) -> Result<Response<UpdateUpstreamResponse>, Status> {
        let result = self.update_upstream_inner(request).await;
        self.state.metrics.record_grpc("update_upstream", &result);
        result
    }

    async fn remove_upstream(
        &self,
        request: Request<RemoveUpstreamRequest>,
    ) -> Result<Response<RemoveUpstreamResponse>, Status> {
        let result = self.remove_upstream_inner(request).await;
        self.state.metrics.record_grpc("remove_upstream", &result);
        result
    }

    async fn list_upstreams(
        &self,
        request: Request<ListUpstreamsRequest>,
    ) -> Result<Response<ListUpstreamsResponse>, Status> {
        let result = self.list_upstreams_inner(request).await;
        self.state.metrics.record_grpc("list_upstreams", &result);
        result
    }

    async fn sync_upstream(
        &self,
        request: Request<SyncUpstreamRequest>,
    ) -> Result<Response<SyncUpstreamResponse>, Status> {
        let result = self.sync_upstream_inner(request).await;
        self.state.metrics.record_grpc("sync_upstream", &result);
        result
    }
}

impl AdminServiceImpl {
    async fn create_token_inner(
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
        if !covered_by(&caller, &scope) {
            return Err(Status::permission_denied(
                "cannot create a token with a wider repo scope than your own",
            ));
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

    async fn list_tokens_inner(
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

        // A repo-scoped admin sees only the tokens its own scope covers.
        // Otherwise this endpoint is a directory of every repo in the
        // registry — the same enumeration `require_repo` refuses to leak
        // through status codes.
        let global = auth::has_global_scope(&caller);
        Ok(Response::new(ListTokensResponse {
            tokens: tokens
                .iter()
                .filter(|t| global || covered_by(&caller, &t.scope))
                .map(token_info)
                .collect(),
        }))
    }

    async fn revoke_token_inner(
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

        // Revoking is the mirror of creating, so it takes the same scope
        // test: an admin may not revoke a token that reaches further than
        // their own does. Without this, a repo-scoped admin could revoke
        // the registry's only global admin token and lock everyone out.
        if !auth::has_global_scope(&caller) && !covered_by(&caller, &token.scope) {
            return Err(Status::permission_denied(
                "cannot revoke a token with a wider repo scope than your own",
            ));
        }

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

    async fn create_user_inner(
        &self,
        request: Request<CreateUserRequest>,
    ) -> Result<Response<CreateUserResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_global_admin(&caller)?;
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

    async fn list_users_inner(
        &self,
        request: Request<ListUsersRequest>,
    ) -> Result<Response<ListUsersResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_global_admin(&caller)?;

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

    async fn set_user_disabled_inner(
        &self,
        request: Request<SetUserDisabledRequest>,
    ) -> Result<Response<SetUserDisabledResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_global_admin(&caller)?;
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

    async fn set_user_password_inner(
        &self,
        request: Request<SetUserPasswordRequest>,
    ) -> Result<Response<SetUserPasswordResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_global_admin(&caller)?;
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

    async fn delete_user_inner(
        &self,
        request: Request<DeleteUserRequest>,
    ) -> Result<Response<DeleteUserResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_global_admin(&caller)?;
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

    async fn query_audit_inner(
        &self,
        request: Request<QueryAuditRequest>,
    ) -> Result<Response<QueryAuditResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_admin(&caller)?;
        let req = request.into_inner();

        // The audit log spans every repo, so an unfiltered query from a
        // repo-scoped admin would hand back activity — and repo names —
        // from repos their token cannot reach. Such a caller has to name a
        // repo, and it has to be one they already have access to.
        if !auth::has_global_scope(&caller) {
            if req.repo.is_empty() {
                return Err(Status::permission_denied(
                    "a repo-scoped admin token must pass a repo filter; only a token scoped \
                     to every repo can query the whole audit log",
                ));
            }
            auth::require_repo(&self.state, &caller, &req.repo, Permission::Write).await?;
        }

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

    async fn rebuild_index_inner(
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
            .await;
            let written = match written {
                Ok(written) => written,
                Err(e) => {
                    self.state
                        .metrics
                        .index_regenerations
                        .with_label_values(&[format.as_str(), "error"])
                        .inc();
                    return Err(Status::internal(e.to_string()));
                }
            };
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

    async fn delete_package_inner(
        &self,
        request: Request<DeletePackageRequest>,
    ) -> Result<Response<DeletePackageResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_admin(&caller)?;
        let req = request.into_inner();

        // Admin permission is repo-independent, so it alone would let a
        // repo-scoped admin token delete anything in the registry by
        // guessing ids. The row is read first purely to learn which repo
        // to enforce the token's scope against.
        let package = self
            .state
            .db
            .find_package(req.id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        let Some(package) = package else {
            return Ok(Response::new(DeletePackageResponse {
                deleted: false,
                storage_path: String::new(),
            }));
        };
        auth::require_repo(&self.state, &caller, &package.repo, Permission::Write).await?;

        let storage_path =
            silo_core::repo::delete_package(&self.state.publish, req.id, &caller.actor, None)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(DeletePackageResponse {
            deleted: storage_path.is_some(),
            storage_path: storage_path.unwrap_or_default(),
        }))
    }

    async fn set_repo_mode_inner(
        &self,
        request: Request<SetRepoModeRequest>,
    ) -> Result<Response<SetRepoModeResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_admin(&caller)?;
        let req = request.into_inner();

        silo_core::config::validate_repo_name("repo", &req.repo)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        // Publishing a repo is the single most consequential thing an
        // admin token can do to one, so it needs the token's own scope to
        // cover that repo — otherwise a repo-scoped admin could make
        // *someone else's* private repo world-readable.
        auth::require_repo(&self.state, &caller, &req.repo, Permission::Write).await?;

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

    async fn create_repo_inner(
        &self,
        request: Request<CreateRepoRequest>,
    ) -> Result<Response<CreateRepoResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_admin(&caller)?;
        let req = request.into_inner();

        silo_core::config::validate_repo_name("repo", &req.repo)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        // Same reasoning as `set_repo_mode_inner`: creating a repo also
        // sets its mode, so it needs the token's own scope to cover it.
        auth::require_repo(&self.state, &caller, &req.repo, Permission::Write).await?;

        if self
            .state
            .db
            .repo_exists(&req.repo)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
        {
            return Err(Status::already_exists(format!(
                "repo `{}` already exists",
                req.repo
            )));
        }

        // Unspecified means "use the default", unlike `set_repo_mode_inner`
        // which requires the caller to say public or private explicitly.
        let public = matches!(
            RepoMode::try_from(req.mode).unwrap_or(RepoMode::Unspecified),
            RepoMode::Public
        );

        let created = self
            .state
            .db
            .create_repo(&req.repo, public)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        if !created {
            return Err(Status::already_exists(format!(
                "repo `{}` already exists",
                req.repo
            )));
        }

        self.state
            .db
            .record_audit(
                AuditEntry::new(audit::action::REPO_CREATE, &caller.actor)
                    .repo(&req.repo)
                    .detail(serde_json::json!({ "public": public })),
            )
            .await;

        let mode = if public {
            RepoMode::Public
        } else {
            RepoMode::Private
        };
        Ok(Response::new(CreateRepoResponse {
            repo: req.repo,
            mode: mode as i32,
        }))
    }

    async fn delete_repo_inner(
        &self,
        request: Request<DeleteRepoRequest>,
    ) -> Result<Response<DeleteRepoResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_admin(&caller)?;
        let req = request.into_inner();

        silo_core::config::validate_repo_name("repo", &req.repo)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        auth::require_repo(&self.state, &caller, &req.repo, Permission::Write).await?;

        let packages = self
            .state
            .db
            .list_all_in_repo(&req.repo)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        if !packages.is_empty() && !req.force {
            return Err(Status::failed_precondition(format!(
                "repo `{}` has {} package(s); pass --force to delete them too",
                req.repo,
                packages.len()
            )));
        }

        let mut deleted = 0i32;
        let mut first_package_error: Option<String> = None;
        if req.force {
            for package in &packages {
                match silo_core::repo::delete_package(
                    &self.state.publish,
                    package.id,
                    &caller.actor,
                    Some(serde_json::json!({ "reason": "repo_delete" })),
                )
                .await
                {
                    Ok(Some(_)) => deleted += 1,
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!(
                            error = %e, repo = %req.repo, package_id = package.id,
                            "failed to delete a package while force-deleting its repo"
                        );
                        first_package_error.get_or_insert_with(|| e.to_string());
                    }
                }
            }
        }

        let repo_deleted = self
            .state
            .db
            .delete_repo(&req.repo)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        if !repo_deleted {
            // Distinguishes why nothing was deleted: a package failed to
            // delete (so the repo is genuinely non-empty and the caller
            // needs the real cause, not just "still has packages"), the
            // repo never existed at all, or — the ordinary non-force
            // case — it simply still has packages.
            if let Some(error) = first_package_error {
                return Err(Status::internal(format!(
                    "repo `{}`: deleted {deleted} package(s), but one failed: {error}",
                    req.repo
                )));
            }
            let exists = self
                .state
                .db
                .repo_exists(&req.repo)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
            if !exists {
                return Err(Status::not_found(format!("no repo `{}`", req.repo)));
            }
            return Err(Status::failed_precondition(format!(
                "repo `{}` still has packages, retry",
                req.repo
            )));
        }

        self.state
            .db
            .record_audit(
                AuditEntry::new(audit::action::REPO_DELETE, &caller.actor)
                    .repo(&req.repo)
                    .detail(serde_json::json!({ "force": req.force, "packages_deleted": deleted })),
            )
            .await;

        Ok(Response::new(DeleteRepoResponse {
            packages_deleted: deleted,
        }))
    }

    async fn set_prune_rule_inner(
        &self,
        request: Request<SetPruneRuleRequest>,
    ) -> Result<Response<SetPruneRuleResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_admin(&caller)?;
        let req = request.into_inner();

        silo_core::config::validate_repo_name("repo", &req.repo)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        auth::require_repo(&self.state, &caller, &req.repo, Permission::Write).await?;
        if req.keep_last_n.is_none() && req.max_age_days.is_none() {
            return Err(Status::invalid_argument(
                "at least one of keep_last_n or max_age_days is required",
            ));
        }
        if req.keep_last_n.is_some_and(|n| n <= 0) {
            return Err(Status::invalid_argument("keep_last_n must be positive"));
        }
        if req.max_age_days.is_some_and(|n| n <= 0) {
            return Err(Status::invalid_argument("max_age_days must be positive"));
        }

        let origin_scope = from_proto_origin_scope(req.origin_scope);
        let rule = self
            .state
            .db
            .set_prune_rule(
                &req.repo,
                &req.channel,
                req.keep_last_n,
                req.max_age_days,
                origin_scope,
            )
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        self.state
            .db
            .record_audit(
                AuditEntry::new(audit::action::PRUNE_RULE_SET, &caller.actor)
                    .repo(&req.repo)
                    .channel(&req.channel)
                    .detail(serde_json::json!({
                        "keep_last_n": req.keep_last_n,
                        "max_age_days": req.max_age_days,
                        "origin_scope": origin_scope,
                    })),
            )
            .await;

        Ok(Response::new(SetPruneRuleResponse {
            rule: Some(to_proto_rule(&rule)),
        }))
    }

    async fn clear_prune_rule_inner(
        &self,
        request: Request<ClearPruneRuleRequest>,
    ) -> Result<Response<ClearPruneRuleResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_admin(&caller)?;
        let req = request.into_inner();

        silo_core::config::validate_repo_name("repo", &req.repo)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        auth::require_repo(&self.state, &caller, &req.repo, Permission::Write).await?;

        let cleared = self
            .state
            .db
            .clear_prune_rule(&req.repo, &req.channel)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        if cleared {
            self.state
                .db
                .record_audit(
                    AuditEntry::new(audit::action::PRUNE_RULE_CLEAR, &caller.actor)
                        .repo(&req.repo)
                        .channel(&req.channel),
                )
                .await;
        }

        Ok(Response::new(ClearPruneRuleResponse { cleared }))
    }

    async fn get_prune_rule_inner(
        &self,
        request: Request<GetPruneRuleRequest>,
    ) -> Result<Response<GetPruneRuleResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_admin(&caller)?;
        let req = request.into_inner();

        silo_core::config::validate_repo_name("repo", &req.repo)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        auth::require_repo(&self.state, &caller, &req.repo, Permission::Write).await?;

        let rule = self
            .state
            .db
            .get_prune_rule(&req.repo, &req.channel)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(GetPruneRuleResponse {
            rule: rule.as_ref().map(to_proto_rule),
        }))
    }

    async fn set_prune_exemption_inner(
        &self,
        request: Request<SetPruneExemptionRequest>,
    ) -> Result<Response<SetPruneExemptionResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_admin(&caller)?;
        let req = request.into_inner();

        silo_core::config::validate_repo_name("repo", &req.repo)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        auth::require_repo(&self.state, &caller, &req.repo, Permission::Write).await?;
        let name = req.name.trim();
        if name.is_empty() {
            return Err(Status::invalid_argument("name is required"));
        }

        if req.exempt {
            self.state
                .db
                .add_prune_exemption(&req.repo, &req.channel, name)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
        } else {
            self.state
                .db
                .remove_prune_exemption(&req.repo, &req.channel, name)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
        }

        self.state
            .db
            .record_audit(
                AuditEntry::new(audit::action::PRUNE_EXEMPTION_SET, &caller.actor)
                    .repo(&req.repo)
                    .channel(&req.channel)
                    .target(name)
                    .detail(serde_json::json!({ "exempt": req.exempt })),
            )
            .await;

        Ok(Response::new(SetPruneExemptionResponse {
            exempted: req.exempt,
        }))
    }

    async fn list_prune_exemptions_inner(
        &self,
        request: Request<ListPruneExemptionsRequest>,
    ) -> Result<Response<ListPruneExemptionsResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_admin(&caller)?;
        let req = request.into_inner();

        silo_core::config::validate_repo_name("repo", &req.repo)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        auth::require_repo(&self.state, &caller, &req.repo, Permission::Write).await?;

        let names = self
            .state
            .db
            .list_prune_exemptions(&req.repo, &req.channel)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(ListPruneExemptionsResponse { names }))
    }

    async fn run_prune_inner(
        &self,
        request: Request<RunPruneRequest>,
    ) -> Result<Response<RunPruneResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_admin(&caller)?;
        let req = request.into_inner();

        if !self.state.config.prune.enabled {
            return Err(Status::failed_precondition(
                "pruning is disabled (`prune.enabled` is false in server config)",
            ));
        }

        if req.repo.is_empty() {
            // An empty repo filter processes every configured rule across
            // every repo — only a token scoped to all repos may trigger
            // that; a repo-scoped admin token must name the repo(s) it
            // actually has access to.
            let has_global_scope = caller
                .token
                .as_ref()
                .is_some_and(|t| matches!(t.scope, Scope::All));
            if !has_global_scope {
                return Err(Status::permission_denied(
                    "a repo-scoped admin token must pass a repo; only a token scoped to every repo can run an unscoped prune",
                ));
            }
        } else {
            auth::require_repo(&self.state, &caller, &req.repo, Permission::Write).await?;
        }

        let scope = silo_core::prune::PruneScope {
            repo: (!req.repo.is_empty()).then_some(req.repo.clone()),
            channel: (!req.channel.is_empty()).then_some(req.channel.clone()),
        };

        let report = silo_core::prune::run(&self.state.publish, &scope, req.dry_run, &caller.actor)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(RunPruneResponse {
            dry_run: report.dry_run,
            candidates: report.candidates.iter().map(to_proto_candidate).collect(),
            deleted: report.deleted as i32,
            failed: report.failed.len() as i32,
        }))
    }

    async fn add_upstream_inner(
        &self,
        request: Request<AddUpstreamRequest>,
    ) -> Result<Response<AddUpstreamResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_admin(&caller)?;
        let req = request.into_inner();

        silo_core::config::validate_repo_name("repo", &req.repo)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        silo_core::config::validate_repo_name("channel", &req.channel)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        silo_core::config::validate_repo_name("name", &req.name)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        auth::require_repo(&self.state, &caller, &req.repo, Permission::Write).await?;

        let format = from_proto_format(req.format)
            .ok_or_else(|| Status::invalid_argument("a valid format is required"))?;
        validate_base_url(&req.base_url)?;
        let cache_mode = proto_cache_mode_to_str(req.cache_mode)?;

        let auth_triplet = req.auth.as_ref().filter(|a| !a.kind.is_empty()).map(|a| {
            (
                a.kind.as_str(),
                non_empty_str(&a.username),
                a.secret.as_str(),
            )
        });
        if auth_triplet.is_some() && self.state.upstream_secrets.is_none() {
            return Err(Status::failed_precondition(
                "this server has no `upstream_secret` key configured, so upstreams can't carry a credential",
            ));
        }

        let opts = silo_pkg::UpstreamFetchOptions {
            arches: req.arches.clone(),
            suite: non_empty_str(&req.suite).map(str::to_string),
            components: req.components.clone(),
        };

        // Validate + first fetch BEFORE anything is persisted — a failure
        // here rejects the call outright and creates no row.
        let http = silo_core::upstream_sync::http_from_plaintext(
            self.state.upstream_http.clone(),
            &req.base_url,
            auth_triplet,
        )
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let fetched = silo_core::upstream_sync::fetch(&http, format, &opts)
            .await
            .map_err(|e| Status::invalid_argument(format!("could not validate upstream: {e}")))?;

        let sealed = auth_triplet
            .map(|(kind, username, secret)| {
                silo_core::upstream_sync::seal_auth(
                    self.state.upstream_secrets.as_ref().expect("checked above"),
                    kind,
                    username,
                    secret,
                )
            })
            .transpose()
            .map_err(|e| Status::internal(e.to_string()))?;

        let row = self
            .state
            .db
            .create_upstream(&silo_db::upstreams::NewUpstream {
                repo: req.repo.clone(),
                channel: req.channel.clone(),
                name: req.name.clone(),
                format: format.as_str().to_string(),
                base_url: req.base_url.clone(),
                cache_mode: cache_mode.to_string(),
                cache_index_in_memory: req.cache_index_in_memory,
                arches: req.arches.clone(),
                suite: opts.suite.clone(),
                components: req.components.clone(),
                auth: sealed,
            })
            .await
            .map_err(|e| match e.downcast_ref::<sqlx::Error>() {
                Some(sqlx::Error::Database(db)) if db.is_unique_violation() => {
                    Status::already_exists(e.to_string())
                }
                _ => Status::internal(e.to_string()),
            })?;

        if format != PackageFormat::Npm {
            let synced: Vec<silo_db::upstreams::SyncedPackage> =
                fetched.into_iter().map(to_synced_package).collect();
            self.state
                .db
                .replace_upstream_packages(row.id, &synced)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
        }
        self.state
            .db
            .record_upstream_sync_success(row.id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        silo_core::repo::rebuild_index_for_upstream(
            &self.state.publish,
            &req.repo,
            &req.channel,
            format,
            &req.arches,
            &caller.actor,
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
        let row = self
            .state
            .db
            .find_upstream(row.id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::internal("upstream vanished immediately after creation"))?;

        self.state
            .db
            .record_audit(
                AuditEntry::new(audit::action::UPSTREAM_ADD, &caller.actor)
                    .repo(&req.repo)
                    .channel(&req.channel)
                    .target(&req.name)
                    .detail(
                        serde_json::json!({ "format": format.as_str(), "base_url": req.base_url }),
                    ),
            )
            .await;

        Ok(Response::new(AddUpstreamResponse {
            upstream: Some(to_proto_upstream(&row)),
        }))
    }

    async fn update_upstream_inner(
        &self,
        request: Request<UpdateUpstreamRequest>,
    ) -> Result<Response<UpdateUpstreamResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_admin(&caller)?;
        let req = request.into_inner();

        silo_core::config::validate_repo_name("repo", &req.repo)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        silo_core::config::validate_repo_name("channel", &req.channel)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        silo_core::config::validate_repo_name("name", &req.name)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        auth::require_repo(&self.state, &caller, &req.repo, Permission::Write).await?;
        let existing = self
            .state
            .db
            .get_upstream(&req.repo, &req.channel, &req.name)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found(format!("no upstream `{}`", req.name)))?;

        if let Some(url) = &req.base_url {
            validate_base_url(url)?;
        }
        let base_url = req
            .base_url
            .clone()
            .unwrap_or_else(|| existing.base_url.clone());
        let cache_mode = match req.cache_mode {
            Some(mode) => proto_cache_mode_to_str(mode)?.to_string(),
            None => existing.cache_mode.clone(),
        };
        let cache_index_in_memory = req
            .cache_index_in_memory
            .unwrap_or(existing.cache_index_in_memory);
        let arches = if req.clear_arches {
            Vec::new()
        } else if req.arches.is_empty() {
            existing.arches.clone()
        } else {
            req.arches.clone()
        };
        let suite = req.suite.clone().or_else(|| existing.suite.clone());
        let components = if req.clear_components {
            Vec::new()
        } else if req.components.is_empty() {
            existing.components.clone()
        } else {
            req.components.clone()
        };

        let sealed = match &req.auth {
            None => None,
            Some(a) if a.kind.is_empty() => {
                // Explicit clear: caller sent `auth` with an empty kind.
                Some(None)
            }
            Some(a) => {
                let secrets = self.state.upstream_secrets.as_ref().ok_or_else(|| {
                    Status::failed_precondition(
                        "this server has no `upstream_secret` key configured",
                    )
                })?;
                let username = non_empty_str(&a.username);
                Some(Some(
                    silo_core::upstream_sync::seal_auth(secrets, &a.kind, username, &a.secret)
                        .map_err(|e| Status::internal(e.to_string()))?,
                ))
            }
        };

        let updated = match sealed {
            None => {
                self.state
                    .db
                    .update_upstream(
                        existing.id,
                        &base_url,
                        &cache_mode,
                        cache_index_in_memory,
                        &arches,
                        suite.as_deref(),
                        &components,
                        None,
                    )
                    .await
            }
            Some(None) => {
                // Clearing: reuse the same update call but with auth
                // fields nulled via a direct query, since `update_upstream`
                // only ever *sets* a credential, never clears one — a
                // clear is only reachable through this explicit path.
                self.state
                    .db
                    .clear_upstream_auth(existing.id)
                    .await
                    .map_err(|e| Status::internal(e.to_string()))?;
                self.state
                    .db
                    .update_upstream(
                        existing.id,
                        &base_url,
                        &cache_mode,
                        cache_index_in_memory,
                        &arches,
                        suite.as_deref(),
                        &components,
                        None,
                    )
                    .await
            }
            Some(Some(sealed)) => {
                self.state
                    .db
                    .update_upstream(
                        existing.id,
                        &base_url,
                        &cache_mode,
                        cache_index_in_memory,
                        &arches,
                        suite.as_deref(),
                        &components,
                        Some(&sealed),
                    )
                    .await
            }
        }
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::not_found(format!("no upstream `{}`", req.name)))?;

        // Any of `base_url`/`cache_mode`/auth/index-cache-toggle changing
        // makes a cached copy of this upstream's index untrustworthy —
        // drop it so the next read repopulates against the new settings.
        self.state
            .publish
            .upstream_index_cache
            .invalidate(existing.id);

        // A `base_url` change is worse than a stale cache: every synced
        // row's `download_url` was resolved against the *old* base URL,
        // so merging the index or serving a pull-through request would
        // keep pointing at the old host until the next sync happens to
        // run. Clearing the synced rows here (rather than merely
        // invalidating the read cache) means the package is simply
        // unadvertised until the next sync repopulates it correctly,
        // instead of silently serving a wrong-host URL.
        if base_url != existing.base_url {
            if let Err(e) = self
                .state
                .db
                .replace_upstream_packages(existing.id, &[])
                .await
            {
                tracing::error!(
                    error = %e,
                    upstream = %req.name,
                    "could not clear synced packages after a base_url change"
                );
            }
        }

        self.state
            .db
            .record_audit(
                AuditEntry::new(audit::action::UPSTREAM_UPDATE, &caller.actor)
                    .repo(&req.repo)
                    .channel(&req.channel)
                    .target(&req.name),
            )
            .await;

        Ok(Response::new(UpdateUpstreamResponse {
            upstream: Some(to_proto_upstream(&updated)),
        }))
    }

    async fn remove_upstream_inner(
        &self,
        request: Request<RemoveUpstreamRequest>,
    ) -> Result<Response<RemoveUpstreamResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_admin(&caller)?;
        let req = request.into_inner();

        silo_core::config::validate_repo_name("repo", &req.repo)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        silo_core::config::validate_repo_name("channel", &req.channel)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        silo_core::config::validate_repo_name("name", &req.name)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        auth::require_repo(&self.state, &caller, &req.repo, Permission::Write).await?;
        let existing = self
            .state
            .db
            .get_upstream(&req.repo, &req.channel, &req.name)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found(format!("no upstream `{}`", req.name)))?;

        let mut pruned = 0i32;
        if req.prune {
            let packages = self
                .state
                .db
                .list_all_in_repo(&req.repo)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
            for package in packages
                .iter()
                .filter(|p| p.origin_upstream_id == Some(existing.id))
            {
                match silo_core::repo::delete_package(
                    &self.state.publish,
                    package.id,
                    &caller.actor,
                    Some(serde_json::json!({ "reason": "upstream_remove" })),
                )
                .await
                {
                    Ok(Some(_)) => pruned += 1,
                    Ok(None) => {}
                    Err(e) => {
                        return Err(Status::internal(format!(
                        "removed {pruned} upstream package(s) before failing on package {}: {e}",
                        package.id
                    )))
                    }
                }
            }
        }

        let removed = self
            .state
            .db
            .delete_upstream(existing.id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .is_some();
        self.state
            .publish
            .upstream_index_cache
            .invalidate(existing.id);

        self.state
            .db
            .record_audit(
                AuditEntry::new(audit::action::UPSTREAM_REMOVE, &caller.actor)
                    .repo(&req.repo)
                    .channel(&req.channel)
                    .target(&req.name)
                    .detail(serde_json::json!({ "prune": req.prune, "packages_pruned": pruned })),
            )
            .await;

        Ok(Response::new(RemoveUpstreamResponse {
            removed,
            packages_pruned: pruned,
        }))
    }

    async fn list_upstreams_inner(
        &self,
        request: Request<ListUpstreamsRequest>,
    ) -> Result<Response<ListUpstreamsResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_admin(&caller)?;
        let req = request.into_inner();

        auth::require_repo(&self.state, &caller, &req.repo, Permission::Read).await?;
        let rows = self
            .state
            .db
            .list_upstreams(&req.repo, &req.channel)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(ListUpstreamsResponse {
            upstreams: rows.iter().map(to_proto_upstream).collect(),
        }))
    }

    async fn sync_upstream_inner(
        &self,
        request: Request<SyncUpstreamRequest>,
    ) -> Result<Response<SyncUpstreamResponse>, Status> {
        let caller = auth::authenticate_grpc(&self.state, &request).await?;
        auth::require_admin(&caller)?;
        let req = request.into_inner();

        silo_core::config::validate_repo_name("repo", &req.repo)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        silo_core::config::validate_repo_name("channel", &req.channel)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        silo_core::config::validate_repo_name("name", &req.name)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        auth::require_repo(&self.state, &caller, &req.repo, Permission::Write).await?;
        let existing = self
            .state
            .db
            .get_upstream(&req.repo, &req.channel, &req.name)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found(format!("no upstream `{}`", req.name)))?;

        let count = silo_core::upstream_sync::sync_one(
            &self.state.db,
            self.state.upstream_http.clone(),
            self.state.upstream_secrets.as_ref(),
            &existing,
        )
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
        self.state
            .publish
            .upstream_index_cache
            .invalidate(existing.id);
        if let Ok(format) = existing.format.parse::<PackageFormat>() {
            silo_core::repo::rebuild_index_for_upstream(
                &self.state.publish,
                &req.repo,
                &req.channel,
                format,
                &existing.arches,
                &caller.actor,
            )
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        }

        self.state
            .db
            .record_audit(
                AuditEntry::new(audit::action::UPSTREAM_SYNC, &caller.actor)
                    .repo(&req.repo)
                    .channel(&req.channel)
                    .target(&req.name)
                    .detail(serde_json::json!({ "packages_synced": count })),
            )
            .await;

        let row = self
            .state
            .db
            .find_upstream(existing.id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found(format!("no upstream `{}`", req.name)))?;

        Ok(Response::new(SyncUpstreamResponse {
            upstream: Some(to_proto_upstream(&row)),
            packages_synced: count as i32,
        }))
    }
}

fn non_empty_str(s: &str) -> Option<&str> {
    (!s.is_empty()).then_some(s)
}

/// Rejects anything but an absolute http(s) URL with no embedded
/// userinfo (`https://user:pass@host/...`). A credential belongs in the
/// upstream's own `auth` field, sealed at rest — one baked into the URL
/// would round-trip in plain text through `download_url` and, on a
/// `no_cache` upstream, straight into a client-visible redirect
/// `Location` header.
fn validate_base_url(url: &str) -> Result<(), Status> {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(Status::invalid_argument(
            "base_url must be an absolute http(s) URL",
        ));
    }
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| Status::invalid_argument(format!("base_url is not a valid URL: {e}")))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(Status::invalid_argument(
            "base_url must not embed credentials — configure `auth` instead",
        ));
    }
    Ok(())
}

fn proto_cache_mode_to_str(value: i32) -> Result<&'static str, Status> {
    match ProtoCacheMode::try_from(value).unwrap_or(ProtoCacheMode::Unspecified) {
        ProtoCacheMode::Cache => Ok("cache"),
        ProtoCacheMode::NoCache => Ok("no_cache"),
        ProtoCacheMode::Unspecified => Err(Status::invalid_argument("cache_mode is required")),
    }
}

fn to_synced_package(pkg: silo_pkg::UpstreamPackage) -> silo_db::upstreams::SyncedPackage {
    silo_db::upstreams::SyncedPackage {
        name: pkg.name,
        epoch: pkg.epoch as i32,
        version: pkg.version,
        release: pkg.release,
        arch: pkg.arch,
        filename: pkg.filename,
        download_url: pkg.download_url,
        size_bytes: pkg.size_bytes,
        sha256: pkg.sha256,
        metadata: pkg.metadata,
    }
}

fn to_proto_upstream(row: &silo_db::upstreams::UpstreamRow) -> UpstreamInfo {
    let cache_mode = match row.cache_mode.as_str() {
        "cache" => ProtoCacheMode::Cache,
        "no_cache" => ProtoCacheMode::NoCache,
        _ => ProtoCacheMode::Unspecified,
    };
    UpstreamInfo {
        id: row.id.to_string(),
        repo: row.repo.clone(),
        channel: row.channel.clone(),
        name: row.name.clone(),
        format: row
            .format
            .parse::<PackageFormat>()
            .map(crate::grpc::to_proto_format)
            .unwrap_or_default() as i32,
        base_url: row.base_url.clone(),
        cache_mode: cache_mode as i32,
        cache_index_in_memory: row.cache_index_in_memory,
        arches: row.arches.clone(),
        suite: row.suite.clone().unwrap_or_default(),
        components: row.components.clone(),
        auth_configured: row.auth_kind.is_some(),
        status: row.status.clone(),
        last_sync_at: row.last_sync_at.map(|t| t.timestamp()).unwrap_or_default(),
        last_sync_error: row.last_sync_error.clone().unwrap_or_default(),
        last_success_at: row
            .last_success_at
            .map(|t| t.timestamp())
            .unwrap_or_default(),
    }
}

fn to_proto_rule(rule: &silo_db::prune::PruneRuleRow) -> ProtoPruneRule {
    ProtoPruneRule {
        repo: rule.repo.clone(),
        channel: rule.channel.clone(),
        keep_last_n: rule.keep_last_n,
        max_age_days: rule.max_age_days,
        updated_at: rule.updated_at.timestamp(),
        origin_scope: to_proto_origin_scope(&rule.origin_scope) as i32,
    }
}

fn to_proto_origin_scope(scope: &str) -> ProtoOriginScope {
    match scope {
        "local" => ProtoOriginScope::Local,
        "upstream" => ProtoOriginScope::Upstream,
        _ => ProtoOriginScope::All,
    }
}

/// Unspecified (the zero value, what an older client that doesn't know
/// about this field sends) is treated as "all" — the behavior every rule
/// had before origin scoping existed, so a client that never sets this
/// field sees no change.
fn from_proto_origin_scope(value: i32) -> &'static str {
    match ProtoOriginScope::try_from(value).unwrap_or(ProtoOriginScope::Unspecified) {
        ProtoOriginScope::Local => "local",
        ProtoOriginScope::Upstream => "upstream",
        ProtoOriginScope::All | ProtoOriginScope::Unspecified => "all",
    }
}

fn to_proto_candidate(candidate: &silo_core::prune::PruneCandidate) -> ProtoPruneCandidate {
    let format = candidate.format.parse().unwrap_or(PackageFormat::Rpm);
    ProtoPruneCandidate {
        id: candidate.id,
        repo: candidate.repo.clone(),
        channel: candidate.channel.clone(),
        format: crate::grpc::to_proto_format(format) as i32,
        index_group: candidate.index_group.clone(),
        name: candidate.name.clone(),
        version: candidate.version.clone(),
        release: candidate.release.clone(),
        arch: candidate.arch.clone(),
        filename: candidate.filename.clone(),
        published_at: candidate.published_at,
        matched_rules: candidate
            .matched_rules
            .iter()
            .map(|r| r.as_str().to_string())
            .collect(),
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

/// Whether `scope` reaches no further than the caller's own token does.
///
/// `Scope::All` is only covered by `Scope::All`; a named set is covered
/// when every repo in it is one the caller can already reach. This is the
/// same test `create_token` applies when minting, reused so listing and
/// revoking can't be a way around it.
fn covered_by(caller: &auth::Authenticated, scope: &Scope) -> bool {
    let Some(caller_token) = &caller.token else {
        return false;
    };
    match scope {
        Scope::All => matches!(caller_token.scope, Scope::All),
        Scope::Repos(repos) => repos.iter().all(|r| caller_token.scope.covers(r)),
    }
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

    fn scoped(scope: Scope) -> auth::Authenticated {
        auth::Authenticated {
            token: Some(silo_db::tokens::Token {
                id: Uuid::nil(),
                name: "t".into(),
                prefix: "0".repeat(12),
                permission: Permission::Admin,
                kind: TokenKind::Api,
                scope,
                user_id: None,
                created_by: None,
                created_at: chrono::Utc::now(),
                expires_at: None,
                last_used_at: None,
                revoked_at: None,
            }),
            actor: silo_db::audit::Actor::system(),
        }
    }

    #[test]
    fn a_scope_never_covers_one_wider_than_itself() {
        let global = scoped(Scope::All);
        let mine = scoped(Scope::Repos(vec!["mine".into(), "also-mine".into()]));

        assert!(covered_by(&global, &Scope::All));
        assert!(covered_by(&global, &Scope::Repos(vec!["anything".into()])));

        assert!(covered_by(&mine, &Scope::Repos(vec!["mine".into()])));
        assert!(covered_by(
            &mine,
            &Scope::Repos(vec!["mine".into(), "also-mine".into()])
        ));

        // The two directions that matter: a named scope never covers
        // `All`, and one unlisted repo is enough to fail the check.
        assert!(!covered_by(&mine, &Scope::All));
        assert!(!covered_by(
            &mine,
            &Scope::Repos(vec!["mine".into(), "theirs".into()])
        ));
        assert!(!covered_by(&mine, &Scope::Repos(vec!["theirs".into()])));

        // An empty set is vacuously covered but reaches nothing anyway.
        assert!(covered_by(&mine, &Scope::Repos(vec![])));

        // A caller with no token covers nothing at all.
        let anon = auth::Authenticated::anonymous(None);
        assert!(!covered_by(&anon, &Scope::All));
        assert!(!covered_by(&anon, &Scope::Repos(vec!["mine".into()])));
    }

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
