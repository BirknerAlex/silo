// Wire types for the JSON gateway. They mirror proto/silo/v1/*.proto: field
// names are the proto names, 64-bit integers are numbers (ids and unix
// seconds stay far below 2^53), and enums travel as their integer values.

export const PackageFormat = {
  Unspecified: 0,
  Rpm: 1,
  Apk: 2,
  Npm: 3,
  Pacman: 4,
  Deb: 5,
  Flatpak: 6,
} as const;

export const RepoMode = { Unspecified: 0, Private: 1, Public: 2 } as const;
export const TokenScope = { Unspecified: 0, All: 1, Repos: 2 } as const;
export const OriginScope = { Unspecified: 0, All: 1, Local: 2, Upstream: 3 } as const;
export const CacheMode = { Unspecified: 0, Cache: 1, NoCache: 2 } as const;

export interface AuthInfo {
  password_login_enabled: boolean;
  oidc_enabled: boolean;
  oidc_issuer: string;
  oidc_client_id: string;
  oidc_scopes: string[];
  oidc_device_authorization_endpoint: string;
  oidc_token_endpoint: string;
}

export interface VersionInfo {
  version: string;
  commit: string;
  built_at: string;
  formats: string[];
}

export interface Session {
  token: string;
  username: string;
  is_admin: boolean;
  expires_at: number;
}

export interface WhoAmI {
  token_name: string;
  username: string;
  permission: "read" | "write" | "admin";
  repos: string[];
  all_repos: boolean;
  expires_at: number;
  is_admin: boolean;
}

export interface RepoInfo {
  repo: string;
  channel: string;
  format: number;
  package_count: number;
  total_bytes: number;
  mode: number;
}

export interface PackageInfo {
  name: string;
  version: string;
  release: string;
  arch: string;
  storage_path: string;
  size_bytes: number;
  format: number;
  sha256: string;
  published_at: number;
  id: number;
  origin_upstream: string;
}

export interface TokenInfo {
  id: string;
  name: string;
  prefix: string;
  permission: "read" | "write" | "admin";
  all_repos: boolean;
  repos: string[];
  created_at: number;
  expires_at: number;
  last_used_at: number;
  revoked_at: number;
  kind: "api" | "session";
}

export interface CreateTokenResponse {
  token: string;
  info: TokenInfo;
}

export interface UserInfo {
  id: string;
  username: string;
  is_admin: boolean;
  disabled: boolean;
  oidc_only: boolean;
  created_at: number;
  last_login_at: number;
}

export interface AuditEntry {
  id: number;
  at: number;
  action: string;
  actor_kind: string;
  actor_name: string;
  repo: string;
  channel: string;
  target: string;
  success: boolean;
  remote_addr: string;
  detail: string;
}

export interface QueryAuditRequest {
  action?: string;
  repo?: string;
  actor?: string;
  only_failures?: boolean;
  limit?: number;
}

export interface PruneRule {
  repo: string;
  channel: string;
  keep_last_n: number | null;
  max_age_days: number | null;
  updated_at: number;
  origin_scope: number;
}

export interface PruneCandidate {
  id: number;
  repo: string;
  channel: string;
  format: number;
  index_group: string;
  name: string;
  version: string;
  release: string;
  arch: string;
  filename: string;
  published_at: number;
  matched_rules: string[];
}

export interface RunPruneResponse {
  dry_run: boolean;
  candidates: PruneCandidate[];
  deleted: number;
  failed: number;
}

export interface UpstreamAuth {
  kind: "" | "basic" | "bearer";
  username: string;
  secret: string;
}

export interface UpstreamInfo {
  id: string;
  repo: string;
  channel: string;
  name: string;
  format: number;
  base_url: string;
  cache_mode: number;
  cache_index_in_memory: boolean;
  arches: string[];
  suite: string;
  components: string[];
  auth_configured: boolean;
  status: "pending" | "ok" | "error";
  last_sync_at: number;
  last_sync_error: string;
  last_success_at: number;
  priority: number;
  package_patterns: string[];
}

export interface AddUpstreamRequest {
  repo: string;
  channel: string;
  name: string;
  format: number;
  base_url: string;
  cache_mode: number;
  cache_index_in_memory: boolean;
  auth?: UpstreamAuth;
  arches: string[];
  suite: string;
  components: string[];
  priority: number;
  package_patterns: string[];
}

export interface UpdateUpstreamRequest {
  repo: string;
  channel: string;
  name: string;
  base_url?: string;
  cache_mode?: number;
  cache_index_in_memory?: boolean;
  auth?: UpstreamAuth;
  arches?: string[];
  suite?: string;
  components?: string[];
  clear_arches?: boolean;
  clear_components?: boolean;
  priority?: number;
  package_patterns?: string[];
  clear_package_patterns?: boolean;
}

export interface Stats {
  generated_at: number;
  days: number;
  totals: {
    repos: number;
    channels: number;
    packages: number;
    bytes: number;
    upstream_packages: number;
    users: number;
    admin_users: number;
    disabled_users: number;
    oidc_users: number;
    api_tokens: number;
    session_tokens: number;
    revoked_tokens: number;
    expired_tokens: number;
    public_repos: number;
  };
  formats: { format: number; packages: number; bytes: number; repos: number }[];
  repos: { repo: string; mode: number; channels: number; packages: number; bytes: number }[];
  activity: {
    day: number;
    publishes: number;
    downloads: number;
    deletes: number;
    logins: number;
    failures: number;
  }[];
  actions: { action: string; count: number; failures: number }[];
  upstreams: { total: number; ok: number; pending: number; error: number; indexed_packages: number };
  runtime: {
    started_at: number;
    uptime_seconds: number;
    publishes_ok: number;
    publishes_failed: number;
    downloads_redirect: number;
    downloads_proxy: number;
    pull_through_served: number;
    grpc_ok: number;
    grpc_error: number;
    auth_failures: number;
    upstream_syncs_ok: number;
    upstream_syncs_failed: number;
    database_up: boolean;
  };
  recent_packages: PackageInfo[];
}

export interface ServerInfo extends VersionInfo {
  public_base_url: string;
  password_login_enabled: boolean;
  oidc_enabled: boolean;
  oidc_issuer: string;
  oidc_exclusive: boolean;
  oidc_allow_username_linking: boolean;
  session_ttl_hours: number;
  signing: string[];
  prune_enabled: boolean;
  upstream_secret_configured: boolean;
  audit_log_downloads: boolean;
  audit_log_pull_through: boolean;
  audit_retention_days: number;
  metrics_enabled: boolean;
  jobs: { name: string; schedule: string; enabled: boolean }[];
}

export interface DeviceStart {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string | null;
  expires_in: number;
  interval: number;
}

export type DevicePoll =
  | { status: "pending" }
  | { status: "slow_down" }
  | { status: "ok"; session: Session };
