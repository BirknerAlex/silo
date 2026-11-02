import { anonymous, rpc } from "./client";
import type {
  AddUpstreamRequest,
  AuditEntry,
  AuthInfo,
  CreateTokenResponse,
  DevicePoll,
  DeviceStart,
  PackageInfo,
  PruneRule,
  QueryAuditRequest,
  RepoInfo,
  RunPruneResponse,
  ServerInfo,
  Session,
  Stats,
  TokenInfo,
  UpdateUpstreamRequest,
  UpstreamInfo,
  UserInfo,
  VersionInfo,
  WhoAmI,
} from "./types";

// One function per RPC. Each corresponds to a `silo` subcommand or to a read
// the console needs; the comments name the command.
export const api = {
  // --- sign-in (silo login / whoami / version) ---
  authInfo: () => anonymous<AuthInfo>("/rpc/GetAuthInfo"),
  version: () => anonymous<VersionInfo>("/rpc/GetVersion"),
  login: (username: string, password: string) =>
    anonymous<Session>("/rpc/Login", { username, password }),
  loginOidc: (id_token: string) => anonymous<Session>("/rpc/LoginOidc", { id_token }),
  oidcDeviceStart: () => anonymous<DeviceStart>("/oidc/device"),
  oidcDevicePoll: (device_code: string) => anonymous<DevicePoll>("/oidc/token", { device_code }),
  whoAmI: () => rpc<WhoAmI>("WhoAmI"),

  // --- repos (silo repos / repo create|set|delete) ---
  listRepos: async () => (await rpc<{ repos: RepoInfo[] }>("ListRepos")).repos,
  createRepo: (repo: string, mode: number) => rpc<{ repo: string; mode: number }>("CreateRepo", { repo, mode }),
  setRepoMode: (repo: string, mode: number) => rpc<{ repo: string; mode: number }>("SetRepoMode", { repo, mode }),
  deleteRepo: (repo: string, force: boolean) =>
    rpc<{ packages_deleted: number }>("DeleteRepo", { repo, force }),

  // --- packages (silo list / delete / index rebuild) ---
  listPackages: async (repo: string, channel: string, format = 0) =>
    (await rpc<{ packages: PackageInfo[] }>("ListPackages", { repo, channel, format })).packages,
  deletePackage: (id: number) => rpc<{ deleted: boolean; storage_path: string }>("DeletePackage", { id }),
  rebuildIndex: (repo: string, channel: string, format: number, index_group: string) =>
    rpc<{ objects: string[]; groups_rebuilt: number }>("RebuildIndex", {
      repo,
      channel,
      format,
      index_group,
    }),

  // --- tokens (silo token create|list|revoke) ---
  listTokens: async (include_revoked: boolean) =>
    (await rpc<{ tokens: TokenInfo[] }>("ListTokens", { include_revoked })).tokens,
  createToken: (req: {
    name: string;
    permission: string;
    scope: number;
    repos: string[];
    expires_at: number;
  }) => rpc<CreateTokenResponse>("CreateToken", req),
  revokeToken: (id: string) => rpc<{ revoked: boolean }>("RevokeToken", { id }),

  // --- users (silo user ...) ---
  listUsers: async () => (await rpc<{ users: UserInfo[] }>("ListUsers")).users,
  createUser: (username: string, password: string, is_admin: boolean) =>
    rpc<{ user: UserInfo }>("CreateUser", { username, password, is_admin }),
  setUserDisabled: (username: string, disabled: boolean) =>
    rpc<{ user: UserInfo }>("SetUserDisabled", { username, disabled }),
  setUserPassword: (username: string, password: string) =>
    rpc<{ user: UserInfo }>("SetUserPassword", { username, password }),
  deleteUser: (username: string) => rpc<{ deleted: boolean }>("DeleteUser", { username }),

  // --- audit (silo audit) ---
  queryAudit: async (query: QueryAuditRequest) =>
    (await rpc<{ entries: AuditEntry[] }>("QueryAudit", query)).entries,

  // --- retention (silo repo set-prune-rule|get-prune-rule|prune-exempt, silo prune) ---
  getPruneRule: async (repo: string, channel: string) =>
    (await rpc<{ rule: PruneRule | null }>("GetPruneRule", { repo, channel })).rule,
  setPruneRule: (req: {
    repo: string;
    channel: string;
    keep_last_n?: number;
    max_age_days?: number;
    origin_scope: number;
  }) => rpc<{ rule: PruneRule }>("SetPruneRule", req),
  clearPruneRule: (repo: string, channel: string) =>
    rpc<{ cleared: boolean }>("ClearPruneRule", { repo, channel }),
  listPruneExemptions: async (repo: string, channel: string) =>
    (await rpc<{ names: string[] }>("ListPruneExemptions", { repo, channel })).names,
  setPruneExemption: (repo: string, channel: string, name: string, exempt: boolean) =>
    rpc<{ exempted: boolean }>("SetPruneExemption", { repo, channel, name, exempt }),
  runPrune: (repo: string, channel: string, dry_run: boolean) =>
    rpc<RunPruneResponse>("RunPrune", { repo, channel, dry_run }),

  // --- upstreams (silo repo add-upstream|update-upstream|remove-upstream|list-upstreams|sync-upstream) ---
  listUpstreams: async (repo: string, channel: string) =>
    (await rpc<{ upstreams: UpstreamInfo[] }>("ListUpstreams", { repo, channel })).upstreams,
  addUpstream: (req: AddUpstreamRequest) => rpc<{ upstream: UpstreamInfo }>("AddUpstream", req),
  updateUpstream: (req: UpdateUpstreamRequest) => rpc<{ upstream: UpstreamInfo }>("UpdateUpstream", req),
  removeUpstream: (repo: string, channel: string, name: string, prune: boolean) =>
    rpc<{ removed: boolean; packages_pruned: number }>("RemoveUpstream", { repo, channel, name, prune }),
  syncUpstream: (repo: string, channel: string, name: string) =>
    rpc<{ upstream: UpstreamInfo; packages_synced: number }>("SyncUpstream", { repo, channel, name }),

  // --- console-only reads ---
  stats: (days: number) => rpc<Stats>("GetStats", { days }),
  serverInfo: () => rpc<ServerInfo>("GetServerInfo"),
};
