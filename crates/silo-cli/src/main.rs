//! The `silo` CLI.
//!
//! One binary covers both audiences: developers publishing packages, and
//! admins managing tokens, users and the audit log. They share a single
//! credential (the token in `~/.config/silo/client.yaml`) and a single
//! transport (gRPC), so there's no separate admin tool to install, secure,
//! and keep in sync.

mod config;
mod login;
mod output;

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use config::ClientConfig;
use output::{bytes as fmt_bytes, dash_if_empty, print_json, timestamp, Table};
use serde_json::json;
use silo_core::BuildInfo;
use silo_pkg::PackageFormat;
use silo_proto::v1::admin_service_client::AdminServiceClient;
use silo_proto::v1::auth_service_client::AuthServiceClient;
use silo_proto::v1::publish_request::Payload;
use silo_proto::v1::publish_service_client::PublishServiceClient;
use silo_proto::v1::read_service_client::ReadServiceClient;
use silo_proto::v1::{
    CreateTokenRequest, CreateUserRequest, DeletePackageRequest, DeleteUserRequest,
    GetAuthInfoRequest, GetVersionRequest, ListPackagesRequest, ListReposRequest,
    ListTokensRequest, ListUsersRequest, LoginOidcRequest, LoginRequest,
    PackageFormat as ProtoFormat, PublishMetadata, PublishRequest, QueryAuditRequest,
    RebuildIndexRequest, RepoMode, RevokeTokenRequest, SetRepoModeRequest, SetUserDisabledRequest,
    SetUserPasswordRequest, TokenScope, WhoAmIRequest,
};
use tonic::transport::{Channel, ClientTlsConfig};

const DEFAULT_CONFIG: &str = "~/.config/silo/client.yaml";

#[derive(Parser)]
#[command(name = "silo", about = "Silo package registry client", version = silo_core::VERSION)]
struct Cli {
    #[arg(long, env = "SILO_CLIENT_CONFIG", default_value = DEFAULT_CONFIG, global = true)]
    config: String,

    /// Overrides `server_addr` from the config file.
    #[arg(long, env = "SILO_SERVER", global = true)]
    server: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Sign in and save a session token.
    Login(LoginArgs),
    /// Discard the saved token.
    Logout,
    /// Show what the current credential can do.
    Whoami {
        #[arg(long)]
        json: bool,
    },

    /// Validate and publish a package.
    Publish(PublishArgs),
    /// List packages in a repo/channel.
    List(ListArgs),
    /// List repos and channels this credential can see, plus any public
    /// repos. Works without signing in.
    Repos {
        #[arg(long)]
        json: bool,
    },
    /// Manage a repo's mode.
    #[command(subcommand)]
    Repo(RepoCommand),

    /// Manage API tokens.
    #[command(subcommand)]
    Token(TokenCommand),
    /// Manage users.
    #[command(subcommand)]
    User(UserCommand),
    /// Read the audit log.
    Audit(AuditArgs),
    /// Repair indexes and remove packages.
    #[command(subcommand)]
    Index(IndexCommand),
    /// Print the client and server versions.
    Version {
        #[arg(long)]
        json: bool,
    },
    /// Remove a published package.
    Delete {
        /// Package id, as shown by `silo list`.
        #[arg(long)]
        id: i64,
    },
}

#[derive(Args)]
struct LoginArgs {
    /// Server address, e.g. `http://silo.internal:8080`. Required the
    /// first time; remembered afterwards.
    #[arg(long)]
    server: Option<String>,
    #[arg(long, env = "SILO_USERNAME")]
    username: Option<String>,
    /// Prefer not to pass this on the command line — it lands in your
    /// shell history and in `ps` output. Omit it and you'll be prompted;
    /// in a pipeline set `SILO_PASSWORD`, or pipe it in on stdin.
    #[arg(long, env = "SILO_PASSWORD", hide_env_values = true)]
    password: Option<String>,
    /// Force the OIDC device flow even when password login is available.
    #[arg(long)]
    oidc: bool,
    /// An OIDC ID token obtained elsewhere, exchanged for a silo token
    /// without running the device flow. This is how CI signs in without a
    /// long-lived secret: GitHub Actions, GitLab CI and Kubernetes can all
    /// mint a short-lived ID token for the job.
    #[arg(long, env = "SILO_OIDC_TOKEN", hide_env_values = true, conflicts_with_all = ["username", "password"])]
    oidc_token: Option<String>,
    /// Read the ID token from a file. Kubernetes projects service-account
    /// tokens onto a path rather than into the environment.
    #[arg(long, conflicts_with = "oidc_token")]
    oidc_token_file: Option<PathBuf>,
    /// Print the token to stdout and write nothing to disk, for
    /// `export SILO_TOKEN=$(silo login --print-token ...)`. A CI runner's
    /// home directory usually outlives the job it belongs to.
    #[arg(long)]
    print_token: bool,
}

#[derive(Args)]
struct PublishArgs {
    path: PathBuf,
    #[arg(long)]
    repo: String,
    #[arg(long)]
    channel: String,
    /// Inferred from the file extension when omitted.
    #[arg(long)]
    format: Option<String>,
}

#[derive(Args)]
struct ListArgs {
    #[arg(long)]
    repo: String,
    #[arg(long)]
    channel: String,
    #[arg(long)]
    format: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand)]
enum RepoCommand {
    /// Set a repo's mode. Public adds unauthenticated read; it never
    /// changes who can write, and never revokes or deletes any token.
    /// Admin only.
    Set {
        repo: String,
        /// "public" or "private".
        #[arg(long)]
        mode: String,
    },
}

#[derive(Subcommand)]
enum TokenCommand {
    /// Create a token. The secret is printed once and never again.
    Create {
        #[arg(long)]
        name: String,
        /// read, write, or admin.
        #[arg(long, default_value = "read")]
        permission: String,
        /// Grant a specific repo. Repeat for several; omit for all repos.
        #[arg(long = "repo")]
        repos: Vec<String>,
        /// Expire after this many days. Omit for a token that never expires.
        #[arg(long)]
        expires_in_days: Option<i64>,
        #[arg(long)]
        json: bool,
    },
    List {
        #[arg(long)]
        include_revoked: bool,
        #[arg(long)]
        json: bool,
    },
    Revoke {
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        id: Option<String>,
    },
}

#[derive(Subcommand)]
enum UserCommand {
    Create {
        #[arg(long)]
        username: String,
        /// Omit to be prompted, or pass --oidc-only for an account that
        /// can only sign in through the identity provider.
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        oidc_only: bool,
        #[arg(long)]
        admin: bool,
    },
    List {
        #[arg(long)]
        json: bool,
    },
    Disable {
        #[arg(long)]
        username: String,
    },
    Enable {
        #[arg(long)]
        username: String,
    },
    SetPassword {
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: Option<String>,
    },
    Delete {
        #[arg(long)]
        username: String,
    },
}

#[derive(Args)]
struct AuditArgs {
    #[arg(long)]
    action: Option<String>,
    #[arg(long)]
    repo: Option<String>,
    #[arg(long)]
    actor: Option<String>,
    /// Show only rejected attempts.
    #[arg(long)]
    failures: bool,
    #[arg(long, default_value_t = 50)]
    limit: i32,
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand)]
enum IndexCommand {
    /// Rebuild an index from the database. Repairs a restored bucket or
    /// an index left stale by an interrupted publish.
    Rebuild {
        #[arg(long)]
        repo: String,
        #[arg(long)]
        channel: String,
        #[arg(long)]
        format: String,
        /// The index unit: an arch for apk, a package name for npm.
        /// Omit to rebuild every group of that format.
        #[arg(long)]
        group: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();
    let config_path = config::resolve_path(&cli.config);

    match cli.command {
        Command::Login(args) => cmd_login(&config_path, cli.server, args).await,
        Command::Logout => cmd_logout(&config_path),
        Command::Whoami { json } => cmd_whoami(&config_path, cli.server.as_deref(), json).await,
        Command::Publish(args) => cmd_publish(&config_path, cli.server.as_deref(), args).await,
        Command::List(args) => cmd_list(&config_path, cli.server.as_deref(), args).await,
        Command::Repos { json } => cmd_repos(&config_path, cli.server.as_deref(), json).await,
        Command::Repo(cmd) => cmd_repo(&config_path, cli.server.as_deref(), cmd).await,
        Command::Token(cmd) => cmd_token(&config_path, cli.server.as_deref(), cmd).await,
        Command::User(cmd) => cmd_user(&config_path, cli.server.as_deref(), cmd).await,
        Command::Audit(args) => cmd_audit(&config_path, cli.server.as_deref(), args).await,
        Command::Index(cmd) => cmd_index(&config_path, cli.server.as_deref(), cmd).await,
        Command::Version { json } => cmd_version(&config_path, cli.server.as_deref(), json).await,
        Command::Delete { id } => cmd_delete(&config_path, cli.server.as_deref(), id).await,
    }
}

// ------------------------------------------------------------- plumbing

/// A loaded config plus the token to present, resolved once per command.
struct Session {
    config: ClientConfig,
    addr: String,
    token: String,
}

fn session(config_path: &str, server_override: Option<&str>) -> anyhow::Result<Session> {
    // A missing config file is not an error: `SILO_TOKEN` plus
    // `SILO_SERVER` (or `--server`) is a complete credential, and that is
    // exactly how a pipeline should run — no file on a runner's disk that
    // outlives the job. `resolve_addr` and `resolve_token` produce the
    // errors when something really is missing, and both name the fix.
    let config = ClientConfig::load_or_default(config_path)?;
    if let Some(warning) = config.expiry_warning() {
        eprintln!("warning: {warning}");
    }
    let addr = resolve_addr(&config, server_override)?;
    let token = config.resolve_token()?;
    Ok(Session {
        config,
        addr,
        token,
    })
}

/// Like [`session`], but tolerates having no credential at all — for the
/// reads that work anonymously against public repos (`silo repos`, `silo
/// list`). A missing/expired token becomes `None` rather than an error;
/// the server decides what an uncredentialed caller can actually see.
struct OptionalSession {
    addr: String,
    token: Option<String>,
}

fn session_optional_auth(
    config_path: &str,
    server_override: Option<&str>,
) -> anyhow::Result<OptionalSession> {
    let config = ClientConfig::load_or_default(config_path)?;
    let addr = resolve_addr(&config, server_override)?;
    let token = config.resolve_token().ok();
    Ok(OptionalSession { addr, token })
}

/// Attaches the bearer token when there is one; leaves the request
/// uncredentialed otherwise, for calls that work anonymously.
fn maybe_auth<T>(message: T, token: Option<&str>) -> anyhow::Result<tonic::Request<T>> {
    let mut request = tonic::Request::new(message);
    if let Some(token) = token {
        authorize(&mut request, token)?;
    }
    Ok(request)
}

fn resolve_addr(config: &ClientConfig, override_addr: Option<&str>) -> anyhow::Result<String> {
    let addr = override_addr
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| Some(config.server_addr.clone()).filter(|s| !s.is_empty()))
        .ok_or_else(|| {
            anyhow::anyhow!("no server address — pass --server or run `silo login --server <addr>`")
        })?;
    Ok(normalize_addr(&addr))
}

/// Adds a scheme when the user omitted one. `host:9090` is what people
/// type; tonic requires a full URI and its error for a bare authority is
/// not self-explanatory. Defaults to `https://` since that's what every
/// real deployment (including `SILO_SERVER` in CI) actually uses.
fn normalize_addr(addr: &str) -> String {
    let addr = addr.trim().trim_end_matches('/');
    if addr.contains("://") {
        addr.to_string()
    } else {
        format!("https://{addr}")
    }
}

async fn connect(addr: &str) -> anyhow::Result<Channel> {
    let endpoint = Channel::from_shared(addr.to_string())
        .map_err(|e| anyhow::anyhow!("`{addr}` is not a valid server address: {e}"))?;
    let endpoint = if addr.starts_with("https://") {
        endpoint
            .tls_config(ClientTlsConfig::new().with_webpki_roots())
            .map_err(|e| anyhow::anyhow!("failed to configure TLS for {addr}: {e}"))?
    } else {
        endpoint
    };
    endpoint
        .connect()
        .await
        .map_err(|e| anyhow::anyhow!("failed to connect to {addr}: {e}"))
}

/// Attaches the bearer token to an outgoing request.
fn authorize<T>(request: &mut tonic::Request<T>, token: &str) -> anyhow::Result<()> {
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse()?);
    Ok(())
}

fn with_auth<T>(message: T, token: &str) -> anyhow::Result<tonic::Request<T>> {
    let mut request = tonic::Request::new(message);
    authorize(&mut request, token)?;
    Ok(request)
}

fn parse_format(value: &str) -> anyhow::Result<PackageFormat> {
    value
        .parse::<PackageFormat>()
        .map_err(|e| anyhow::anyhow!("{e}"))
}

fn to_proto_format(format: PackageFormat) -> ProtoFormat {
    match format {
        PackageFormat::Rpm => ProtoFormat::Rpm,
        PackageFormat::Apk => ProtoFormat::Apk,
        PackageFormat::Npm => ProtoFormat::Npm,
        PackageFormat::Pacman => ProtoFormat::Pacman,
    }
}

fn format_name(value: i32) -> String {
    match ProtoFormat::try_from(value) {
        Ok(ProtoFormat::Rpm) => "rpm".into(),
        Ok(ProtoFormat::Apk) => "apk".into(),
        Ok(ProtoFormat::Npm) => "npm".into(),
        Ok(ProtoFormat::Pacman) => "pacman".into(),
        _ => "-".into(),
    }
}

// ----------------------------------------------------------------- auth

/// Signs in and stores (or prints) a session token.
///
/// Four credential sources, in the order they're tried, because the same
/// command has to serve a developer at a terminal and a pipeline with no
/// terminal at all:
///
/// 1. An OIDC ID token supplied directly (`--oidc-token`,
///    `--oidc-token-file`, `SILO_OIDC_TOKEN`) — the secretless CI path.
/// 2. Username and password from flags or `SILO_USERNAME`/`SILO_PASSWORD`.
/// 3. The OIDC device flow, if the server has no password login or
///    `--oidc` was given.
/// 4. Interactive prompts.
///
/// Note what is deliberately *not* here: `SILO_TOKEN`. A CI job that
/// already has an API token doesn't log in at all — it sets that variable
/// and every command picks it up (see [`ClientConfig::resolve_token`]).
async fn cmd_login(
    config_path: &str,
    global_server: Option<String>,
    args: LoginArgs,
) -> anyhow::Result<()> {
    let mut config = ClientConfig::load_or_default(config_path)?;
    let addr = resolve_addr(&config, args.server.as_deref().or(global_server.as_deref()))?;

    let channel = connect(&addr).await?;
    let mut auth = AuthServiceClient::new(channel);

    let info = auth
        .get_auth_info(tonic::Request::new(GetAuthInfoRequest {}))
        .await?
        .into_inner();

    let supplied_id_token = match (&args.oidc_token, &args.oidc_token_file) {
        (Some(token), _) => Some(token.trim().to_string()),
        (None, Some(path)) => Some(
            std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", path.display()))?
                .trim()
                .to_string(),
        ),
        (None, None) => None,
    };

    if supplied_id_token.is_some() && !info.oidc_enabled {
        anyhow::bail!("this server has no OIDC configured, so it cannot accept an ID token");
    }

    let response = if let Some(id_token) = supplied_id_token {
        auth.login_oidc(tonic::Request::new(LoginOidcRequest { id_token }))
            .await?
            .into_inner()
            .into()
    } else if args.oidc || !info.password_login_enabled {
        if !info.oidc_enabled {
            anyhow::bail!("this server has no OIDC configured");
        }
        // The device flow needs a human to open a URL. Failing here beats
        // a CI job that hangs until its timeout with the reason buried in
        // a log nobody reads.
        if !login::is_interactive() {
            anyhow::bail!(
                "the OIDC device flow needs a browser, and this session has no terminal — \
                 pass --oidc-token with an ID token from your CI provider, or use an API \
                 token via SILO_TOKEN"
            );
        }
        let id_token = login::oidc_device_flow(&info).await?;
        auth.login_oidc(tonic::Request::new(LoginOidcRequest { id_token }))
            .await?
            .into_inner()
            .into()
    } else {
        let username = match args.username {
            Some(username) => username,
            None => {
                require_interactive("a username", "SILO_USERNAME")?;
                login::prompt_line("Username: ")?
            }
        };
        let password = match args.password {
            Some(password) => password,
            // `prompt_password` reads stdin when there's no TTY, so
            // `echo pw | silo login --username x` works in a script.
            None => login::prompt_password("Password: ")?,
        };
        auth.login(tonic::Request::new(LoginRequest { username, password }))
            .await?
            .into_inner()
            .into()
    };
    let response: SignedIn = response;

    if args.print_token {
        // Only the token goes to stdout, so `$(silo login --print-token)`
        // captures a usable value. Everything else goes to stderr.
        println!("{}", response.token);
        eprintln!(
            "Signed in to {addr} as {}{}; session expires {}.",
            response.username,
            if response.is_admin { " (admin)" } else { "" },
            timestamp(response.expires_at)
        );
        return Ok(());
    }

    config.server_addr = addr.clone();
    config.token = Some(response.token);
    config.token_expires_at = Some(response.expires_at);
    config.username = Some(response.username.clone());
    config.save(config_path)?;

    println!(
        "Signed in to {addr} as {}{}.",
        response.username,
        if response.is_admin { " (admin)" } else { "" }
    );
    println!("Session expires {}.", timestamp(response.expires_at));
    println!("Credentials saved to {config_path}");
    Ok(())
}

/// What the CLI actually needs from a successful sign-in.
///
/// The two login RPCs return separate wire messages — deliberately, so
/// either can grow a field without imposing it on the other — that happen
/// to be field-identical today. This is where the two converge, so the
/// rest of the command does not care which flow produced the session.
struct SignedIn {
    token: String,
    username: String,
    is_admin: bool,
    expires_at: i64,
}

impl From<silo_proto::v1::LoginResponse> for SignedIn {
    fn from(r: silo_proto::v1::LoginResponse) -> Self {
        Self {
            token: r.token,
            username: r.username,
            is_admin: r.is_admin,
            expires_at: r.expires_at,
        }
    }
}

impl From<silo_proto::v1::LoginOidcResponse> for SignedIn {
    fn from(r: silo_proto::v1::LoginOidcResponse) -> Self {
        Self {
            token: r.token,
            username: r.username,
            is_admin: r.is_admin,
            expires_at: r.expires_at,
        }
    }
}

/// Refuses to prompt when there is nobody to answer, naming the
/// environment variable that would have supplied the value.
fn require_interactive(what: &str, env_var: &str) -> anyhow::Result<()> {
    if login::is_interactive() {
        return Ok(());
    }
    anyhow::bail!(
        "{what} is required, and this session has no terminal to prompt on — set {env_var}"
    )
}

fn cmd_logout(config_path: &str) -> anyhow::Result<()> {
    let mut config = ClientConfig::load_or_default(config_path)?;
    if config.token.is_none() {
        println!("Not signed in.");
        return Ok(());
    }
    // The server-side session token isn't revoked here: it expires on its
    // own, and revoking would need a call this credential may no longer be
    // able to make. Use `silo token revoke` to kill it immediately.
    config.token = None;
    config.token_expires_at = None;
    config.username = None;
    config.save(config_path)?;
    println!("Signed out. The saved token has been removed from {config_path}");
    Ok(())
}

async fn cmd_whoami(config_path: &str, server: Option<&str>, json: bool) -> anyhow::Result<()> {
    let session = session(config_path, server)?;
    let mut client = AuthServiceClient::new(connect(&session.addr).await?);
    let info = client
        .who_am_i(with_auth(WhoAmIRequest {}, &session.token)?)
        .await?
        .into_inner();

    if json {
        return print_json(&json!({
            "server": session.addr,
            "token_name": info.token_name,
            "username": info.username,
            "permission": info.permission,
            "all_repos": info.all_repos,
            "repos": info.repos,
            "is_admin": info.is_admin,
            "expires_at": info.expires_at,
        }));
    }

    println!("server:     {}", session.addr);
    println!("token:      {}", info.token_name);
    if !info.username.is_empty() {
        println!("user:       {}", info.username);
    }
    println!("permission: {}", info.permission);
    println!(
        "repos:      {}",
        if info.all_repos {
            "all".to_string()
        } else if info.repos.is_empty() {
            "(none)".to_string()
        } else {
            info.repos.join(", ")
        }
    );
    println!("expires:    {}", timestamp(info.expires_at));
    let _ = session.config;
    Ok(())
}

/// Version skew between a CLI and a server is a common cause of confusing
/// failures, so this reports both sides rather than just the binary's own
/// version — which is what `--version` already does.
///
/// The server half is best-effort. Not being able to reach a server is a
/// perfectly normal state for this command (no config yet, wrong address,
/// server down) and is exactly the situation where you most want to know
/// what your client is, so an unreachable server is reported as a line of
/// output rather than a non-zero exit.
async fn cmd_version(config_path: &str, server: Option<&str>, json: bool) -> anyhow::Result<()> {
    let client = BuildInfo::current();
    let server = fetch_server_version(config_path, server).await;

    if json {
        return print_json(&json!({
            "client": client,
            "server": match &server {
                Ok(info) => json!({
                    "version": info.version,
                    "commit": info.commit,
                    "built_at": info.built_at,
                    "formats": info.formats,
                }),
                Err(e) => json!({ "error": e.to_string() }),
            },
        }));
    }

    println!("client:  {}", client.short());
    println!("  built: {}", client.built_at);
    match server {
        Ok(info) => {
            let info_short = BuildInfo {
                version: info.version.clone(),
                commit: info.commit.clone(),
                built_at: info.built_at.clone(),
            };
            println!("server:  {}", info_short.short());
            println!("  built: {}", info.built_at);
            println!("  formats: {}", dash_if_empty(info.formats.join(", ")));
            if info.version != client.version {
                println!();
                println!(
                    "note: client {} and server {} are different versions",
                    client.version, info.version
                );
            }
        }
        Err(e) => println!("server:  unavailable ({e})"),
    }
    Ok(())
}

/// Reads the server's version without requiring a credential — GetVersion
/// is unauthenticated, so this works before `silo login`.
async fn fetch_server_version(
    config_path: &str,
    server: Option<&str>,
) -> anyhow::Result<silo_proto::v1::GetVersionResponse> {
    let config = ClientConfig::load_or_default(config_path).unwrap_or_default();
    let addr = resolve_addr(&config, server)?;
    let mut client = AuthServiceClient::new(connect(&addr).await?);
    client
        .get_version(tonic::Request::new(GetVersionRequest {}))
        .await
        .map(|r| r.into_inner())
        .map_err(|status| match status.code() {
            // The method not existing *is* the answer: this server predates
            // GetVersion. Saying so is far more useful than relaying a bare
            // "Unimplemented".
            tonic::Code::Unimplemented => {
                anyhow::anyhow!("server is older than this client and does not report its version")
            }
            _ => anyhow::anyhow!("{status}"),
        })
}

// -------------------------------------------------------------- packages

async fn cmd_publish(
    config_path: &str,
    server: Option<&str>,
    args: PublishArgs,
) -> anyhow::Result<()> {
    let session = session(config_path, server)?;

    let bytes = std::fs::read(&args.path)
        .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", args.path.display()))?;

    let format = match &args.format {
        Some(name) => parse_format(name)?,
        None => {
            let filename = args
                .path
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_default();
            PackageFormat::from_filename(&filename).ok_or_else(|| {
                anyhow::anyhow!(
                    "could not infer the format of `{filename}` — pass --format rpm|apk|npm"
                )
            })?
        }
    };

    // Validate locally first: a malformed package shouldn't cost a
    // round trip, and the local error names the file the user typed.
    let parsed = format.handler().parse(&bytes).map_err(|e| {
        anyhow::anyhow!(
            "{} is not a valid {format} package: {e}",
            args.path.display()
        )
    })?;
    println!("validated {} ({})", parsed.filename, parsed.nevra());

    let mut client = PublishServiceClient::new(connect(&session.addr).await?);

    let mut messages = vec![PublishRequest {
        payload: Some(Payload::Metadata(PublishMetadata {
            repo: args.repo.clone(),
            channel: args.channel.clone(),
            format: to_proto_format(format) as i32,
        })),
    }];
    for chunk in bytes.chunks(64 * 1024) {
        messages.push(PublishRequest {
            payload: Some(Payload::Chunk(chunk.to_vec())),
        });
    }

    let request = with_auth(tokio_stream::iter(messages), &session.token)?;
    let response = client.publish(request).await?.into_inner();

    println!(
        "published {} -> {} ({}, {}{})",
        parsed.nevra(),
        response.storage_path,
        format,
        fmt_bytes(response.size_bytes),
        if response.signed { ", signed" } else { "" }
    );
    if !response.index_objects.is_empty() {
        println!("index updated: {}", response.index_objects.join(", "));
    }
    Ok(())
}

async fn cmd_list(config_path: &str, server: Option<&str>, args: ListArgs) -> anyhow::Result<()> {
    let session = session_optional_auth(config_path, server)?;
    let format = args.format.as_deref().map(parse_format).transpose()?;

    let mut client = ReadServiceClient::new(connect(&session.addr).await?);
    let response = client
        .list_packages(maybe_auth(
            ListPackagesRequest {
                repo: args.repo.clone(),
                channel: args.channel.clone(),
                format: format.map(|f| to_proto_format(f) as i32).unwrap_or(0),
            },
            session.token.as_deref(),
        )?)
        .await?
        .into_inner();

    if args.json {
        let packages: Vec<_> = response
            .packages
            .iter()
            .map(|p| {
                json!({
                    "id": p.id,
                    "format": format_name(p.format),
                    "name": p.name,
                    "version": p.version,
                    "release": p.release,
                    "arch": p.arch,
                    "storage_path": p.storage_path,
                    "size_bytes": p.size_bytes,
                    "sha256": p.sha256,
                    "published_at": p.published_at,
                })
            })
            .collect();
        return print_json(&json!(packages));
    }

    let mut table = Table::new(&[
        "ID",
        "FORMAT",
        "NAME",
        "VERSION",
        "ARCH",
        "SIZE",
        "PUBLISHED",
    ]);
    for pkg in &response.packages {
        let version = if pkg.release.is_empty() {
            pkg.version.clone()
        } else {
            format!("{}-{}", pkg.version, pkg.release)
        };
        table.row(vec![
            pkg.id.to_string(),
            format_name(pkg.format),
            pkg.name.clone(),
            version,
            dash_if_empty(&pkg.arch),
            fmt_bytes(pkg.size_bytes),
            timestamp(pkg.published_at),
        ]);
    }
    table.print(&format!("no packages in {}/{}", args.repo, args.channel));
    Ok(())
}

async fn cmd_repos(config_path: &str, server: Option<&str>, json: bool) -> anyhow::Result<()> {
    let session = session_optional_auth(config_path, server)?;
    let mut client = ReadServiceClient::new(connect(&session.addr).await?);
    let response = client
        .list_repos(maybe_auth(ListReposRequest {}, session.token.as_deref())?)
        .await?
        .into_inner();

    if json {
        let repos: Vec<_> = response
            .repos
            .iter()
            .map(|r| {
                json!({
                    "repo": r.repo,
                    "channel": r.channel,
                    "format": format_name(r.format),
                    "mode": mode_name(r.mode),
                    "packages": r.package_count,
                    "total_bytes": r.total_bytes,
                })
            })
            .collect();
        return print_json(&json!(repos));
    }

    let mut table = Table::new(&["REPO", "CHANNEL", "FORMAT", "MODE", "PACKAGES", "SIZE"]);
    for repo in &response.repos {
        table.row(vec![
            repo.repo.clone(),
            repo.channel.clone(),
            format_name(repo.format),
            mode_name(repo.mode),
            repo.package_count.to_string(),
            fmt_bytes(repo.total_bytes),
        ]);
    }
    table.print("no repos yet — publish something to create one");
    Ok(())
}

fn mode_name(value: i32) -> String {
    match RepoMode::try_from(value) {
        Ok(RepoMode::Public) => "public".into(),
        Ok(RepoMode::Private) => "private".into(),
        _ => "-".into(),
    }
}

async fn cmd_repo(config_path: &str, server: Option<&str>, cmd: RepoCommand) -> anyhow::Result<()> {
    let session = session(config_path, server)?;
    let mut client = AdminServiceClient::new(connect(&session.addr).await?);

    match cmd {
        RepoCommand::Set { repo, mode } => {
            let mode = match mode.to_ascii_lowercase().as_str() {
                "public" => RepoMode::Public,
                "private" => RepoMode::Private,
                other => anyhow::bail!("mode must be `public` or `private`, got `{other}`"),
            };
            let response = client
                .set_repo_mode(with_auth(
                    SetRepoModeRequest {
                        repo,
                        mode: mode as i32,
                    },
                    &session.token,
                )?)
                .await?
                .into_inner();
            println!("{}: {}", response.repo, mode_name(response.mode));
        }
    }
    Ok(())
}

async fn cmd_delete(config_path: &str, server: Option<&str>, id: i64) -> anyhow::Result<()> {
    let session = session(config_path, server)?;
    let mut client = AdminServiceClient::new(connect(&session.addr).await?);
    let response = client
        .delete_package(with_auth(DeletePackageRequest { id }, &session.token)?)
        .await?
        .into_inner();

    if response.deleted {
        println!("deleted {} and rebuilt the index", response.storage_path);
    } else {
        println!("no package with id {id}");
    }
    Ok(())
}

// ---------------------------------------------------------------- tokens

async fn cmd_token(
    config_path: &str,
    server: Option<&str>,
    cmd: TokenCommand,
) -> anyhow::Result<()> {
    let session = session(config_path, server)?;
    let mut client = AdminServiceClient::new(connect(&session.addr).await?);

    match cmd {
        TokenCommand::Create {
            name,
            permission,
            repos,
            expires_in_days,
            json,
        } => {
            let scope = if repos.is_empty() {
                TokenScope::All
            } else {
                TokenScope::Repos
            };
            let expires_at = expires_in_days
                .map(|days| (chrono::Utc::now() + chrono::Duration::days(days)).timestamp())
                .unwrap_or(0);

            let response = client
                .create_token(with_auth(
                    CreateTokenRequest {
                        name: name.clone(),
                        permission: permission.clone(),
                        scope: scope as i32,
                        repos: repos.clone(),
                        expires_at,
                    },
                    &session.token,
                )?)
                .await?
                .into_inner();

            let info = response.info.unwrap_or_default();
            if json {
                return print_json(&json!({
                    "token": response.token,
                    "id": info.id,
                    "name": info.name,
                    "permission": info.permission,
                    "all_repos": info.all_repos,
                    "repos": info.repos,
                    "expires_at": info.expires_at,
                }));
            }

            println!("Token created. This is the only time it is shown.\n");
            println!("  name:       {}", info.name);
            println!("  permission: {}", info.permission);
            println!(
                "  repos:      {}",
                if info.all_repos {
                    "all".to_string()
                } else {
                    info.repos.join(", ")
                }
            );
            println!("  expires:    {}", timestamp(info.expires_at));
            println!("\n  {}\n", response.token);
        }

        TokenCommand::List {
            include_revoked,
            json,
        } => {
            let response = client
                .list_tokens(with_auth(
                    ListTokensRequest { include_revoked },
                    &session.token,
                )?)
                .await?
                .into_inner();

            if json {
                let tokens: Vec<_> = response
                    .tokens
                    .iter()
                    .map(|t| {
                        json!({
                            "id": t.id,
                            "name": t.name,
                            "prefix": t.prefix,
                            "permission": t.permission,
                            "all_repos": t.all_repos,
                            "repos": t.repos,
                            "created_at": t.created_at,
                            "expires_at": t.expires_at,
                            "last_used_at": t.last_used_at,
                            "revoked_at": t.revoked_at,
                        })
                    })
                    .collect();
                return print_json(&json!(tokens));
            }

            let mut table = Table::new(&[
                "NAME",
                "PERMISSION",
                "REPOS",
                "CREATED",
                "EXPIRES",
                "LAST USED",
                "STATUS",
            ]);
            for token in &response.tokens {
                table.row(vec![
                    token.name.clone(),
                    token.permission.clone(),
                    if token.all_repos {
                        "all".to_string()
                    } else {
                        dash_if_empty(token.repos.join(","))
                    },
                    timestamp(token.created_at),
                    timestamp(token.expires_at),
                    timestamp(token.last_used_at),
                    if token.revoked_at > 0 {
                        "revoked".to_string()
                    } else {
                        "active".to_string()
                    },
                ]);
            }
            table.print("no tokens");
        }

        TokenCommand::Revoke { name, id } => {
            if name.is_none() && id.is_none() {
                anyhow::bail!("pass --name or --id");
            }
            let response = client
                .revoke_token(with_auth(
                    RevokeTokenRequest {
                        id: id.unwrap_or_default(),
                        name: name.clone().unwrap_or_default(),
                    },
                    &session.token,
                )?)
                .await?
                .into_inner();

            if response.revoked {
                println!("token revoked");
            } else {
                println!("no matching active token");
            }
        }
    }
    Ok(())
}

// ----------------------------------------------------------------- users

async fn cmd_user(config_path: &str, server: Option<&str>, cmd: UserCommand) -> anyhow::Result<()> {
    let session = session(config_path, server)?;
    let mut client = AdminServiceClient::new(connect(&session.addr).await?);

    match cmd {
        UserCommand::Create {
            username,
            password,
            oidc_only,
            admin,
        } => {
            let password = if oidc_only {
                String::new()
            } else {
                match password {
                    Some(password) => password,
                    None => login::prompt_password(&format!("Password for {username}: "))?,
                }
            };

            let user = client
                .create_user(with_auth(
                    CreateUserRequest {
                        username: username.clone(),
                        password,
                        is_admin: admin,
                    },
                    &session.token,
                )?)
                .await?
                .into_inner()
                .user
                .unwrap_or_default();

            println!(
                "created user {}{}{}",
                user.username,
                if user.is_admin { " (admin)" } else { "" },
                if user.oidc_only { " (OIDC only)" } else { "" }
            );
        }

        UserCommand::List { json } => {
            let response = client
                .list_users(with_auth(ListUsersRequest {}, &session.token)?)
                .await?
                .into_inner();

            if json {
                let users: Vec<_> = response
                    .users
                    .iter()
                    .map(|u| {
                        json!({
                            "username": u.username,
                            "is_admin": u.is_admin,
                            "disabled": u.disabled,
                            "oidc_only": u.oidc_only,
                            "created_at": u.created_at,
                            "last_login_at": u.last_login_at,
                        })
                    })
                    .collect();
                return print_json(&json!(users));
            }

            let mut table = Table::new(&["USERNAME", "ADMIN", "AUTH", "STATUS", "LAST LOGIN"]);
            for user in &response.users {
                table.row(vec![
                    user.username.clone(),
                    if user.is_admin { "yes" } else { "no" }.to_string(),
                    if user.oidc_only { "oidc" } else { "password" }.to_string(),
                    if user.disabled { "disabled" } else { "active" }.to_string(),
                    timestamp(user.last_login_at),
                ]);
            }
            table.print("no users");
        }

        UserCommand::Disable { username } | UserCommand::Enable { username }
            if username.trim().is_empty() =>
        {
            anyhow::bail!("--username is required");
        }

        UserCommand::Disable { username } => {
            let user = client
                .set_user_disabled(with_auth(
                    SetUserDisabledRequest {
                        username,
                        disabled: true,
                    },
                    &session.token,
                )?)
                .await?
                .into_inner();
            println!("disabled {}", user.user.unwrap_or_default().username);
        }

        UserCommand::Enable { username } => {
            let user = client
                .set_user_disabled(with_auth(
                    SetUserDisabledRequest {
                        username,
                        disabled: false,
                    },
                    &session.token,
                )?)
                .await?
                .into_inner();
            println!("enabled {}", user.user.unwrap_or_default().username);
        }

        UserCommand::SetPassword { username, password } => {
            let password = match password {
                Some(password) => password,
                None => login::prompt_password(&format!("New password for {username}: "))?,
            };
            let user = client
                .set_user_password(with_auth(
                    SetUserPasswordRequest { username, password },
                    &session.token,
                )?)
                .await?
                .into_inner();
            println!(
                "password updated for {}",
                user.user.unwrap_or_default().username
            );
        }

        UserCommand::Delete { username } => {
            let response = client
                .delete_user(with_auth(
                    DeleteUserRequest {
                        username: username.clone(),
                    },
                    &session.token,
                )?)
                .await?
                .into_inner();
            if response.deleted {
                println!("deleted {username}");
            } else {
                println!("no user {username}");
            }
        }
    }
    Ok(())
}

// ----------------------------------------------------------------- audit

async fn cmd_audit(config_path: &str, server: Option<&str>, args: AuditArgs) -> anyhow::Result<()> {
    let session = session(config_path, server)?;
    let mut client = AdminServiceClient::new(connect(&session.addr).await?);

    let response = client
        .query_audit(with_auth(
            QueryAuditRequest {
                action: args.action.unwrap_or_default(),
                repo: args.repo.unwrap_or_default(),
                actor: args.actor.unwrap_or_default(),
                only_failures: args.failures,
                limit: args.limit,
            },
            &session.token,
        )?)
        .await?
        .into_inner();

    if args.json {
        let entries: Vec<_> = response
            .entries
            .iter()
            .map(|e| {
                json!({
                    "id": e.id,
                    "at": e.at,
                    "action": e.action,
                    "actor_kind": e.actor_kind,
                    "actor": e.actor_name,
                    "repo": e.repo,
                    "channel": e.channel,
                    "target": e.target,
                    "success": e.success,
                    "remote_addr": e.remote_addr,
                    "detail": serde_json::from_str::<serde_json::Value>(&e.detail)
                        .unwrap_or(serde_json::Value::Null),
                })
            })
            .collect();
        return print_json(&json!(entries));
    }

    let mut table = Table::new(&["WHEN", "ACTION", "ACTOR", "REPO", "TARGET", "OK"]);
    for entry in &response.entries {
        table.row(vec![
            timestamp(entry.at),
            entry.action.clone(),
            dash_if_empty(&entry.actor_name),
            dash_if_empty(if entry.channel.is_empty() {
                entry.repo.clone()
            } else {
                format!("{}/{}", entry.repo, entry.channel)
            }),
            dash_if_empty(&entry.target),
            if entry.success { "yes" } else { "NO" }.to_string(),
        ]);
    }
    table.print("no audit entries match");
    Ok(())
}

// ----------------------------------------------------------------- index

async fn cmd_index(
    config_path: &str,
    server: Option<&str>,
    cmd: IndexCommand,
) -> anyhow::Result<()> {
    let session = session(config_path, server)?;
    let mut client = AdminServiceClient::new(connect(&session.addr).await?);

    match cmd {
        IndexCommand::Rebuild {
            repo,
            channel,
            format,
            group,
        } => {
            let format = parse_format(&format)?;
            let response = client
                .rebuild_index(with_auth(
                    RebuildIndexRequest {
                        repo: repo.clone(),
                        channel: channel.clone(),
                        format: to_proto_format(format) as i32,
                        index_group: group.unwrap_or_default(),
                    },
                    &session.token,
                )?)
                .await?
                .into_inner();

            println!(
                "rebuilt {} index group(s) in {repo}/{channel}, {} object(s) written",
                response.groups_rebuilt,
                response.objects.len()
            );
            for object in &response.objects {
                println!("  {object}");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_cli_definition_is_internally_consistent() {
        // Catches duplicate flags, bad defaults, and conflicting short
        // options at test time rather than on a user's first run.
        Cli::command().debug_assert();
    }

    #[test]
    fn bare_host_ports_get_a_scheme() {
        assert_eq!(
            normalize_addr("silo.internal:9090"),
            "https://silo.internal:9090"
        );
        assert_eq!(
            normalize_addr("https://silo.example.com"),
            "https://silo.example.com"
        );
        assert_eq!(
            normalize_addr("http://silo.internal:9090/"),
            "http://silo.internal:9090"
        );
        assert_eq!(normalize_addr("  silo:9090  "), "https://silo:9090");
    }

    #[test]
    fn the_server_flag_overrides_the_config() {
        let config = ClientConfig {
            server_addr: "http://from-config:9090".into(),
            ..Default::default()
        };
        assert_eq!(
            resolve_addr(&config, Some("override:1234")).unwrap(),
            "https://override:1234"
        );
        assert_eq!(
            resolve_addr(&config, None).unwrap(),
            "http://from-config:9090"
        );
        // An empty override falls through rather than blanking the address.
        assert_eq!(
            resolve_addr(&config, Some("")).unwrap(),
            "http://from-config:9090"
        );
    }

    #[test]
    fn a_missing_server_address_explains_how_to_set_one() {
        let err = resolve_addr(&ClientConfig::default(), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--server"));
        assert!(err.contains("silo login"));
    }

    #[test]
    fn formats_parse_from_their_cli_spelling() {
        assert_eq!(parse_format("rpm").unwrap(), PackageFormat::Rpm);
        assert_eq!(parse_format("apk").unwrap(), PackageFormat::Apk);
        assert_eq!(parse_format("alpine").unwrap(), PackageFormat::Apk);
        assert_eq!(parse_format("npm").unwrap(), PackageFormat::Npm);
        assert!(parse_format("deb").is_err());
    }

    #[test]
    fn wire_format_values_render_back_to_names() {
        for format in PackageFormat::ALL {
            assert_eq!(format_name(to_proto_format(format) as i32), format.as_str());
        }
        assert_eq!(format_name(0), "-", "unspecified renders as a dash");
        assert_eq!(format_name(99), "-");
    }

    #[test]
    fn publish_infers_the_format_from_the_file_extension() {
        assert_eq!(
            PackageFormat::from_filename("foo-1.0-1.x86_64.rpm"),
            Some(PackageFormat::Rpm)
        );
        assert_eq!(
            PackageFormat::from_filename("foo-1.0-r0.apk"),
            Some(PackageFormat::Apk)
        );
        assert_eq!(
            PackageFormat::from_filename("widget-1.0.0.tgz"),
            Some(PackageFormat::Npm)
        );
        assert_eq!(PackageFormat::from_filename("notes.txt"), None);
    }

    #[test]
    fn auth_metadata_uses_the_bearer_scheme() {
        let request = with_auth((), "silo_abc_def").unwrap();
        assert_eq!(
            request.metadata().get("authorization").unwrap(),
            "Bearer silo_abc_def"
        );
    }
}
