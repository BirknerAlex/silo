use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use axum::extract::{ConnectInfo, Request};
use axum::middleware::{self, Next};
use axum::response::Response;
use clap::Parser;
use silo_core::oidc::Verifier;
use silo_core::{Config, PublishContext, Signers, Storage};
use silo_db::Db;
use silo_proto::v1::admin_service_server::AdminServiceServer;
use silo_proto::v1::auth_service_server::AuthServiceServer;
use silo_proto::v1::publish_service_server::PublishServiceServer;
use silo_proto::v1::read_service_server::ReadServiceServer;
use silo_server::metrics::Metrics;
use silo_server::{admin, bootstrap, grpc, grpc_auth, http, maintenance, AppState};

#[derive(Parser)]
struct Args {
    #[arg(long, env = "SILO_CONFIG", default_value = "/etc/silo/config.yaml")]
    config: String,

    /// Apply pending migrations and exit. Useful as a Kubernetes Job when
    /// you'd rather not have replicas migrate during a rolling deploy —
    /// though they can, safely, since sqlx takes an advisory lock.
    #[arg(long)]
    migrate_only: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let config = Config::load(&args.config)?;

    // Everything that can fail on bad input fails here, before the server
    // starts accepting traffic: key material, the database, the identity
    // provider. A registry that boots and then rejects the first publish
    // is much harder to diagnose than one that refuses to boot.
    let signers = Signers::from_config(&config.signing)?;
    let storage = Storage::from_config(&config.storage)?;
    let upstream_secrets = config
        .upstream_secret
        .as_ref()
        .map(|c| silo_core::secret_box::SecretBox::new(&c.key))
        .transpose()?;

    let db = Db::connect(
        &config
            .database
            .to_db_config(config.auth.token_pepper.clone()),
    )
    .await?;

    if args.migrate_only {
        tracing::info!("migrations applied; exiting because --migrate-only was given");
        return Ok(());
    }

    bootstrap::run(&db, &config.auth).await?;

    let oidc = match &config.oidc {
        Some(cfg) => {
            let verifier = Verifier::new(cfg.clone()).await?;
            tracing::info!(issuer = %cfg.issuer, exclusive = cfg.exclusive, "OIDC enabled");
            Some(verifier)
        }
        None => None,
    };

    let addr = config.addr.clone();

    let state = Arc::new(AppState {
        publish: PublishContext {
            storage: storage.clone(),
            db: db.clone(),
            signers: signers.clone(),
            public_base_url: config.public_base_url.clone(),
            upstream_index_cache: Default::default(),
        },
        config,
        storage,
        db,
        oidc,
        metrics: Metrics::new()?,
        upstream_secrets,
        // A connect timeout on top of every individual `UpstreamHttp`
        // call's own request timeout (see `upstream.rs`): the request
        // timeout bounds one fetch, but a client built with
        // `reqwest::Client::new()`'s defaults has no connect timeout at
        // all, so a mirror that accepts a TCP connection and then never
        // sends anything could otherwise hang past that. This is the
        // client every pull-through request and `maintenance::run_upstream_sync`
        // share.
        upstream_http: reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .context("could not build the upstream HTTP client")?,
    });

    // gRPC and the package-manager HTTP surface share one listener. They
    // never collide on path (gRPC methods live under their
    // fully-qualified service name, e.g. `/silo.v1.PublishService/*`,
    // which no HTTP route shape matches) or on protocol (hyper's
    // connection builder sniffs the HTTP/2 client preface per connection,
    // so plain HTTP/1.1 requests and prior-knowledge h2c gRPC calls are
    // dispatched to the right stack automatically).
    let mut grpc_routes = tonic::service::Routes::builder();
    grpc_routes
        .add_service(PublishServiceServer::new(grpc::PublishServiceImpl {
            state: state.clone(),
        }))
        .add_service(ReadServiceServer::new(grpc::ReadServiceImpl {
            state: state.clone(),
        }))
        .add_service(AuthServiceServer::new(grpc_auth::AuthServiceImpl {
            state: state.clone(),
        }))
        .add_service(AdminServiceServer::new(admin::AdminServiceImpl {
            state: state.clone(),
        }));
    let grpc_routes = grpc_routes.routes().into_axum_router();

    let app = http::router(state.clone())
        .merge(grpc_routes)
        // gRPC handlers read the peer IP via `tonic::Request::remote_addr`,
        // which looks for a `TcpConnectInfo` extension that tonic's own
        // transport normally inserts. Serving through plain axum/hyper
        // instead, this bridges it from the `ConnectInfo` extension that
        // `into_make_service_with_connect_info` inserts below.
        .layer(middleware::from_fn(inject_tcp_connect_info));

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    // `into_make_service_with_connect_info` is what makes the client IP
    // available to handlers, which the audit log records.
    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    );

    tokio::spawn(maintenance::run(state.clone()));

    tracing::info!(
        version = %silo_core::BuildInfo::current().short(),
        addr = %addr,
        formats = "rpm,apk,npm",
        "silo-server starting"
    );

    server.await.map_err(anyhow::Error::from)
}

async fn inject_tcp_connect_info(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut request: Request,
    next: Next,
) -> Response {
    request
        .extensions_mut()
        .insert(tonic::transport::server::TcpConnectInfo {
            local_addr: None,
            remote_addr: Some(addr),
        });
    next.run(request).await
}
