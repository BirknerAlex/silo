use std::net::SocketAddr;
use std::sync::Arc;

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

    let grpc_addr: SocketAddr = config.grpc_addr.parse()?;
    let http_addr = config.http_addr.clone();

    let state = Arc::new(AppState {
        publish: PublishContext {
            storage: storage.clone(),
            db: db.clone(),
            signers: signers.clone(),
            public_base_url: config.public_base_url.clone(),
        },
        config,
        storage,
        db,
        oidc,
        metrics: Metrics::new()?,
    });

    let grpc_server = tonic::transport::Server::builder()
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
        }))
        .serve(grpc_addr);

    let http_router = http::router(state.clone());
    let http_listener = tokio::net::TcpListener::bind(&http_addr).await?;
    // `into_make_service_with_connect_info` is what makes the client IP
    // available to handlers, which the audit log records.
    let http_server = axum::serve(
        http_listener,
        http_router.into_make_service_with_connect_info::<SocketAddr>(),
    );

    tokio::spawn(maintenance::run(state.clone()));

    tracing::info!(
        version = %silo_core::BuildInfo::current().short(),
        grpc_addr = %grpc_addr,
        http_addr = %http_addr,
        formats = "rpm,apk,npm",
        "silo-server starting"
    );

    tokio::select! {
        res = grpc_server => res.map_err(anyhow::Error::from),
        res = http_server => res.map_err(anyhow::Error::from),
    }
}
