use std::sync::Arc;

use clap::Parser;
use silo_core::{Config, Storage};
use silo_proto::v1::publish_service_server::PublishServiceServer;
use silo_proto::v1::read_service_server::ReadServiceServer;
use silo_server::{grpc, http, AppState};

#[derive(Parser)]
struct Args {
    #[arg(long, env = "SILO_CONFIG", default_value = "/etc/silo/config.yaml")]
    config: String,
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
    let storage = Storage::from_config(&config.storage)?;
    let grpc_addr = config.grpc_addr.parse()?;
    let http_addr = config.http_addr.clone();

    let state = Arc::new(AppState { config, storage });

    let publish_svc = PublishServiceServer::new(grpc::PublishServiceImpl {
        state: state.clone(),
    });
    let read_svc = ReadServiceServer::new(grpc::ReadServiceImpl {
        state: state.clone(),
    });

    let grpc_server = tonic::transport::Server::builder()
        .add_service(publish_svc)
        .add_service(read_svc)
        .serve(grpc_addr);

    let http_router = http::router(state.clone());
    let http_listener = tokio::net::TcpListener::bind(&http_addr).await?;
    let http_server = axum::serve(http_listener, http_router);

    tracing::info!(grpc_addr = %grpc_addr, http_addr = %http_addr, "silo-server starting");

    tokio::select! {
        res = grpc_server => res.map_err(anyhow::Error::from),
        res = http_server => res.map_err(anyhow::Error::from),
    }
}
