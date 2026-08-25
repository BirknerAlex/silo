mod config;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use config::ClientConfig;
use silo_proto::v1::publish_request::Payload;
use silo_proto::v1::publish_service_client::PublishServiceClient;
use silo_proto::v1::read_service_client::ReadServiceClient;
use silo_proto::v1::{ListPackagesRequest, PackageFormat, PublishMetadata, PublishRequest};
use silo_rpm::{PackageParser, RpmParser};

#[derive(Parser)]
#[command(name = "silo", about = "Silo package registry client")]
struct Cli {
    #[arg(
        long,
        env = "SILO_CLIENT_CONFIG",
        default_value = "~/.config/silo/client.yaml"
    )]
    config: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate and publish a package to a repo/channel.
    Publish {
        path: PathBuf,
        #[arg(long)]
        repo: String,
        #[arg(long)]
        channel: String,
    },
    /// List packages published to a repo/channel.
    List {
        #[arg(long)]
        repo: String,
        #[arg(long)]
        channel: String,
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
    let config_path = shellexpand::tilde(&cli.config).into_owned();
    let config = ClientConfig::load(&config_path)?;

    match cli.command {
        Command::Publish {
            path,
            repo,
            channel,
        } => publish(&config, &path, &repo, &channel).await,
        Command::List { repo, channel } => list(&config, &repo, &channel).await,
    }
}

async fn list(config: &ClientConfig, repo: &str, channel: &str) -> anyhow::Result<()> {
    let token = config
        .read_token
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("client config is missing `read_token`"))?;

    let mut client = ReadServiceClient::connect(config.server_addr.clone())
        .await
        .map_err(|e| anyhow::anyhow!("failed to connect to {}: {e}", config.server_addr))?;

    let mut request = tonic::Request::new(ListPackagesRequest {
        repo: repo.to_string(),
        channel: channel.to_string(),
    });
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse()?);

    let response = client.list_packages(request).await?.into_inner();
    for pkg in response.packages {
        println!(
            "{}-{}-{}.{}\t{}",
            pkg.name, pkg.version, pkg.release, pkg.arch, pkg.storage_path
        );
    }
    Ok(())
}

async fn publish(
    config: &ClientConfig,
    path: &PathBuf,
    repo: &str,
    channel: &str,
) -> anyhow::Result<()> {
    let bytes = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", path.display()))?;

    // Validate locally before spending a round trip on the server.
    let parsed = RpmParser
        .parse(&bytes)
        .map_err(|e| anyhow::anyhow!("{} is not a valid rpm: {e}", path.display()))?;
    println!("validated {} ({})", parsed.filename, parsed.nevra());

    let token = config
        .publish_token
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("client config is missing `publish_token`"))?;

    let mut client = PublishServiceClient::connect(config.server_addr.clone())
        .await
        .map_err(|e| anyhow::anyhow!("failed to connect to {}: {e}", config.server_addr))?;

    let mut messages = vec![PublishRequest {
        payload: Some(Payload::Metadata(PublishMetadata {
            repo: repo.to_string(),
            channel: channel.to_string(),
            format: PackageFormat::Rpm as i32,
        })),
    }];
    for chunk in bytes.chunks(64 * 1024) {
        messages.push(PublishRequest {
            payload: Some(Payload::Chunk(chunk.to_vec())),
        });
    }

    let mut request = tonic::Request::new(tokio_stream::iter(messages));
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {token}").parse()?);

    let response = client.publish(request).await?.into_inner();

    println!(
        "published {}-{}-{}.{} -> {} (signed: {})",
        response.name,
        response.version,
        response.release,
        response.arch,
        response.storage_path,
        response.signed
    );
    Ok(())
}
