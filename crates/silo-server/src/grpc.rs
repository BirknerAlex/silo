use std::sync::Arc;

use futures::StreamExt;
use silo_proto::v1::publish_request::Payload;
use silo_proto::v1::publish_service_server::PublishService;
use silo_proto::v1::read_service_server::ReadService;
use silo_proto::v1::{
    ListPackagesRequest, ListPackagesResponse, PackageFormat as ProtoFormat, PackageInfo,
    PublishRequest, PublishResponse,
};
use silo_rpm::{PackageParser, RpmParser};
use tonic::{Request, Response, Status, Streaming};

use crate::auth;
use crate::AppState;

pub struct PublishServiceImpl {
    pub state: Arc<AppState>,
}

#[tonic::async_trait]
impl PublishService for PublishServiceImpl {
    async fn publish(
        &self,
        request: Request<Streaming<PublishRequest>>,
    ) -> Result<Response<PublishResponse>, Status> {
        auth::check_bearer(&request, &self.state.config.auth.publish_token)?;

        let mut stream = request.into_inner();

        let first = stream
            .next()
            .await
            .ok_or_else(|| Status::invalid_argument("empty request stream"))??;
        let metadata = match first.payload {
            Some(Payload::Metadata(m)) => m,
            _ => return Err(Status::invalid_argument("first message must be metadata")),
        };
        if metadata.repo.is_empty() || metadata.channel.is_empty() {
            return Err(Status::invalid_argument("repo and channel are required"));
        }
        if ProtoFormat::try_from(metadata.format).unwrap_or(ProtoFormat::Unspecified)
            != ProtoFormat::Rpm
        {
            return Err(Status::invalid_argument("only the rpm format is supported"));
        }

        let mut bytes = Vec::new();
        while let Some(msg) = stream.next().await {
            let msg = msg?;
            match msg.payload {
                Some(Payload::Chunk(chunk)) => bytes.extend_from_slice(&chunk),
                Some(Payload::Metadata(_)) => {
                    return Err(Status::invalid_argument(
                        "unexpected metadata after stream start",
                    ))
                }
                None => {}
            }
        }
        if bytes.is_empty() {
            return Err(Status::invalid_argument("no package bytes received"));
        }

        let parsed = RpmParser
            .parse(&bytes)
            .map_err(|e| Status::invalid_argument(format!("invalid rpm: {e}")))?;

        let outcome = silo_core::repo::publish(
            &self.state.storage,
            &metadata.repo,
            &metadata.channel,
            parsed.clone(),
            self.state.config.gpg.as_ref(),
        )
        .await
        .map_err(|e| Status::internal(format!("publish failed: {e}")))?;

        Ok(Response::new(PublishResponse {
            name: parsed.name,
            version: parsed.version,
            release: parsed.release,
            arch: parsed.arch,
            storage_path: outcome.storage_path,
            signed: outcome.signed,
        }))
    }
}

pub struct ReadServiceImpl {
    pub state: Arc<AppState>,
}

#[tonic::async_trait]
impl ReadService for ReadServiceImpl {
    async fn list_packages(
        &self,
        request: Request<ListPackagesRequest>,
    ) -> Result<Response<ListPackagesResponse>, Status> {
        auth::check_bearer(&request, &self.state.config.auth.read_token)?;
        let req = request.into_inner();
        if req.repo.is_empty() || req.channel.is_empty() {
            return Err(Status::invalid_argument("repo and channel are required"));
        }

        let prefix = silo_core::repo::packages_prefix(&req.repo, &req.channel);
        let entries = self
            .state
            .storage
            .list_sized(&prefix)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let packages = entries
            .into_iter()
            .filter_map(|(storage_path, size_bytes)| {
                let filename = storage_path.rsplit('/').next().unwrap_or(&storage_path);
                let (name, version, release, arch) = silo_rpm::parse_nvra_filename(filename)?;
                Some(PackageInfo {
                    name,
                    version,
                    release,
                    arch,
                    storage_path,
                    size_bytes: size_bytes as i64,
                })
            })
            .collect();

        Ok(Response::new(ListPackagesResponse { packages }))
    }
}
