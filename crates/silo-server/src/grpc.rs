//! The publish and read gRPC services.

use std::sync::Arc;
use std::time::Instant;

use futures::StreamExt;
use silo_db::audit::{self, AuditEntry};
use silo_db::tokens::Permission;
use silo_pkg::PackageFormat;
use silo_proto::v1::publish_request::Payload;
use silo_proto::v1::publish_service_server::PublishService;
use silo_proto::v1::read_service_server::ReadService;
use silo_proto::v1::{
    ListPackagesRequest, ListPackagesResponse, ListReposRequest, ListReposResponse,
    PackageFormat as ProtoFormat, PackageInfo, PublishRequest, PublishResponse, RepoInfo, RepoMode,
};
use tonic::{Request, Response, Status, Streaming};

use silo_core::repo::MAX_PACKAGE_BYTES;

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
        // The credential is lifted out before the request is consumed:
        // `Streaming` isn't `Sync`, so borrowing the request across the
        // verification await would make this future non-`Send`.
        let credential = auth::extract_grpc_credential(&self.state, &request)?;
        let mut stream = request.into_inner();
        let authenticated = auth::authenticate_credential(&self.state, credential).await?;

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

        let format = from_proto_format(metadata.format)
            .ok_or_else(|| Status::invalid_argument("format must be one of rpm, apk, or npm"))?;

        // Authorize before reading the body: a client with no write access
        // shouldn't get to stream a gigabyte before being told no.
        auth::require_repo(
            &self.state,
            &authenticated,
            &metadata.repo,
            Permission::Write,
        )
        .await?;

        let mut bytes = Vec::new();
        while let Some(msg) = stream.next().await {
            let msg = msg?;
            match msg.payload {
                Some(Payload::Chunk(chunk)) => {
                    if bytes.len() + chunk.len() > MAX_PACKAGE_BYTES {
                        return Err(Status::resource_exhausted(format!(
                            "package exceeds the {} GiB upload limit",
                            MAX_PACKAGE_BYTES / (1024 * 1024 * 1024)
                        )));
                    }
                    bytes.extend_from_slice(&chunk);
                }
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

        let started = Instant::now();
        let outcome = silo_core::repo::publish(
            &self.state.publish,
            &metadata.repo,
            &metadata.channel,
            format,
            bytes,
            &authenticated.actor,
        )
        .await;

        let elapsed = started.elapsed().as_secs_f64();
        self.state
            .metrics
            .record_publish(format.as_str(), outcome.is_ok(), elapsed);

        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(e) => {
                // A rejected publish leaves no other trace, so the audit
                // log is the only place it can be seen afterwards.
                self.state
                    .db
                    .record_audit(
                        AuditEntry::new(audit::action::PACKAGE_PUBLISH, &authenticated.actor)
                            .repo(&metadata.repo)
                            .channel(&metadata.channel)
                            .detail(serde_json::json!({ "format": format.as_str() }))
                            .failed(&e),
                    )
                    .await;
                return Err(publish_error_to_status(e));
            }
        };

        Ok(Response::new(PublishResponse {
            name: outcome.name,
            version: outcome.version,
            release: outcome.release,
            arch: outcome.arch,
            storage_path: outcome.storage_path,
            signed: outcome.signed,
            format: to_proto_format(outcome.format) as i32,
            size_bytes: outcome.size_bytes,
            sha256: outcome.sha256,
            index_objects: outcome.index_objects,
        }))
    }
}

/// Maps a [`silo_core::repo::classify_publish_error`] verdict to a gRPC
/// status.
fn publish_error_to_status(error: anyhow::Error) -> Status {
    use silo_core::repo::PublishErrorKind;
    let message = error.to_string();
    match silo_core::repo::classify_publish_error(&error) {
        PublishErrorKind::InvalidArgument => Status::invalid_argument(message),
        PublishErrorKind::Timeout => Status::deadline_exceeded(message),
        PublishErrorKind::Internal => {
            tracing::error!(error = %error, "publish failed");
            Status::internal(message)
        }
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
        let authenticated = auth::authenticate_grpc(&self.state, &request).await?;
        let req = request.into_inner();
        if req.repo.is_empty() || req.channel.is_empty() {
            return Err(Status::invalid_argument("repo and channel are required"));
        }
        auth::require_repo(&self.state, &authenticated, &req.repo, Permission::Read).await?;

        // Listing reads the database, not the bucket: no LIST call, and
        // metadata that a filename could never carry (size, checksum,
        // publisher, timestamp) comes back for free.
        let rows = self
            .state
            .db
            .list_packages(&req.repo, &req.channel, from_proto_format(req.format))
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let packages = rows
            .into_iter()
            .map(|row| PackageInfo {
                format: to_proto_format(row.format.parse().unwrap_or(PackageFormat::Rpm)) as i32,
                name: row.name,
                version: row.version,
                release: row.release,
                arch: row.arch,
                storage_path: row.storage_key,
                size_bytes: row.size_bytes,
                sha256: row.sha256,
                published_at: row.published_at.timestamp(),
                id: row.id,
            })
            .collect();

        Ok(Response::new(ListPackagesResponse { packages }))
    }

    async fn list_repos(
        &self,
        request: Request<ListReposRequest>,
    ) -> Result<Response<ListReposResponse>, Status> {
        let authenticated = auth::authenticate_grpc(&self.state, &request).await?;

        let summaries = self
            .state
            .db
            .list_repos()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // A repo-scoped token shouldn't learn which other repos exist —
        // unless the repo is public, in which case everyone gets to see
        // it, credential or not.
        let repos = summaries
            .into_iter()
            .filter(|s| authenticated.allows(&s.repo, Permission::Read) || s.public)
            .map(|s| RepoInfo {
                format: to_proto_format(s.format.parse().unwrap_or(PackageFormat::Rpm)) as i32,
                repo: s.repo,
                channel: s.channel,
                package_count: s.packages,
                total_bytes: s.total_bytes,
                mode: if s.public {
                    RepoMode::Public
                } else {
                    RepoMode::Private
                } as i32,
            })
            .collect();

        Ok(Response::new(ListReposResponse { repos }))
    }
}

/// `UNSPECIFIED` means "no filter" on read paths and is rejected on the
/// publish path, so this returns `Option` rather than defaulting.
pub fn from_proto_format(value: i32) -> Option<PackageFormat> {
    match ProtoFormat::try_from(value).ok()? {
        ProtoFormat::Rpm => Some(PackageFormat::Rpm),
        ProtoFormat::Apk => Some(PackageFormat::Apk),
        ProtoFormat::Npm => Some(PackageFormat::Npm),
        ProtoFormat::Pacman => Some(PackageFormat::Pacman),
        ProtoFormat::Unspecified => None,
    }
}

pub fn to_proto_format(format: PackageFormat) -> ProtoFormat {
    match format {
        PackageFormat::Rpm => ProtoFormat::Rpm,
        PackageFormat::Apk => ProtoFormat::Apk,
        PackageFormat::Npm => ProtoFormat::Npm,
        PackageFormat::Pacman => ProtoFormat::Pacman,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_format_round_trips_through_the_wire_enum() {
        for format in PackageFormat::ALL {
            let proto = to_proto_format(format);
            assert_eq!(from_proto_format(proto as i32), Some(format));
        }
    }

    #[test]
    fn unspecified_and_unknown_wire_values_map_to_no_format() {
        assert_eq!(from_proto_format(ProtoFormat::Unspecified as i32), None);
        assert_eq!(from_proto_format(9999), None);
    }

    #[test]
    fn parse_failures_are_reported_as_client_errors() {
        let status = publish_error_to_status(anyhow::anyhow!("invalid apk package: no .PKGINFO"));
        assert_eq!(status.code(), tonic::Code::InvalidArgument);

        let status = publish_error_to_status(anyhow::anyhow!(
            "repo name `a/b` may only contain letters, digits, and the characters - _ ."
        ));
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn lock_timeouts_are_reported_as_deadline_exceeded() {
        let status = publish_error_to_status(anyhow::anyhow!(
            "timed out waiting for the lock on `index:r|c|rpm|`: canceling statement"
        ));
        assert_eq!(status.code(), tonic::Code::DeadlineExceeded);
    }

    #[test]
    fn unexpected_failures_stay_internal() {
        let status = publish_error_to_status(anyhow::anyhow!("connection reset by peer"));
        assert_eq!(status.code(), tonic::Code::Internal);
    }

    #[test]
    fn the_upload_ceiling_is_a_sane_size() {
        assert_eq!(MAX_PACKAGE_BYTES, 2 * 1024 * 1024 * 1024);
    }
}
