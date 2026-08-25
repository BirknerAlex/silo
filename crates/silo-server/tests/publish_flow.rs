//! End-to-end test of the gRPC Publish flow: real tonic client/server over
//! a loopback socket, in-memory S3 backend, no GPG key configured.
//! Gated on `createrepo_c` being installed since repodata regeneration
//! shells out to it — skips gracefully on machines without it (e.g. macOS).

use std::sync::Arc;

use silo_core::config::{AuthConfig, Config, StorageConfig};
use silo_core::Storage;
use silo_proto::v1::publish_request::Payload;
use silo_proto::v1::publish_service_client::PublishServiceClient;
use silo_proto::v1::publish_service_server::PublishServiceServer;
use silo_proto::v1::read_service_client::ReadServiceClient;
use silo_proto::v1::read_service_server::ReadServiceServer;
use silo_proto::v1::{ListPackagesRequest, PackageFormat, PublishMetadata, PublishRequest};
use silo_server::{grpc, AppState};
use tonic::transport::Server;
use tonic::Request;

async fn spawn_test_server() -> (String, tokio::task::JoinHandle<()>) {
    let config = Config {
        grpc_addr: "127.0.0.1:0".into(),
        http_addr: "127.0.0.1:0".into(),
        storage: StorageConfig {
            bucket: "test".into(),
            endpoint: None,
            region: "us-east-1".into(),
            access_key_id: "x".into(),
            secret_access_key: "x".into(),
            allow_http: false,
        },
        auth: AuthConfig {
            publish_token: "pub-token".into(),
            read_token: "read-token".into(),
        },
        gpg: None,
    };
    let state = Arc::new(AppState {
        config,
        storage: Storage::in_memory(),
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    let publish_svc = PublishServiceServer::new(grpc::PublishServiceImpl {
        state: state.clone(),
    });
    let read_svc = ReadServiceServer::new(grpc::ReadServiceImpl {
        state: state.clone(),
    });

    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(publish_svc)
            .add_service(read_svc)
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    (format!("http://{addr}"), handle)
}

#[tokio::test]
async fn publish_then_list_round_trip() {
    if !silo_core::repodata::is_available() {
        eprintln!("skipping: createrepo_c not installed on this machine");
        return;
    }

    let (addr, _handle) = spawn_test_server().await;

    let mut publish_client = PublishServiceClient::connect(addr.clone()).await.unwrap();

    let rpm_bytes = silo_rpm::build_test_rpm("silo-itest", "1.0.0", "1", "x86_64");

    let mut msgs = vec![PublishRequest {
        payload: Some(Payload::Metadata(PublishMetadata {
            repo: "myrepo".into(),
            channel: "stable".into(),
            format: PackageFormat::Rpm as i32,
        })),
    }];
    for chunk in rpm_bytes.chunks(4096) {
        msgs.push(PublishRequest {
            payload: Some(Payload::Chunk(chunk.to_vec())),
        });
    }

    let mut req = Request::new(tokio_stream::iter(msgs));
    req.metadata_mut()
        .insert("authorization", "Bearer pub-token".parse().unwrap());

    let resp = publish_client.publish(req).await.unwrap().into_inner();
    assert_eq!(resp.name, "silo-itest");
    assert_eq!(resp.version, "1.0.0");
    assert_eq!(resp.release, "1");
    assert_eq!(resp.arch, "x86_64");
    assert!(!resp.signed);
    assert_eq!(
        resp.storage_path,
        "myrepo/stable/Packages/silo-itest-1.0.0-1.x86_64.rpm"
    );

    let mut read_client = ReadServiceClient::connect(addr).await.unwrap();
    let mut list_req = Request::new(ListPackagesRequest {
        repo: "myrepo".into(),
        channel: "stable".into(),
    });
    list_req
        .metadata_mut()
        .insert("authorization", "Bearer read-token".parse().unwrap());
    let list_resp = read_client
        .list_packages(list_req)
        .await
        .unwrap()
        .into_inner();

    assert_eq!(list_resp.packages.len(), 1);
    let pkg = &list_resp.packages[0];
    assert_eq!(pkg.name, "silo-itest");
    assert_eq!(pkg.version, "1.0.0");
    assert_eq!(pkg.arch, "x86_64");
}

#[tokio::test]
async fn publish_rejects_wrong_token() {
    let (addr, _handle) = spawn_test_server().await;
    let mut client = PublishServiceClient::connect(addr).await.unwrap();

    let rpm_bytes = silo_rpm::build_test_rpm("silo-itest", "1.0.0", "1", "x86_64");
    let msgs = vec![
        PublishRequest {
            payload: Some(Payload::Metadata(PublishMetadata {
                repo: "myrepo".into(),
                channel: "stable".into(),
                format: PackageFormat::Rpm as i32,
            })),
        },
        PublishRequest {
            payload: Some(Payload::Chunk(rpm_bytes)),
        },
    ];
    let mut req = Request::new(tokio_stream::iter(msgs));
    req.metadata_mut()
        .insert("authorization", "Bearer wrong-token".parse().unwrap());

    let err = client.publish(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}
