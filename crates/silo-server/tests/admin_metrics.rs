//! Registry-shaped metrics that only move when a real admin RPC or the
//! background maintenance job runs — as opposed to `metrics.rs`'s own unit
//! tests, which call `Metrics`' methods directly and never touch a
//! handler.
//!
//! See `tests/common/mod.rs` for how to point these at a database.

mod common;

use common::{unique_repo, Harness};
use silo_pkg::testutil::build_test_rpm;
use silo_pkg::PackageFormat;
use silo_proto::v1::admin_service_server::AdminService;
use silo_proto::v1::{PackageFormat as ProtoFormat, RebuildIndexRequest};
use silo_server::admin::AdminServiceImpl;

fn request<T>(msg: T, token: Option<&str>) -> tonic::Request<T> {
    let mut req = tonic::Request::new(msg);
    if let Some(token) = token {
        req.metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
    }
    req
}

#[tokio::test]
async fn rebuilding_an_index_over_grpc_is_counted() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("rebuild-metrics");
    let admin = harness.admin_token().await;

    silo_core::repo::publish(
        &harness.state.publish,
        &repo,
        "stable",
        PackageFormat::Rpm,
        build_test_rpm("widget", "1.0", "1", "x86_64"),
        &silo_db::audit::Actor {
            kind: silo_db::audit::ActorKind::Token,
            name: "test-publisher".into(),
            token_id: None,
            user_id: None,
            remote_addr: None,
        },
    )
    .await
    .expect("seed a package to rebuild the index for");

    let service = AdminServiceImpl {
        state: harness.state.clone(),
    };
    let response = service
        .rebuild_index(request(
            RebuildIndexRequest {
                repo: repo.clone(),
                channel: "stable".into(),
                format: ProtoFormat::Rpm as i32,
                index_group: String::new(),
            },
            Some(&admin.secret),
        ))
        .await
        .expect("rebuild the index")
        .into_inner();
    assert_eq!(response.groups_rebuilt, 1);

    assert_eq!(
        harness
            .state
            .metrics
            .index_regenerations
            .with_label_values(&["rpm", "ok"])
            .get(),
        1
    );
    assert_eq!(
        harness
            .state
            .metrics
            .grpc_requests
            .with_label_values(&["rebuild_index", "ok"])
            .get(),
        1
    );
}
