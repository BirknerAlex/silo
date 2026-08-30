//! Retention-based pruning: rule CRUD, keep-last-N, max-age, their union,
//! per-package exemptions, dry-run, the global enable switch, and scoping.
//!
//! See `tests/common/mod.rs` for how to point these at a database.

mod common;

use common::{unique_repo, Harness};
use silo_db::audit::{Actor, ActorKind, AuditQuery};
use silo_db::tokens::{Permission, Scope};
use silo_pkg::testutil::build_test_apk;
use silo_pkg::PackageFormat;
use silo_proto::v1::admin_service_server::AdminService;
use silo_proto::v1::{
    ClearPruneRuleRequest, GetPruneRuleRequest, ListPruneExemptionsRequest, RunPruneRequest,
    SetPruneExemptionRequest, SetPruneRuleRequest,
};
use silo_server::admin::AdminServiceImpl;

fn actor() -> Actor {
    Actor {
        kind: ActorKind::Token,
        name: "test-publisher".into(),
        token_id: None,
        user_id: None,
        remote_addr: Some("10.0.0.1".into()),
    }
}

fn request<T>(msg: T, token: Option<&str>) -> tonic::Request<T> {
    let mut req = tonic::Request::new(msg);
    if let Some(token) = token {
        req.metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
    }
    req
}

/// Publishes `n` versions of one apk package, oldest first, then backdates
/// their `published_at` timestamps so `n - 1` days separate each version
/// from the next — deterministic ages without sleeping in a test.
async fn publish_versions(
    harness: &Harness,
    repo: &str,
    channel: &str,
    name: &str,
    n: u32,
) -> Vec<i64> {
    let mut ids = Vec::new();
    for i in 0..n {
        silo_core::repo::publish(
            &harness.state.publish,
            repo,
            channel,
            PackageFormat::Apk,
            build_test_apk(name, &format!("1.{i}-r0"), "x86_64"),
            &actor(),
        )
        .await
        .unwrap_or_else(|e| panic!("publish {name} 1.{i}: {e}"));
    }

    let rows = harness.db.list_packages(repo, channel, None).await.unwrap();
    for row in rows.iter().filter(|r| r.name == name) {
        // version "1.<i>-r0" -> i encodes publish order; back-date so
        // higher i (published later) is younger.
        let i: i64 = row
            .version
            .trim_start_matches("1.")
            .trim_end_matches("-r0")
            .parse()
            .unwrap();
        let age_days = (n as i64 - 1) - i;
        set_published_at_days_ago(harness, row.id, age_days).await;
        ids.push(row.id);
    }
    ids
}

async fn set_published_at_days_ago(harness: &Harness, id: i64, days: i64) {
    sqlx::query(
        "UPDATE packages SET published_at = now() - ($2 || ' days')::interval WHERE id = $1",
    )
    .bind(id)
    .bind(days.to_string())
    .execute(harness.db.pool())
    .await
    .unwrap();
}

async fn versions_remaining(
    harness: &Harness,
    repo: &str,
    channel: &str,
    name: &str,
) -> Vec<String> {
    let mut versions = harness
        .db
        .list_packages(repo, channel, None)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.name == name)
        .map(|r| r.version)
        .collect::<Vec<_>>();
    versions.sort();
    versions
}

#[tokio::test]
async fn set_get_clear_prune_rule_round_trips() {
    let url = require_db!();
    let harness = Harness::new(&url).await;
    let repo = unique_repo("ruleroundtrip");
    let admin = harness.admin_token().await;
    let service = AdminServiceImpl {
        state: harness.state.clone(),
    };

    assert!(harness
        .db
        .get_prune_rule(&repo, "stable")
        .await
        .unwrap()
        .is_none());

    let response = service
        .set_prune_rule(request(
            SetPruneRuleRequest {
                repo: repo.clone(),
                channel: "stable".into(),
                keep_last_n: Some(5),
                max_age_days: None,
            },
            Some(&admin.secret),
        ))
        .await
        .expect("set rule")
        .into_inner();
    let rule = response.rule.expect("rule in response");
    assert_eq!(rule.keep_last_n, Some(5));
    assert_eq!(rule.max_age_days, None);

    // Setting again updates rather than duplicating.
    service
        .set_prune_rule(request(
            SetPruneRuleRequest {
                repo: repo.clone(),
                channel: "stable".into(),
                keep_last_n: Some(3),
                max_age_days: Some(90),
            },
            Some(&admin.secret),
        ))
        .await
        .expect("update rule");

    let got = service
        .get_prune_rule(request(
            GetPruneRuleRequest {
                repo: repo.clone(),
                channel: "stable".into(),
            },
            Some(&admin.secret),
        ))
        .await
        .expect("get rule")
        .into_inner()
        .rule
        .expect("rule exists");
    assert_eq!(got.keep_last_n, Some(3));
    assert_eq!(got.max_age_days, Some(90));

    let cleared = service
        .clear_prune_rule(request(
            ClearPruneRuleRequest {
                repo: repo.clone(),
                channel: "stable".into(),
            },
            Some(&admin.secret),
        ))
        .await
        .expect("clear rule")
        .into_inner();
    assert!(cleared.cleared);
    assert!(harness
        .db
        .get_prune_rule(&repo, "stable")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn keep_last_n_deletes_the_oldest_beyond_n() {
    let url = require_db!();
    let harness = Harness::with_config(&url, |c| c.prune.enabled = true).await;
    let repo = unique_repo("keeplastn");
    let admin = harness.admin_token().await;

    publish_versions(&harness, &repo, "edge", "widget", 5).await;
    harness
        .db
        .set_prune_rule(&repo, "edge", Some(2), None)
        .await
        .unwrap();

    let service = AdminServiceImpl {
        state: harness.state.clone(),
    };
    let response = service
        .run_prune(request(
            RunPruneRequest {
                repo: repo.clone(),
                channel: "edge".into(),
                dry_run: false,
            },
            Some(&admin.secret),
        ))
        .await
        .expect("run prune")
        .into_inner();

    assert_eq!(response.deleted, 3);
    assert_eq!(response.failed, 0);

    let remaining = versions_remaining(&harness, &repo, "edge", "widget").await;
    assert_eq!(remaining, vec!["1.3-r0".to_string(), "1.4-r0".to_string()]);
}

#[tokio::test]
async fn max_age_deletes_versions_older_than_the_threshold() {
    let url = require_db!();
    let harness = Harness::with_config(&url, |c| c.prune.enabled = true).await;
    let repo = unique_repo("maxage");
    let admin = harness.admin_token().await;

    // 5 versions, one per day, oldest at 4 days old.
    publish_versions(&harness, &repo, "edge", "widget", 5).await;
    harness
        .db
        .set_prune_rule(&repo, "edge", None, Some(2))
        .await
        .unwrap();

    let service = AdminServiceImpl {
        state: harness.state.clone(),
    };
    let response = service
        .run_prune(request(
            RunPruneRequest {
                repo: repo.clone(),
                channel: "edge".into(),
                dry_run: false,
            },
            Some(&admin.secret),
        ))
        .await
        .expect("run prune")
        .into_inner();

    // Ages 4,3,2,1,0 days; max_age_days=2 keeps anything younger than 2
    // days old (ages 0 and 1), prunes ages 2,3,4.
    assert_eq!(response.deleted, 3);
    let remaining = versions_remaining(&harness, &repo, "edge", "widget").await;
    assert_eq!(remaining, vec!["1.3-r0".to_string(), "1.4-r0".to_string()]);
}

#[tokio::test]
async fn combined_rules_are_a_union_not_an_intersection() {
    let url = require_db!();
    let harness = Harness::with_config(&url, |c| c.prune.enabled = true).await;
    let repo = unique_repo("combined");
    let admin = harness.admin_token().await;

    // Ages 4,3,2,1,0 days old (5 versions).
    publish_versions(&harness, &repo, "edge", "widget", 5).await;
    // keep_last_n=4 alone would only prune the oldest (age 4).
    // max_age_days=3 alone would prune ages 4 and 3.
    // Union: ages 3 and 4 pruned (age 4 hit by both, age 3 hit by max_age only).
    harness
        .db
        .set_prune_rule(&repo, "edge", Some(4), Some(3))
        .await
        .unwrap();

    let service = AdminServiceImpl {
        state: harness.state.clone(),
    };
    let response = service
        .run_prune(request(
            RunPruneRequest {
                repo: repo.clone(),
                channel: "edge".into(),
                dry_run: false,
            },
            Some(&admin.secret),
        ))
        .await
        .expect("run prune")
        .into_inner();

    assert_eq!(response.deleted, 2);
    let remaining = versions_remaining(&harness, &repo, "edge", "widget").await;
    assert_eq!(
        remaining,
        vec![
            "1.2-r0".to_string(),
            "1.3-r0".to_string(),
            "1.4-r0".to_string()
        ]
    );
}

#[tokio::test]
async fn an_exempt_name_survives_both_rules() {
    let url = require_db!();
    let harness = Harness::with_config(&url, |c| c.prune.enabled = true).await;
    let repo = unique_repo("exempt");
    let admin = harness.admin_token().await;

    publish_versions(&harness, &repo, "edge", "widget", 5).await;
    harness
        .db
        .set_prune_rule(&repo, "edge", Some(1), Some(1))
        .await
        .unwrap();

    let service = AdminServiceImpl {
        state: harness.state.clone(),
    };
    let exempted = service
        .set_prune_exemption(request(
            SetPruneExemptionRequest {
                repo: repo.clone(),
                channel: "edge".into(),
                name: "widget".into(),
                exempt: true,
            },
            Some(&admin.secret),
        ))
        .await
        .expect("exempt")
        .into_inner();
    assert!(exempted.exempted);

    let names = service
        .list_prune_exemptions(request(
            ListPruneExemptionsRequest {
                repo: repo.clone(),
                channel: "edge".into(),
            },
            Some(&admin.secret),
        ))
        .await
        .expect("list exemptions")
        .into_inner()
        .names;
    assert_eq!(names, vec!["widget".to_string()]);

    let response = service
        .run_prune(request(
            RunPruneRequest {
                repo: repo.clone(),
                channel: "edge".into(),
                dry_run: false,
            },
            Some(&admin.secret),
        ))
        .await
        .expect("run prune")
        .into_inner();

    assert_eq!(response.deleted, 0);
    assert_eq!(
        versions_remaining(&harness, &repo, "edge", "widget")
            .await
            .len(),
        5
    );
}

#[tokio::test]
async fn dry_run_reports_without_deleting_or_auditing() {
    let url = require_db!();
    let harness = Harness::with_config(&url, |c| c.prune.enabled = true).await;
    let repo = unique_repo("dryrun");
    let admin = harness.admin_token().await;

    publish_versions(&harness, &repo, "edge", "widget", 5).await;
    harness
        .db
        .set_prune_rule(&repo, "edge", Some(2), None)
        .await
        .unwrap();

    let service = AdminServiceImpl {
        state: harness.state.clone(),
    };
    let response = service
        .run_prune(request(
            RunPruneRequest {
                repo: repo.clone(),
                channel: "edge".into(),
                dry_run: true,
            },
            Some(&admin.secret),
        ))
        .await
        .expect("dry run")
        .into_inner();

    assert!(response.dry_run);
    assert_eq!(response.candidates.len(), 3);
    assert_eq!(response.deleted, 0);
    // Nothing was actually removed.
    assert_eq!(
        versions_remaining(&harness, &repo, "edge", "widget")
            .await
            .len(),
        5
    );

    let entries = harness
        .db
        .query_audit(&AuditQuery {
            repo: Some(repo.clone()),
            limit: 100,
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(
        entries
            .iter()
            .all(|e| e.action != silo_db::audit::action::PACKAGE_DELETE
                && e.action != silo_db::audit::action::REPO_PRUNE_RUN),
        "dry run should not write delete or summary audit entries"
    );
}

#[tokio::test]
async fn live_run_writes_package_delete_and_summary_audit_entries() {
    let url = require_db!();
    let harness = Harness::with_config(&url, |c| c.prune.enabled = true).await;
    let repo = unique_repo("auditrun");
    let admin = harness.admin_token().await;

    publish_versions(&harness, &repo, "edge", "widget", 3).await;
    harness
        .db
        .set_prune_rule(&repo, "edge", Some(1), None)
        .await
        .unwrap();

    let service = AdminServiceImpl {
        state: harness.state.clone(),
    };
    let response = service
        .run_prune(request(
            RunPruneRequest {
                repo: repo.clone(),
                channel: "edge".into(),
                dry_run: false,
            },
            Some(&admin.secret),
        ))
        .await
        .expect("run prune")
        .into_inner();
    assert_eq!(response.deleted, 2);

    let entries = harness
        .db
        .query_audit(&AuditQuery {
            repo: Some(repo.clone()),
            limit: 100,
            ..Default::default()
        })
        .await
        .unwrap();

    let deletes = entries
        .iter()
        .filter(|e| e.action == silo_db::audit::action::PACKAGE_DELETE)
        .count();
    assert_eq!(deletes, 2);

    let summaries = entries
        .iter()
        .filter(|e| e.action == silo_db::audit::action::REPO_PRUNE_RUN)
        .count();
    assert_eq!(summaries, 1);
}

#[tokio::test]
async fn prune_disabled_globally_rejects_run_prune() {
    let url = require_db!();
    // `prune.enabled` defaults to false.
    let harness = Harness::new(&url).await;
    let repo = unique_repo("disabled");
    let admin = harness.admin_token().await;

    harness
        .db
        .set_prune_rule(&repo, "edge", Some(1), None)
        .await
        .unwrap();

    let service = AdminServiceImpl {
        state: harness.state.clone(),
    };
    let err = service
        .run_prune(request(
            RunPruneRequest {
                repo: repo.clone(),
                channel: "edge".into(),
                dry_run: false,
            },
            Some(&admin.secret),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
}

#[tokio::test]
async fn scoping_by_repo_and_channel_leaves_others_untouched() {
    let url = require_db!();
    let harness = Harness::with_config(&url, |c| c.prune.enabled = true).await;
    let repo_a = unique_repo("scopea");
    let repo_b = unique_repo("scopeb");
    let admin = harness.admin_token().await;

    publish_versions(&harness, &repo_a, "edge", "widget", 5).await;
    publish_versions(&harness, &repo_b, "edge", "widget", 5).await;
    harness
        .db
        .set_prune_rule(&repo_a, "edge", Some(1), None)
        .await
        .unwrap();
    harness
        .db
        .set_prune_rule(&repo_b, "edge", Some(1), None)
        .await
        .unwrap();

    let service = AdminServiceImpl {
        state: harness.state.clone(),
    };
    let response = service
        .run_prune(request(
            RunPruneRequest {
                repo: repo_a.clone(),
                channel: "edge".into(),
                dry_run: false,
            },
            Some(&admin.secret),
        ))
        .await
        .expect("run prune")
        .into_inner();
    assert_eq!(response.deleted, 4);

    assert_eq!(
        versions_remaining(&harness, &repo_a, "edge", "widget")
            .await
            .len(),
        1
    );
    // repo_b's rule was never triggered by a run scoped to repo_a.
    assert_eq!(
        versions_remaining(&harness, &repo_b, "edge", "widget")
            .await
            .len(),
        5
    );
}

#[tokio::test]
async fn running_with_no_configured_rule_is_a_silent_no_op() {
    let url = require_db!();
    let harness = Harness::with_config(&url, |c| c.prune.enabled = true).await;
    let repo = unique_repo("norule");
    let admin = harness.admin_token().await;

    publish_versions(&harness, &repo, "edge", "widget", 3).await;
    // No rule configured for this repo/channel.

    let service = AdminServiceImpl {
        state: harness.state.clone(),
    };
    let response = service
        .run_prune(request(
            RunPruneRequest {
                repo: repo.clone(),
                channel: "edge".into(),
                dry_run: false,
            },
            Some(&admin.secret),
        ))
        .await
        .expect("run prune succeeds even with nothing configured")
        .into_inner();

    assert_eq!(response.deleted, 0);
    assert!(response.candidates.is_empty());
    assert_eq!(
        versions_remaining(&harness, &repo, "edge", "widget")
            .await
            .len(),
        3
    );
}

#[tokio::test]
async fn a_repo_scoped_admin_cannot_touch_another_repos_prune_config() {
    let url = require_db!();
    let harness = Harness::with_config(&url, |c| c.prune.enabled = true).await;
    let mine = unique_repo("scopedmine");
    let other = unique_repo("scopedother");
    let scoped_admin = harness
        .token(
            "scoped-admin",
            Permission::Admin,
            Scope::Repos(vec![mine.clone()]),
        )
        .await;

    let service = AdminServiceImpl {
        state: harness.state.clone(),
    };

    // Scoped to `mine`: operating on `mine` succeeds.
    let response = service
        .set_prune_rule(request(
            SetPruneRuleRequest {
                repo: mine.clone(),
                channel: "edge".into(),
                keep_last_n: Some(1),
                max_age_days: None,
            },
            Some(&scoped_admin.secret),
        ))
        .await
        .expect("scoped admin can configure its own repo");
    assert!(response.into_inner().rule.is_some());

    // The same token cannot touch a repo outside its scope.
    let err = service
        .set_prune_rule(request(
            SetPruneRuleRequest {
                repo: other.clone(),
                channel: "edge".into(),
                keep_last_n: Some(1),
                max_age_days: None,
            },
            Some(&scoped_admin.secret),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    assert!(harness
        .db
        .get_prune_rule(&other, "edge")
        .await
        .unwrap()
        .is_none());

    let err = service
        .clear_prune_rule(request(
            ClearPruneRuleRequest {
                repo: other.clone(),
                channel: "edge".into(),
            },
            Some(&scoped_admin.secret),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    let err = service
        .get_prune_rule(request(
            GetPruneRuleRequest {
                repo: other.clone(),
                channel: "edge".into(),
            },
            Some(&scoped_admin.secret),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    let err = service
        .set_prune_exemption(request(
            SetPruneExemptionRequest {
                repo: other.clone(),
                channel: "edge".into(),
                name: "widget".into(),
                exempt: true,
            },
            Some(&scoped_admin.secret),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    let err = service
        .list_prune_exemptions(request(
            ListPruneExemptionsRequest {
                repo: other.clone(),
                channel: "edge".into(),
            },
            Some(&scoped_admin.secret),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn an_unscoped_prune_run_requires_global_scope() {
    let url = require_db!();
    let harness = Harness::with_config(&url, |c| c.prune.enabled = true).await;
    let mine = unique_repo("unscopedmine");
    let scoped_admin = harness
        .token(
            "scoped-admin",
            Permission::Admin,
            Scope::Repos(vec![mine.clone()]),
        )
        .await;
    let global_admin = harness.admin_token().await;

    harness
        .db
        .set_prune_rule(&mine, "edge", Some(1), None)
        .await
        .unwrap();

    let service = AdminServiceImpl {
        state: harness.state.clone(),
    };

    // Omitting `repo` means "every configured rule" — a repo-scoped token
    // must not be able to trigger that.
    let err = service
        .run_prune(request(
            RunPruneRequest {
                repo: String::new(),
                channel: String::new(),
                dry_run: true,
            },
            Some(&scoped_admin.secret),
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    // The same scoped token can still run a prune it explicitly names.
    service
        .run_prune(request(
            RunPruneRequest {
                repo: mine.clone(),
                channel: "edge".into(),
                dry_run: true,
            },
            Some(&scoped_admin.secret),
        ))
        .await
        .expect("a repo-scoped token can prune the repo it's scoped to");

    // A globally-scoped admin token can still run an unscoped prune.
    service
        .run_prune(request(
            RunPruneRequest {
                repo: String::new(),
                channel: String::new(),
                dry_run: true,
            },
            Some(&global_admin.secret),
        ))
        .await
        .expect("a globally-scoped admin token can run an unscoped prune");
}
