//! Retention-based package deletion.
//!
//! A rule lives per `(repo, channel)` (see [`silo_db::prune`]) and is
//! evaluated per "package identity" — the same `(format, index_group,
//! name)` grouping the index renderer already uses to tell versions of one
//! package apart from each other. `keep_last_n` and `max_age_days` are
//! independent: a version is a candidate if it violates either one that's
//! configured, and the two constraints listed on a candidate ("why") is a
//! union, not an intersection.
//!
//! Actual deletion is delegated to [`crate::repo::delete_package`], so a
//! pruned package goes through the exact same storage-delete +
//! index-regenerate + audit path a manual `silo delete` does.

use std::collections::{HashMap, HashSet};

use chrono::Utc;
use serde::Serialize;
use serde_json::json;
use silo_db::audit::{self, Actor, AuditEntry};
use silo_db::packages::PackageRow;
use silo_db::prune::PruneRuleRow;

use crate::repo::{self, PublishContext};

/// A rule this package version violated, and therefore why it's a prune
/// candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchedRule {
    KeepLastN,
    MaxAge,
}

impl MatchedRule {
    pub fn as_str(&self) -> &'static str {
        match self {
            MatchedRule::KeepLastN => "keep_last_n",
            MatchedRule::MaxAge => "max_age",
        }
    }
}

/// One package version the prune engine decided to remove, and why.
#[derive(Debug, Clone, Serialize)]
pub struct PruneCandidate {
    pub id: i64,
    pub repo: String,
    pub channel: String,
    pub format: String,
    pub index_group: String,
    pub name: String,
    pub version: String,
    pub release: String,
    pub arch: String,
    pub filename: String,
    pub published_at: i64,
    pub matched_rules: Vec<MatchedRule>,
}

/// The outcome of one [`run`] call.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PruneReport {
    /// Number of `(format, index_group, name)` groups evaluated across
    /// every scanned repo/channel.
    pub scanned_groups: usize,
    pub candidates: Vec<PruneCandidate>,
    /// Packages actually removed by this run — `candidates.len()` overcounts
    /// under concurrent runs, since a candidate another run already deleted
    /// resolves as `Ok(None)` here rather than an error. 0 on a dry run.
    pub deleted: usize,
    /// Populated only on a live run: candidate ids that failed to delete
    /// (storage error, etc). Empty on a dry run since nothing is attempted.
    pub failed: Vec<(i64, String)>,
    pub dry_run: bool,
}

/// Which packages a rule's `origin_scope` column allows it to touch,
/// parsed from the `prune_rules.origin_scope` text column. Stored per
/// rule (set via `silo repo set-prune-rule --origin`) rather than passed
/// in at run time, so `silo prune`/the scheduled job apply exactly the
/// scope each rule was configured with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginFilter {
    All,
    LocalOnly,
    UpstreamOnly,
}

impl OriginFilter {
    pub fn as_str(&self) -> &'static str {
        match self {
            OriginFilter::All => "all",
            OriginFilter::LocalOnly => "local",
            OriginFilter::UpstreamOnly => "upstream",
        }
    }

    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "all" => Ok(OriginFilter::All),
            "local" => Ok(OriginFilter::LocalOnly),
            "upstream" => Ok(OriginFilter::UpstreamOnly),
            other => {
                anyhow::bail!("invalid origin scope `{other}` (expected all, local, or upstream)")
            }
        }
    }

    fn matches(&self, origin_upstream_id: Option<silo_db::Uuid>) -> bool {
        match self {
            OriginFilter::All => true,
            OriginFilter::LocalOnly => origin_upstream_id.is_none(),
            OriginFilter::UpstreamOnly => origin_upstream_id.is_some(),
        }
    }
}

/// Which `(repo, channel)` rules a [`run`] call considers. `None` fields
/// mean "every value" — an empty scope runs every configured rule.
#[derive(Debug, Clone, Default)]
pub struct PruneScope {
    pub repo: Option<String>,
    pub channel: Option<String>,
}

impl PruneScope {
    pub fn all() -> Self {
        Self::default()
    }

    fn matches(&self, repo: &str, channel: &str) -> bool {
        self.repo.as_deref().is_none_or(|r| r == repo)
            && self.channel.as_deref().is_none_or(|c| c == channel)
    }
}

/// Evaluates every configured rule within `scope` and, unless `dry_run`,
/// deletes every match via [`repo::delete_package`]. A `(repo, channel)`
/// with no configured rule is silently skipped — there's nothing to
/// prune there, not an error.
pub async fn run(
    ctx: &PublishContext,
    scope: &PruneScope,
    dry_run: bool,
    actor: &Actor,
) -> anyhow::Result<PruneReport> {
    let rules = ctx
        .db
        .list_prune_rules()
        .await?
        .into_iter()
        .filter(|r| scope.matches(&r.repo, &r.channel))
        .collect::<Vec<_>>();

    let mut report = PruneReport {
        dry_run,
        ..Default::default()
    };

    for rule in &rules {
        let rows = ctx
            .db
            .list_packages(&rule.repo, &rule.channel, None)
            .await?;
        let exempt = ctx
            .db
            .list_prune_exemptions(&rule.repo, &rule.channel)
            .await?
            .into_iter()
            .collect::<HashSet<_>>();
        let exempt_refs: HashSet<&str> = exempt.iter().map(String::as_str).collect();

        let groups = group_by_identity(&rows);
        report.scanned_groups += groups.len();

        let origin = OriginFilter::parse(&rule.origin_scope)
            // A rule row's `origin_scope` is constrained by a DB CHECK, so
            // this only trips if a future version writes a value this
            // binary doesn't know — fail open to `All` rather than
            // skipping the rule's packages entirely.
            .unwrap_or(OriginFilter::All);
        let candidates = select_candidates(&groups, rule, &exempt_refs, origin);
        let scope_had_candidates = !candidates.is_empty();
        report.candidates.extend(candidates.clone());

        if dry_run || !scope_had_candidates {
            continue;
        }

        let mut scope_deleted = 0usize;
        let mut scope_failed = 0usize;
        for candidate in &candidates {
            let reason = json!({
                "reason": "prune",
                "rules": candidate.matched_rules.iter().map(MatchedRule::as_str).collect::<Vec<_>>(),
            });
            match repo::delete_package(ctx, candidate.id, actor, Some(reason)).await {
                // `Ok(None)` means the row was already gone — a concurrent
                // run or manual delete beat this one to it. That's neither
                // a deletion this run performed nor a failure.
                Ok(Some(_)) => scope_deleted += 1,
                Ok(None) => {}
                Err(e) => {
                    scope_failed += 1;
                    report.failed.push((candidate.id, e.to_string()));
                }
            }
        }
        report.deleted += scope_deleted;

        ctx.db
            .record_audit(
                AuditEntry::new(audit::action::REPO_PRUNE_RUN, actor)
                    .repo(&rule.repo)
                    .channel(&rule.channel)
                    .detail(json!({ "deleted": scope_deleted, "failed": scope_failed })),
            )
            .await;
    }

    Ok(report)
}

/// Groups rows by package identity: `(format, index_group, name)`, the
/// same grouping the index renderer uses to tell versions of one package
/// apart from each other.
fn group_by_identity(rows: &[PackageRow]) -> HashMap<(String, String, String), Vec<&PackageRow>> {
    let mut groups: HashMap<(String, String, String), Vec<&PackageRow>> = HashMap::new();
    for row in rows {
        groups
            .entry((
                row.format.clone(),
                row.index_group.clone(),
                row.name.clone(),
            ))
            .or_default()
            .push(row);
    }
    groups
}

/// Pure rule evaluation: given already-grouped rows, a rule, and a set of
/// exempt names, returns every version that violates the rule. No
/// database access, so this is independently unit-testable.
///
/// `origin` narrows which rows within each group are even considered —
/// e.g. `UpstreamOnly` means `keep_last_n`/`max_age_days` are evaluated
/// only among that package's pulled-through versions, so a rule scoped to
/// upstream-origin packages never counts (or deletes) a locally published
/// version of the same name, and vice versa.
fn select_candidates(
    groups: &HashMap<(String, String, String), Vec<&PackageRow>>,
    rule: &PruneRuleRow,
    exempt_names: &HashSet<&str>,
    origin: OriginFilter,
) -> Vec<PruneCandidate> {
    let now = Utc::now();
    let mut candidates: HashMap<i64, PruneCandidate> = HashMap::new();

    for ((_, _, name), rows) in groups {
        if exempt_names.contains(name.as_str()) {
            continue;
        }

        let mut sorted: Vec<&PackageRow> = rows
            .iter()
            .copied()
            .filter(|row| origin.matches(row.origin_upstream_id))
            .collect();
        sorted.sort_by_key(|row| std::cmp::Reverse(row.published_at));

        if let Some(keep) = rule.keep_last_n {
            for row in sorted.iter().skip(keep.max(0) as usize) {
                mark(&mut candidates, row, MatchedRule::KeepLastN);
            }
        }

        if let Some(max_age) = rule.max_age_days {
            let cutoff = now - chrono::Duration::days(max_age as i64);
            for row in sorted.iter().filter(|row| row.published_at < cutoff) {
                mark(&mut candidates, row, MatchedRule::MaxAge);
            }
        }
    }

    let mut candidates = candidates.into_values().collect::<Vec<_>>();
    candidates.sort_by_key(|c| c.id);
    candidates
}

fn mark(candidates: &mut HashMap<i64, PruneCandidate>, row: &PackageRow, rule: MatchedRule) {
    candidates
        .entry(row.id)
        .and_modify(|c| {
            if !c.matched_rules.contains(&rule) {
                c.matched_rules.push(rule);
            }
        })
        .or_insert_with(|| PruneCandidate {
            id: row.id,
            repo: row.repo.clone(),
            channel: row.channel.clone(),
            format: row.format.clone(),
            index_group: row.index_group.clone(),
            name: row.name.clone(),
            version: row.version.clone(),
            release: row.release.clone(),
            arch: row.arch.clone(),
            filename: row.filename.clone(),
            published_at: row.published_at.timestamp(),
            matched_rules: vec![rule],
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json as jsonval;

    fn row(id: i64, name: &str, version: &str, published_at_secs: i64) -> PackageRow {
        PackageRow {
            id,
            repo: "r".into(),
            channel: "c".into(),
            format: "apk".into(),
            index_group: "x86_64".into(),
            name: name.into(),
            epoch: 0,
            version: version.into(),
            release: String::new(),
            arch: "x86_64".into(),
            filename: format!("{name}-{version}.apk"),
            storage_key: format!("r/c/apk/x86_64/{name}-{version}.apk"),
            size_bytes: 1,
            sha256: "abc".into(),
            metadata: jsonval!({}),
            published_at: chrono::DateTime::from_timestamp(published_at_secs, 0).unwrap(),
            published_by_token: None,
            published_by_user: None,
            origin_upstream_id: None,
        }
    }

    fn upstream_row(id: i64, name: &str, version: &str, published_at_secs: i64) -> PackageRow {
        PackageRow {
            origin_upstream_id: Some(silo_db::Uuid::from_u128(1)),
            ..row(id, name, version, published_at_secs)
        }
    }

    fn rule(keep_last_n: Option<i32>, max_age_days: Option<i32>) -> PruneRuleRow {
        PruneRuleRow {
            repo: "r".into(),
            channel: "c".into(),
            keep_last_n,
            max_age_days,
            origin_scope: "all".into(),
            created_at: chrono::DateTime::from_timestamp(0, 0).unwrap(),
            updated_at: chrono::DateTime::from_timestamp(0, 0).unwrap(),
        }
    }

    fn now_secs() -> i64 {
        Utc::now().timestamp()
    }

    #[test]
    fn keep_last_n_alone_prunes_everything_past_the_cutoff() {
        let now = now_secs();
        let rows = vec![
            row(1, "foo", "3.0", now),
            row(2, "foo", "2.0", now - 10),
            row(3, "foo", "1.0", now - 20),
        ];
        let groups = group_by_identity(&rows);
        let candidates = select_candidates(
            &groups,
            &rule(Some(2), None),
            &HashSet::new(),
            OriginFilter::All,
        );
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].id, 3);
        assert_eq!(candidates[0].matched_rules, vec![MatchedRule::KeepLastN]);
    }

    #[test]
    fn max_age_alone_prunes_everything_older_than_the_cutoff() {
        let now = now_secs();
        let day = 86_400;
        let rows = vec![
            row(1, "foo", "3.0", now),
            row(2, "foo", "2.0", now - 100 * day),
            row(3, "foo", "1.0", now - 200 * day),
        ];
        let groups = group_by_identity(&rows);
        let candidates = select_candidates(
            &groups,
            &rule(None, Some(90)),
            &HashSet::new(),
            OriginFilter::All,
        );
        let mut ids = candidates.iter().map(|c| c.id).collect::<Vec<_>>();
        ids.sort();
        assert_eq!(ids, vec![2, 3]);
        assert_eq!(candidates[0].matched_rules, vec![MatchedRule::MaxAge]);
    }

    #[test]
    fn combined_rules_are_a_union_not_an_intersection() {
        let now = now_secs();
        let day = 86_400;
        // id 1: newest, violates neither rule.
        // id 2: within keep_last_n=1's cutoff position-wise (2nd newest) but also old enough for max_age.
        // id 3: oldest, violates both.
        let rows = vec![
            row(1, "foo", "3.0", now),
            row(2, "foo", "2.0", now - 100 * day),
            row(3, "foo", "1.0", now - 200 * day),
        ];
        let groups = group_by_identity(&rows);
        let candidates = select_candidates(
            &groups,
            &rule(Some(1), Some(90)),
            &HashSet::new(),
            OriginFilter::All,
        );
        let mut ids = candidates.iter().map(|c| c.id).collect::<Vec<_>>();
        ids.sort();
        assert_eq!(ids, vec![2, 3]);
        let three = candidates.iter().find(|c| c.id == 3).unwrap();
        assert_eq!(three.matched_rules.len(), 2);
    }

    #[test]
    fn exempt_names_are_skipped_entirely() {
        let now = now_secs();
        let rows = vec![row(1, "foo", "2.0", now), row(2, "foo", "1.0", now - 10)];
        let groups = group_by_identity(&rows);
        let exempt = HashSet::from(["foo"]);
        let candidates =
            select_candidates(&groups, &rule(Some(1), None), &exempt, OriginFilter::All);
        assert!(candidates.is_empty());
    }

    #[test]
    fn empty_groups_produce_no_candidates() {
        let groups = group_by_identity(&[]);
        let candidates = select_candidates(
            &groups,
            &rule(Some(1), None),
            &HashSet::new(),
            OriginFilter::All,
        );
        assert!(candidates.is_empty());
    }

    #[test]
    fn upstream_only_ignores_local_versions_of_the_same_package() {
        let now = now_secs();
        let day = 86_400;
        // Two local versions and two upstream versions of the same name.
        // A keep_last_n=1 rule scoped to upstream must count and prune
        // only among the upstream ones, leaving every local version
        // alone even though it outnumbers the retained count.
        let rows = vec![
            row(1, "foo", "3.0", now),
            row(2, "foo", "2.0", now - day),
            upstream_row(3, "foo", "1.9", now - 2 * day),
            upstream_row(4, "foo", "1.8", now - 3 * day),
        ];
        let groups = group_by_identity(&rows);
        let candidates = select_candidates(
            &groups,
            &rule(Some(1), None),
            &HashSet::new(),
            OriginFilter::UpstreamOnly,
        );
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].id, 4);
    }

    #[test]
    fn local_only_ignores_upstream_versions_of_the_same_package() {
        let now = now_secs();
        let day = 86_400;
        let rows = vec![
            row(1, "foo", "3.0", now),
            row(2, "foo", "2.0", now - day),
            upstream_row(3, "foo", "1.9", now - 2 * day),
        ];
        let groups = group_by_identity(&rows);
        let candidates = select_candidates(
            &groups,
            &rule(Some(1), None),
            &HashSet::new(),
            OriginFilter::LocalOnly,
        );
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].id, 2);
    }

    #[test]
    fn origin_filter_parses_and_round_trips_its_as_str() {
        for (text, filter) in [
            ("all", OriginFilter::All),
            ("local", OriginFilter::LocalOnly),
            ("upstream", OriginFilter::UpstreamOnly),
        ] {
            assert_eq!(OriginFilter::parse(text).unwrap(), filter);
            assert_eq!(filter.as_str(), text);
        }
        assert!(OriginFilter::parse("bogus").is_err());
    }

    #[test]
    fn scope_all_matches_everything() {
        let scope = PruneScope::all();
        assert!(scope.matches("any-repo", "any-channel"));
    }

    #[test]
    fn scope_narrows_by_repo_and_channel() {
        let scope = PruneScope {
            repo: Some("r".into()),
            channel: None,
        };
        assert!(scope.matches("r", "stable"));
        assert!(!scope.matches("other", "stable"));

        let scope = PruneScope {
            repo: Some("r".into()),
            channel: Some("stable".into()),
        };
        assert!(scope.matches("r", "stable"));
        assert!(!scope.matches("r", "edge"));
    }
}
