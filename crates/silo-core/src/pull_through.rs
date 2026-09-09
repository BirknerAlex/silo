//! Pull-through cache: the request-time decision of how to answer a
//! package request that might not be servable from what silo already has,
//! and the orchestration that carries an [`Action::FetchAndCache`]/
//! [`Action::RedirectToUpstream`]/[`Action::ProxyUpstream`] decision out.
//!
//! [`decide`] is a pure function — no I/O, fully unit-testable — because
//! it's the highest-leverage piece of this feature to get right: every
//! branch is a distinct, observable client-facing behavior (serve what we
//! have, fetch and keep a copy, redirect the client to fetch it directly,
//! or proxy it through without keeping a copy), and the four inputs that
//! decide between them (local presence, upstream freshness, the
//! upstream's cache mode, whether it needs a credential) are each cheap
//! to enumerate exhaustively in tests.
//!
//! [`resolve`] is the impure half: it looks up the facts `decide` needs,
//! calls it, and carries out whichever action comes back — routing a
//! `FetchAndCache` through [`crate::repo::publish_with_origin`] rather
//! than a bespoke "write to storage" path, so a cache-mode pull-through
//! inherits the exact same advisory-lock-scoped, DB-driven index
//! regeneration a real publish gets (see `repo`'s module doc). That's
//! what makes two concurrent requests for the same missing package safe:
//! they can't race the index any differently than two real publishes
//! already don't.

use silo_db::upstreams::UpstreamRow;
use silo_db::Db;
use silo_pkg::PackageFormat;

/// Whether a package artifact should be persisted into silo's own storage
/// once fetched, or only ever proxied/redirected through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheMode {
    Cache,
    NoCache,
}

impl CacheMode {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "cache" => Ok(CacheMode::Cache),
            "no_cache" => Ok(CacheMode::NoCache),
            other => anyhow::bail!("invalid cache mode `{other}` (expected cache or no_cache)"),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            CacheMode::Cache => "cache",
            CacheMode::NoCache => "no_cache",
        }
    }
}

/// What the synced index knows about whether/what version an upstream
/// has, distinguishing "confirmed absent" from "can't know without
/// fetching" — the latter is npm's structural reality (see the `silo-pkg`
/// `npm` module doc), and conflating it with "confirmed absent" would
/// make every npm request 404 instead of falling through to a real fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamAvailability<'a> {
    Known(Option<(u32, &'a str, &'a str)>),
    Unknown,
}

/// What to do about one requested package artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Already have a fresh-enough copy; serve it the normal way.
    ServeLocal,
    /// Fetch from upstream and persist via `publish_with_origin`, then
    /// serve the now-local copy.
    FetchAndCache,
    /// 302 straight to the upstream's URL; nothing persisted.
    RedirectToUpstream,
    /// Fetch server-side (applying the upstream's stored credential) and
    /// stream the bytes back; nothing persisted, and the credential never
    /// reaches the client.
    ProxyUpstream,
    /// No local copy, and no upstream confirms one exists (or none is
    /// configured at all).
    NotFound,
}

/// The pure decision. See the module doc for why this has no I/O.
pub fn decide(
    format: PackageFormat,
    local: Option<(u32, &str, &str)>,
    upstream: Option<(CacheMode, bool, UpstreamAvailability<'_>)>,
) -> Action {
    let Some((cache_mode, upstream_requires_auth, availability)) = upstream else {
        return if local.is_some() {
            Action::ServeLocal
        } else {
            Action::NotFound
        };
    };

    match availability {
        UpstreamAvailability::Known(None) => {
            if local.is_some() {
                Action::ServeLocal
            } else {
                Action::NotFound
            }
        }
        UpstreamAvailability::Known(Some(upstream_version)) => {
            let stale = match local {
                None => true,
                Some(local_version) => {
                    format.compare_versions(upstream_version, local_version)
                        == std::cmp::Ordering::Greater
                }
            };
            if !stale {
                Action::ServeLocal
            } else {
                fetch_action(cache_mode, upstream_requires_auth)
            }
        }
        UpstreamAvailability::Unknown => {
            // Can't tell freshness without fetching (npm); a local copy is
            // served as-is rather than re-fetched on every request —
            // freshness for npm is rechecked by whatever triggers a fresh
            // packument fetch (a subsequent miss, or an explicit
            // `sync-upstream`), not by paying for one on every hit.
            if local.is_some() {
                Action::ServeLocal
            } else {
                fetch_action(cache_mode, upstream_requires_auth)
            }
        }
    }
}

fn fetch_action(cache_mode: CacheMode, upstream_requires_auth: bool) -> Action {
    match cache_mode {
        CacheMode::Cache => Action::FetchAndCache,
        CacheMode::NoCache if upstream_requires_auth => Action::ProxyUpstream,
        CacheMode::NoCache => Action::RedirectToUpstream,
    }
}

/// Lists which configured upstreams back a `(repo, channel, format)`
/// triple, in the order they should be tried: highest `priority` first,
/// ties broken by name so the order is always total and stable. Callers
/// must fall through to the next candidate on a confirmed miss rather
/// than stopping at the first one, or every upstream after the first is
/// unreachable in practice.
///
/// This does not apply [`upstream_serves`] — the package name isn't
/// always known this early (an rpm request carries a filename, not a
/// name). Callers that do know it filter with `upstream_serves` as they
/// go.
pub async fn select_upstreams(
    db: &Db,
    repo: &str,
    channel: &str,
    format: PackageFormat,
) -> anyhow::Result<Vec<UpstreamRow>> {
    let mut upstreams = db.list_upstreams(repo, channel).await?;
    upstreams.retain(|u| u.format == format.as_str());
    Ok(upstreams)
}

/// Whether `upstream` is allowed to answer for `package_name`.
///
/// An upstream with no patterns answers for everything, which is what
/// every upstream does until someone says otherwise. Patterns exist for
/// the case where two upstreams of one format are *not* interchangeable
/// mirrors: a vendor registry that holds one scope, next to a public one
/// that holds the rest. Without them the only thing deciding which
/// upstream serves a name is which one answers first — and an upstream
/// that proxies or redirects unknown names to the public registry
/// answers for everything, so it wins everything, and every package in
/// the repo ends up attributed to it.
pub fn upstream_serves(upstream: &UpstreamRow, package_name: &str) -> bool {
    upstream.package_patterns.is_empty()
        || upstream
            .package_patterns
            .iter()
            .any(|pattern| glob_matches(pattern, package_name))
}

/// Matches `name` against a glob: `*` stands for any run of characters
/// (including none, and including `/`), `?` for exactly one, and
/// everything else is literal. The whole name must match, not a prefix —
/// `@acme/*` is a scope, not "anything starting with `@acme/`" that
/// could also match `@acme/x/../y`.
///
/// `*` deliberately spans `/` so `@acme/*` covers the whole scope. npm
/// names have at most one separator and the other formats have none, so
/// there is no nesting for a stricter `*` to protect.
///
/// Hand-rolled rather than pulled in: this is the entire feature, the
/// two metacharacters are the two an operator expects from a shell glob,
/// and backtracking on inputs this short is free.
fn glob_matches(pattern: &str, name: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    // `star` remembers the last `*` and how much of `name` it had eaten,
    // so a failed match resumes by letting that `*` swallow one more
    // character instead of giving up.
    let (mut p, mut n) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == name[n]) {
            p += 1;
            n += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some((p, n));
            p += 1;
        } else if let Some((star_p, star_n)) = star {
            p = star_p + 1;
            n = star_n + 1;
            star = Some((star_p, star_n + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|c| *c == '*')
}

/// Whether decrypting `upstream`'s stored credential (if any) would
/// succeed — used to decide `ProxyUpstream` vs `RedirectToUpstream`
/// without actually needing the plaintext at this point.
pub fn requires_auth(upstream: &UpstreamRow) -> bool {
    upstream.auth_kind.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_upstream_configured_serves_local_or_404s() {
        assert_eq!(
            decide(PackageFormat::Rpm, Some((0, "1.0", "1")), None),
            Action::ServeLocal
        );
        assert_eq!(decide(PackageFormat::Rpm, None, None), Action::NotFound);
    }

    #[test]
    fn known_absent_upstream_serves_local_or_404s() {
        let up = Some((CacheMode::Cache, false, UpstreamAvailability::Known(None)));
        assert_eq!(
            decide(PackageFormat::Rpm, Some((0, "1.0", "1")), up),
            Action::ServeLocal
        );
        assert_eq!(decide(PackageFormat::Rpm, None, up), Action::NotFound);
    }

    #[test]
    fn a_fresh_local_copy_is_served_without_fetching() {
        let up = Some((
            CacheMode::Cache,
            false,
            UpstreamAvailability::Known(Some((0, "1.0", "1"))),
        ));
        assert_eq!(
            decide(PackageFormat::Rpm, Some((0, "1.0", "1")), up),
            Action::ServeLocal
        );
    }

    #[test]
    fn a_stale_local_copy_triggers_a_fetch_and_cache_when_the_upstream_caches() {
        let up = Some((
            CacheMode::Cache,
            false,
            UpstreamAvailability::Known(Some((0, "2.0", "1"))),
        ));
        assert_eq!(
            decide(PackageFormat::Rpm, Some((0, "1.0", "1")), up),
            Action::FetchAndCache
        );
    }

    #[test]
    fn a_missing_local_copy_triggers_a_fetch_when_the_upstream_has_it() {
        let up = Some((
            CacheMode::Cache,
            false,
            UpstreamAvailability::Known(Some((0, "1.0", "1"))),
        ));
        assert_eq!(decide(PackageFormat::Rpm, None, up), Action::FetchAndCache);
    }

    #[test]
    fn no_cache_upstream_redirects_when_no_auth_is_needed() {
        let up = Some((
            CacheMode::NoCache,
            false,
            UpstreamAvailability::Known(Some((0, "1.0", "1"))),
        ));
        assert_eq!(
            decide(PackageFormat::Rpm, None, up),
            Action::RedirectToUpstream
        );
    }

    #[test]
    fn no_cache_upstream_proxies_when_auth_is_needed_never_redirecting_a_credentialed_fetch() {
        let up = Some((
            CacheMode::NoCache,
            true,
            UpstreamAvailability::Known(Some((0, "1.0", "1"))),
        ));
        assert_eq!(decide(PackageFormat::Rpm, None, up), Action::ProxyUpstream);
    }

    #[test]
    fn unknown_availability_serves_an_existing_local_copy_without_fetching() {
        // npm's structural case: no synced index exists to confirm
        // freshness, so a local copy is trusted rather than re-fetched on
        // every single request.
        let up = Some((CacheMode::Cache, false, UpstreamAvailability::Unknown));
        assert_eq!(
            decide(PackageFormat::Npm, Some((0, "1.0.0", "")), up),
            Action::ServeLocal
        );
    }

    #[test]
    fn unknown_availability_with_no_local_copy_still_attempts_a_fetch() {
        let up = Some((CacheMode::Cache, false, UpstreamAvailability::Unknown));
        assert_eq!(decide(PackageFormat::Npm, None, up), Action::FetchAndCache);
    }

    #[test]
    fn unknown_availability_no_cache_respects_the_auth_split_too() {
        let redirect = Some((CacheMode::NoCache, false, UpstreamAvailability::Unknown));
        assert_eq!(
            decide(PackageFormat::Npm, None, redirect),
            Action::RedirectToUpstream
        );
        let proxy = Some((CacheMode::NoCache, true, UpstreamAvailability::Unknown));
        assert_eq!(
            decide(PackageFormat::Npm, None, proxy),
            Action::ProxyUpstream
        );
    }

    #[test]
    fn a_glob_matches_the_whole_name_not_a_prefix() {
        assert!(glob_matches("lodash", "lodash"));
        assert!(!glob_matches("lodash", "lodash-es"));
        assert!(!glob_matches("odash", "lodash"));
    }

    #[test]
    fn a_scope_glob_covers_the_scope_and_nothing_else() {
        assert!(glob_matches(
            "@fortawesome/*",
            "@fortawesome/fontawesome-pro"
        ));
        assert!(glob_matches(
            "@fortawesome/*",
            "@fortawesome/vue-fontawesome"
        ));
        // The one this feature exists for: a public package must not fall
        // inside a vendor registry's scope.
        assert!(!glob_matches("@fortawesome/*", "@babel/core"));
        assert!(!glob_matches("@fortawesome/*", "lodash"));
        // `*` spans `/`, so a scope glob covers the whole scope, but the
        // scope prefix itself still has to match exactly.
        assert!(!glob_matches("@fortawesome/*", "@fortawesomeX/thing"));
    }

    #[test]
    fn a_star_matches_an_empty_run_and_a_question_mark_matches_exactly_one() {
        assert!(glob_matches("*", ""));
        assert!(glob_matches("*", "anything/at-all"));
        assert!(glob_matches("@acme/*", "@acme/"));
        assert!(glob_matches("nod?", "node"));
        assert!(!glob_matches("nod?", "nod"));
        assert!(!glob_matches("nod?", "nodejs"));
    }

    #[test]
    fn several_stars_and_trailing_literals_still_match() {
        assert!(glob_matches("*-plugin-*", "eslint-plugin-vue"));
        assert!(glob_matches("@*/core", "@babel/core"));
        assert!(!glob_matches("@*/core", "@babel/parser"));
        assert!(glob_matches("**", "anything"));
    }

    #[test]
    fn an_upstream_without_patterns_answers_for_everything() {
        let mut upstream = test_upstream(vec![]);
        assert!(upstream_serves(&upstream, "anything"));
        upstream.package_patterns = vec!["@acme/*".into()];
        assert!(upstream_serves(&upstream, "@acme/widget"));
        assert!(!upstream_serves(&upstream, "lodash"));
    }

    #[test]
    fn patterns_are_alternatives_so_one_upstream_can_hold_several_scopes() {
        let upstream = test_upstream(vec![
            "@acme/*".into(),
            "@vendor/*".into(),
            "legacy-tool".into(),
        ]);
        assert!(upstream_serves(&upstream, "@acme/widget"));
        assert!(upstream_serves(&upstream, "@vendor/thing"));
        assert!(upstream_serves(&upstream, "legacy-tool"));
        assert!(!upstream_serves(&upstream, "@other/thing"));
    }

    fn test_upstream(package_patterns: Vec<String>) -> UpstreamRow {
        UpstreamRow {
            id: silo_db::Uuid::nil(),
            repo: "r".into(),
            channel: "c".into(),
            name: "n".into(),
            format: "npm".into(),
            base_url: "https://example.com".into(),
            cache_mode: "cache".into(),
            cache_index_in_memory: false,
            priority: 0,
            package_patterns,
            arches: vec![],
            suite: None,
            components: vec![],
            auth_kind: None,
            auth_username: None,
            auth_secret_ciphertext: None,
            auth_secret_nonce: None,
            status: "ok".into(),
            last_sync_at: None,
            last_sync_error: None,
            last_success_at: None,
            created_at: chrono::DateTime::from_timestamp(0, 0).unwrap(),
            updated_at: chrono::DateTime::from_timestamp(0, 0).unwrap(),
        }
    }

    #[test]
    fn cache_mode_parses_the_two_stored_strings_and_rejects_anything_else() {
        assert_eq!(CacheMode::parse("cache").unwrap(), CacheMode::Cache);
        assert_eq!(CacheMode::parse("no_cache").unwrap(), CacheMode::NoCache);
        assert!(CacheMode::parse("nocache").is_err());
    }
}
