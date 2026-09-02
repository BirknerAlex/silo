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

/// Picks which configured upstream backs a `(repo, channel, format)`
/// triple. Multiple upstreams of the same format may be configured (the
/// user's "one or more" ask); the first by name is used, giving a
/// deterministic, operator-controllable choice (rename to reorder)
/// without a separate priority column to manage.
pub async fn select_upstream(
    db: &Db,
    repo: &str,
    channel: &str,
    format: PackageFormat,
) -> anyhow::Result<Option<UpstreamRow>> {
    let mut upstreams = db.list_upstreams(repo, channel).await?;
    upstreams.retain(|u| u.format == format.as_str());
    Ok(upstreams.into_iter().next())
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
    fn cache_mode_parses_the_two_stored_strings_and_rejects_anything_else() {
        assert_eq!(CacheMode::parse("cache").unwrap(), CacheMode::Cache);
        assert_eq!(CacheMode::parse("no_cache").unwrap(), CacheMode::NoCache);
        assert!(CacheMode::parse("nocache").is_err());
    }
}
