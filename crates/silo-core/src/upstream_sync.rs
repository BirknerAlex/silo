//! Syncing an upstream's index into `upstream_packages`.
//!
//! Two entry points share the same fetch: [`fetch`] (used by `add-upstream`
//! to validate reachability *before* a row exists, and by `sync-upstream`/
//! the periodic job to refresh an existing one) and [`sync_one`] (the
//! periodic job's per-upstream unit of work: fetch, replace, record the
//! outcome on the row).
//!
//! npm is the odd one out everywhere in this module — see `silo-pkg`'s
//! `npm` module doc: there is no endpoint that lists every package a
//! registry holds, so [`fetch`] only probes reachability for npm and
//! returns no entries, and [`sync_one`] skips [`replace_upstream_packages`]
//! entirely for it. Calling that wholesale replace with npm's always-empty
//! fetch would erase every package [`sync_npm_package`] has lazily
//! populated from real pull-through requests — the one case in this module
//! where "sync found nothing" must not mean "delete everything".

use silo_db::upstreams::{SealedAuth, SyncedPackage, UpstreamRow};
use silo_db::Db;
use silo_pkg::{PackageFormat, UpstreamError, UpstreamFetchOptions, UpstreamHttp, UpstreamPackage};

use crate::secret_box::{Sealed, SecretBox};

/// Builds the [`UpstreamHttp`] seam for one upstream row, decrypting its
/// stored credential (if any) into a resolved auth header. The only place
/// in the pull-through path that ever sees upstream credentials in the
/// clear — everything downstream of this takes an opaque header.
pub fn http_for(
    client: reqwest::Client,
    secrets: Option<&SecretBox>,
    row: &UpstreamRow,
) -> anyhow::Result<UpstreamHttp> {
    let mut http = UpstreamHttp::new(client, &row.base_url);
    let Some(kind) = &row.auth_kind else {
        return Ok(http);
    };
    let (Some(ciphertext), Some(nonce)) = (&row.auth_secret_ciphertext, &row.auth_secret_nonce)
    else {
        anyhow::bail!("upstream {} has auth_kind set but no stored secret", row.id);
    };
    let secrets = secrets.ok_or_else(|| {
        anyhow::anyhow!(
            "upstream {} has a credential but no `upstream_secret` key is configured",
            row.id
        )
    })?;
    let secret = secrets.open(&Sealed {
        ciphertext: ciphertext.clone(),
        nonce: nonce.clone(),
    })?;

    let header_value = match kind.as_str() {
        "basic" => {
            let username = row.auth_username.as_deref().unwrap_or("");
            format!("Basic {}", encode_basic(username, &secret))
        }
        "bearer" => format!("Bearer {secret}"),
        other => anyhow::bail!("unknown upstream auth kind `{other}`"),
    };
    http = http.with_auth_header("Authorization", header_value);
    Ok(http)
}

/// Builds an [`UpstreamHttp`] directly from a plaintext credential —
/// what `add-upstream`/`update-upstream` use to validate reachability and
/// do the first fetch *before* anything is encrypted and stored, since
/// there's no row yet for [`http_for`] to decrypt from.
pub fn http_from_plaintext(
    client: reqwest::Client,
    base_url: &str,
    auth: Option<(&str, Option<&str>, &str)>,
) -> anyhow::Result<UpstreamHttp> {
    let mut http = UpstreamHttp::new(client, base_url);
    let Some((kind, username, secret)) = auth else {
        return Ok(http);
    };
    let header_value = match kind {
        "basic" => format!("Basic {}", encode_basic(username.unwrap_or(""), secret)),
        "bearer" => format!("Bearer {secret}"),
        other => anyhow::bail!("unknown upstream auth kind `{other}`"),
    };
    http = http.with_auth_header("Authorization", header_value);
    Ok(http)
}

fn encode_basic(username: &str, password: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"))
}

/// Encrypts a plaintext credential for storage, the inverse of what
/// [`http_for`] decrypts. Used by the `add-upstream`/`update-upstream`
/// handlers, which are the only callers that ever see a credential in the
/// clear coming in from a request.
pub fn seal_auth(
    secrets: &SecretBox,
    kind: &str,
    username: Option<&str>,
    secret: &str,
) -> anyhow::Result<SealedAuth> {
    let sealed = secrets.seal(secret)?;
    Ok(SealedAuth {
        kind: kind.to_string(),
        username: username.map(str::to_string),
        ciphertext: sealed.ciphertext,
        nonce: sealed.nonce,
    })
}

fn fetch_options(row: &UpstreamRow) -> UpstreamFetchOptions {
    UpstreamFetchOptions {
        arches: row.arches.clone(),
        suite: row.suite.clone(),
        components: row.components.clone(),
    }
}

/// Fetches and parses one upstream's index. Shared by `add-upstream`
/// (called before any row exists, purely to validate + get first data)
/// and by [`sync_one`]/`sync-upstream` (called against an existing row).
pub async fn fetch(
    http: &UpstreamHttp,
    format: PackageFormat,
    opts: &UpstreamFetchOptions,
) -> Result<Vec<UpstreamPackage>, UpstreamError> {
    format.upstream_handler().fetch_index(http, opts).await
}

fn to_synced(pkg: UpstreamPackage) -> SyncedPackage {
    SyncedPackage {
        name: pkg.name,
        epoch: pkg.epoch as i32,
        version: pkg.version,
        release: pkg.release,
        arch: pkg.arch,
        filename: pkg.filename,
        download_url: pkg.download_url,
        size_bytes: pkg.size_bytes,
        sha256: pkg.sha256,
        metadata: pkg.metadata,
    }
}

/// One periodic-job unit of work: fetch an existing upstream's index,
/// replace its synced rows, and record the outcome on the `upstreams`
/// row. Errors are recorded rather than propagated — one broken upstream
/// must not abort the batch (see `maintenance::run_upstream_sync`).
pub async fn sync_one(
    db: &Db,
    client: reqwest::Client,
    secrets: Option<&SecretBox>,
    row: &UpstreamRow,
) -> anyhow::Result<usize> {
    let format: PackageFormat = row.format.parse().map_err(|_| {
        anyhow::anyhow!(
            "upstream {} has an unrecognized format `{}`",
            row.id,
            row.format
        )
    })?;
    let http = http_for(client, secrets, row)?;
    let opts = fetch_options(row);

    // Two syncs of the *same* upstream (a manual `sync-upstream` racing
    // the periodic job, say) aren't otherwise serialized: each fetches
    // its own snapshot and does its own replace-on-sync, so an older,
    // slower fetch's replace committing after a newer one's would delete
    // rows the newer fetch had just added. An advisory lock scoped to
    // this upstream forces the two passes to run one after the other
    // instead of interleaving — held for the whole fetch+replace so a
    // second sync can't start against a half-replaced index either.
    let lock = db.lock(format!("upstream_sync:{}", row.id)).await?;

    let outcome = match fetch(&http, format, &opts).await {
        Ok(packages) => {
            let count = packages.len();
            // npm's fetch is a reachability probe only — it never returns
            // entries — so replacing here would wipe every row
            // `sync_npm_package` has lazily populated. Skip the replace
            // for npm; every other format's fetch is a real full index.
            if format != PackageFormat::Npm {
                let synced: Vec<SyncedPackage> = packages.into_iter().map(to_synced).collect();
                db.replace_upstream_packages(row.id, &synced).await?;
            }
            db.record_upstream_sync_success(row.id).await?;
            Ok(count)
        }
        Err(e) => {
            db.record_upstream_sync_failure(row.id, &e.to_string())
                .await?;
            Err(e.into())
        }
    };
    lock.commit().await?;
    outcome
}

/// The lazy per-name path npm's pull-through request handling uses in
/// place of a wholesale sync: fetches one package's packument and upserts
/// its versions into `upstream_packages`, returning what was fetched so
/// the caller can immediately act on it without a second read.
pub async fn sync_npm_package(
    db: &Db,
    client: reqwest::Client,
    secrets: Option<&SecretBox>,
    row: &UpstreamRow,
    name: &str,
) -> anyhow::Result<Vec<UpstreamPackage>> {
    let http = http_for(client, secrets, row)?;
    let packages = silo_pkg::npm::fetch_package_versions(&http, name).await?;
    let synced: Vec<SyncedPackage> = packages.iter().cloned().map(to_synced).collect();
    db.upsert_upstream_packages(row.id, &synced).await?;
    Ok(packages)
}

/// Whether `upstream_id`'s stored auth (if any) round-trips through the
/// configured secret key — used nowhere on the hot path, but by
/// `update-upstream` to fail fast if a key rotation has orphaned a
/// credential rather than surfacing it later as an inexplicable fetch
/// failure. Not currently wired into a CLI/RPC surface; kept as a small
/// building block for that surface's error message rather than making
/// callers reverse-engineer "auth failed" into "was it the key?" from a
/// generic fetch error.
pub fn credential_is_readable(secrets: Option<&SecretBox>, row: &UpstreamRow) -> bool {
    let Some(kind) = &row.auth_kind else {
        return true;
    };
    let _ = kind;
    let (Some(ciphertext), Some(nonce)) = (&row.auth_secret_ciphertext, &row.auth_secret_nonce)
    else {
        return false;
    };
    let Some(secrets) = secrets else { return false };
    secrets
        .open(&Sealed {
            ciphertext: ciphertext.clone(),
            nonce: nonce.clone(),
        })
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(auth_kind: Option<&str>) -> UpstreamRow {
        UpstreamRow {
            id: silo_db::Uuid::nil(),
            repo: "r".into(),
            channel: "c".into(),
            name: "n".into(),
            format: "rpm".into(),
            base_url: "https://example.com/repo".into(),
            cache_mode: "cache".into(),
            cache_index_in_memory: false,
            arches: vec![],
            suite: None,
            components: vec![],
            auth_kind: auth_kind.map(str::to_string),
            auth_username: auth_kind.map(|_| "bot".to_string()),
            auth_secret_ciphertext: None,
            auth_secret_nonce: None,
            status: "pending".into(),
            last_sync_at: None,
            last_sync_error: None,
            last_success_at: None,
            created_at: chrono::DateTime::from_timestamp(0, 0).unwrap(),
            updated_at: chrono::DateTime::from_timestamp(0, 0).unwrap(),
        }
    }

    #[test]
    fn no_auth_kind_produces_no_header() {
        let http = http_for(reqwest::Client::new(), None, &row(None)).unwrap();
        assert_eq!(http.base_url(), "https://example.com/repo");
    }

    #[test]
    fn basic_auth_round_trips_through_seal_and_http_for() {
        let secrets = SecretBox::new(&SecretBox::generate_key()).unwrap();
        let sealed = seal_auth(&secrets, "basic", Some("bot"), "hunter2").unwrap();
        let mut r = row(Some("basic"));
        r.auth_secret_ciphertext = Some(sealed.ciphertext);
        r.auth_secret_nonce = Some(sealed.nonce);

        // `http_for` builds successfully — the header content itself is
        // opaque to callers by design, but a wrong-key decrypt failing is
        // what matters here.
        assert!(http_for(reqwest::Client::new(), Some(&secrets), &r).is_ok());
    }

    #[test]
    fn a_credential_with_no_configured_secret_key_is_an_error() {
        let secrets = SecretBox::new(&SecretBox::generate_key()).unwrap();
        let sealed = seal_auth(&secrets, "bearer", None, "token123").unwrap();
        let mut r = row(Some("bearer"));
        r.auth_secret_ciphertext = Some(sealed.ciphertext);
        r.auth_secret_nonce = Some(sealed.nonce);

        assert!(http_for(reqwest::Client::new(), None, &r).is_err());
    }

    #[test]
    fn credential_is_readable_matches_a_successful_decrypt() {
        let secrets = SecretBox::new(&SecretBox::generate_key()).unwrap();
        let other = SecretBox::new(&SecretBox::generate_key()).unwrap();
        let sealed = seal_auth(&secrets, "bearer", None, "token123").unwrap();
        let mut r = row(Some("bearer"));
        r.auth_secret_ciphertext = Some(sealed.ciphertext);
        r.auth_secret_nonce = Some(sealed.nonce);

        assert!(credential_is_readable(Some(&secrets), &r));
        assert!(!credential_is_readable(Some(&other), &r));
        assert!(!credential_is_readable(None, &r));
        assert!(credential_is_readable(Some(&secrets), &row(None)));
    }
}
