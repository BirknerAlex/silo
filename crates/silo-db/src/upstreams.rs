//! Upstream sources a repo/channel can pull through, and the synced view
//! of what each one has.
//!
//! See the `0005_upstreams.sql` migration doc comment for why
//! `upstream_packages` is a separate table from `packages`: a `packages`
//! row means "this repo serves these bytes"; an `upstream_packages` row
//! means "the upstream claims to have this, unfetched".

use serde_json::Value;
use sqlx::{FromRow, PgExecutor};
use uuid::Uuid;

use crate::{DateTime, Db};

#[derive(Debug, Clone, FromRow)]
pub struct UpstreamRow {
    pub id: Uuid,
    pub repo: String,
    pub channel: String,
    pub name: String,
    pub format: String,
    pub base_url: String,
    pub cache_mode: String,
    pub cache_index_in_memory: bool,
    pub arches: Vec<String>,
    pub suite: Option<String>,
    pub components: Vec<String>,
    pub auth_kind: Option<String>,
    pub auth_username: Option<String>,
    pub auth_secret_ciphertext: Option<Vec<u8>>,
    pub auth_secret_nonce: Option<Vec<u8>>,
    pub status: String,
    pub last_sync_at: Option<DateTime>,
    pub last_sync_error: Option<String>,
    pub last_success_at: Option<DateTime>,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}

/// A sealed (AES-GCM encrypted) upstream credential, opaque to this
/// module — encryption/decryption is `silo_core::secret_box`'s job, not
/// `silo-db`'s, so this crate never sees plaintext.
#[derive(Debug, Clone)]
pub struct SealedAuth {
    pub kind: String,
    pub username: Option<String>,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct NewUpstream {
    pub repo: String,
    pub channel: String,
    pub name: String,
    pub format: String,
    pub base_url: String,
    pub cache_mode: String,
    pub cache_index_in_memory: bool,
    pub arches: Vec<String>,
    pub suite: Option<String>,
    pub components: Vec<String>,
    pub auth: Option<SealedAuth>,
}

const COLUMNS: &str = "id, repo, channel, name, format, base_url, cache_mode, \
                       cache_index_in_memory, arches, suite, components, auth_kind, \
                       auth_username, auth_secret_ciphertext, auth_secret_nonce, status, \
                       last_sync_at, last_sync_error, last_success_at, created_at, updated_at";

impl Db {
    /// Inserts a new upstream row. Fails on a `(repo, channel, name)`
    /// collision — the caller (the `add-upstream` flow) is expected to
    /// have already run the first sync successfully before calling this,
    /// so a row only ever exists once its upstream has been validated.
    pub async fn create_upstream(&self, new: &NewUpstream) -> anyhow::Result<UpstreamRow> {
        let (auth_kind, auth_username, ciphertext, nonce) = match &new.auth {
            Some(auth) => (
                Some(auth.kind.clone()),
                auth.username.clone(),
                Some(auth.ciphertext.clone()),
                Some(auth.nonce.clone()),
            ),
            None => (None, None, None, None),
        };
        Ok(sqlx::query_as(&format!(
            "INSERT INTO upstreams (repo, channel, name, format, base_url, cache_mode, \
                                    cache_index_in_memory, arches, suite, components, \
                                    auth_kind, auth_username, auth_secret_ciphertext, \
                                    auth_secret_nonce, status) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'ok') \
             RETURNING {COLUMNS}"
        ))
        .bind(&new.repo)
        .bind(&new.channel)
        .bind(&new.name)
        .bind(&new.format)
        .bind(&new.base_url)
        .bind(&new.cache_mode)
        .bind(new.cache_index_in_memory)
        .bind(&new.arches)
        .bind(&new.suite)
        .bind(&new.components)
        .bind(auth_kind)
        .bind(auth_username)
        .bind(ciphertext)
        .bind(nonce)
        .fetch_one(self.pool())
        .await?)
    }

    pub async fn get_upstream(
        &self,
        repo: &str,
        channel: &str,
        name: &str,
    ) -> anyhow::Result<Option<UpstreamRow>> {
        Ok(sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM upstreams WHERE repo = $1 AND channel = $2 AND name = $3"
        ))
        .bind(repo)
        .bind(channel)
        .bind(name)
        .fetch_optional(self.pool())
        .await?)
    }

    pub async fn find_upstream(&self, id: Uuid) -> anyhow::Result<Option<UpstreamRow>> {
        Ok(
            sqlx::query_as(&format!("SELECT {COLUMNS} FROM upstreams WHERE id = $1"))
                .bind(id)
                .fetch_optional(self.pool())
                .await?,
        )
    }

    pub async fn list_upstreams(
        &self,
        repo: &str,
        channel: &str,
    ) -> anyhow::Result<Vec<UpstreamRow>> {
        list_upstreams(self.pool(), repo, channel).await
    }

    /// Every upstream across every repo — what the periodic sync job
    /// iterates over.
    pub async fn list_all_upstreams(&self) -> anyhow::Result<Vec<UpstreamRow>> {
        Ok(sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM upstreams ORDER BY repo, channel, name"
        ))
        .fetch_all(self.pool())
        .await?)
    }

    /// Deletes an upstream row. `packages.origin_upstream_id` referencing
    /// it is set NULL by the FK (`ON DELETE SET NULL`) — callers that want
    /// cached packages deleted first (`remove-upstream --prune`) must do
    /// that themselves, via `repo::delete_package`, before calling this.
    pub async fn delete_upstream(&self, id: Uuid) -> anyhow::Result<Option<UpstreamRow>> {
        Ok(sqlx::query_as(&format!(
            "DELETE FROM upstreams WHERE id = $1 RETURNING {COLUMNS}"
        ))
        .bind(id)
        .fetch_optional(self.pool())
        .await?)
    }

    /// Updates the mutable settings on an existing upstream — everything
    /// except its identity (`repo`/`channel`/`name`/`format`), which would
    /// need a new upstream rather than a rename. `auth = None` leaves the
    /// stored credential untouched; clearing it is a distinct explicit
    /// action (`clear_upstream_auth`) so a caller can't accidentally wipe
    /// a working credential by omitting `auth` from an unrelated update.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_upstream(
        &self,
        id: Uuid,
        base_url: &str,
        cache_mode: &str,
        cache_index_in_memory: bool,
        arches: &[String],
        suite: Option<&str>,
        components: &[String],
        auth: Option<&SealedAuth>,
    ) -> anyhow::Result<Option<UpstreamRow>> {
        if let Some(auth) = auth {
            return Ok(sqlx::query_as(&format!(
                "UPDATE upstreams SET base_url = $2, cache_mode = $3, \
                     cache_index_in_memory = $4, arches = $5, suite = $6, components = $7, \
                     auth_kind = $8, auth_username = $9, auth_secret_ciphertext = $10, \
                     auth_secret_nonce = $11, updated_at = now() \
                 WHERE id = $1 RETURNING {COLUMNS}"
            ))
            .bind(id)
            .bind(base_url)
            .bind(cache_mode)
            .bind(cache_index_in_memory)
            .bind(arches)
            .bind(suite)
            .bind(components)
            .bind(&auth.kind)
            .bind(&auth.username)
            .bind(&auth.ciphertext)
            .bind(&auth.nonce)
            .fetch_optional(self.pool())
            .await?);
        }
        Ok(sqlx::query_as(&format!(
            "UPDATE upstreams SET base_url = $2, cache_mode = $3, \
                 cache_index_in_memory = $4, arches = $5, suite = $6, components = $7, \
                 updated_at = now() \
             WHERE id = $1 RETURNING {COLUMNS}"
        ))
        .bind(id)
        .bind(base_url)
        .bind(cache_mode)
        .bind(cache_index_in_memory)
        .bind(arches)
        .bind(suite)
        .bind(components)
        .fetch_optional(self.pool())
        .await?)
    }

    /// Clears a stored credential without touching anything else —
    /// `update_upstream` only ever *sets* one, so a caller that wants to
    /// remove a credential entirely (rather than replace it) uses this
    /// instead.
    pub async fn clear_upstream_auth(&self, id: Uuid) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE upstreams SET auth_kind = NULL, auth_username = NULL, \
                 auth_secret_ciphertext = NULL, auth_secret_nonce = NULL, updated_at = now() \
             WHERE id = $1",
        )
        .bind(id)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Records a successful sync: clears any prior error, stamps both
    /// `last_sync_at` and `last_success_at`.
    pub async fn record_upstream_sync_success(&self, id: Uuid) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE upstreams SET status = 'ok', last_sync_error = NULL, \
                 last_sync_at = now(), last_success_at = now(), updated_at = now() \
             WHERE id = $1",
        )
        .bind(id)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Records a failed sync. `last_success_at` is left untouched — a
    /// transient failure doesn't erase the record of when data was last
    /// known-good.
    pub async fn record_upstream_sync_failure(&self, id: Uuid, error: &str) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE upstreams SET status = 'error', last_sync_error = $2, \
                 last_sync_at = now(), updated_at = now() \
             WHERE id = $1",
        )
        .bind(id)
        .bind(error)
        .execute(self.pool())
        .await?;
        Ok(())
    }
}

/// Same query as [`Db::list_upstreams`], over an explicit executor —
/// what a caller already holding a transaction (index regeneration,
/// inside its advisory-lock transaction) uses instead of taking a second
/// connection from the pool while the first sits idle mid-transaction.
pub async fn list_upstreams<'e, E: PgExecutor<'e>>(
    executor: E,
    repo: &str,
    channel: &str,
) -> anyhow::Result<Vec<UpstreamRow>> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM upstreams WHERE repo = $1 AND channel = $2 ORDER BY name"
    ))
    .bind(repo)
    .bind(channel)
    .fetch_all(executor)
    .await?)
}

#[derive(Debug, Clone, FromRow)]
pub struct UpstreamPackageRow {
    pub id: i64,
    pub upstream_id: Uuid,
    pub name: String,
    pub epoch: i32,
    pub version: String,
    pub release: String,
    pub arch: String,
    pub filename: String,
    pub download_url: String,
    pub size_bytes: Option<i64>,
    pub sha256: Option<String>,
    pub metadata: Value,
    pub synced_at: DateTime,
}

/// One entry a sync fetched from an upstream's index, ready to upsert.
#[derive(Debug, Clone)]
pub struct SyncedPackage {
    pub name: String,
    pub epoch: i32,
    pub version: String,
    pub release: String,
    pub arch: String,
    pub filename: String,
    pub download_url: String,
    pub size_bytes: Option<i64>,
    pub sha256: Option<String>,
    pub metadata: Value,
}

const UP_COLUMNS: &str = "id, upstream_id, name, epoch, version, release, arch, filename, \
                          download_url, size_bytes, sha256, metadata, synced_at";

impl Db {
    /// Replaces `upstream_id`'s synced index with `fresh`: upserts every
    /// entry, then deletes whatever wasn't in `fresh` — a full
    /// replace-on-sync, mirroring how a publish rewrites its whole index
    /// from the database rather than patching it incrementally. Run
    /// inside one transaction so a reader never observes a half-replaced
    /// index.
    pub async fn replace_upstream_packages(
        &self,
        upstream_id: Uuid,
        fresh: &[SyncedPackage],
    ) -> anyhow::Result<()> {
        let mut tx = self.pool().begin().await?;

        for pkg in fresh {
            sqlx::query(
                "INSERT INTO upstream_packages (upstream_id, name, epoch, version, release, \
                     arch, filename, download_url, size_bytes, sha256, metadata) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) \
                 ON CONFLICT (upstream_id, name, epoch, version, release, arch) DO UPDATE SET \
                     filename = excluded.filename, \
                     download_url = excluded.download_url, \
                     size_bytes = excluded.size_bytes, \
                     sha256 = excluded.sha256, \
                     metadata = excluded.metadata, \
                     synced_at = now()",
            )
            .bind(upstream_id)
            .bind(&pkg.name)
            .bind(pkg.epoch)
            .bind(&pkg.version)
            .bind(&pkg.release)
            .bind(&pkg.arch)
            .bind(&pkg.filename)
            .bind(&pkg.download_url)
            .bind(pkg.size_bytes)
            .bind(&pkg.sha256)
            .bind(&pkg.metadata)
            .execute(&mut *tx)
            .await?;
        }

        // Delete anything from a prior sync that `fresh` no longer lists —
        // built as a set of tuples rather than a per-row DELETE so a
        // 100k-entry upstream doesn't cost 100k round trips.
        let names: Vec<&str> = fresh.iter().map(|p| p.name.as_str()).collect();
        let versions: Vec<&str> = fresh.iter().map(|p| p.version.as_str()).collect();
        let releases: Vec<&str> = fresh.iter().map(|p| p.release.as_str()).collect();
        let arches: Vec<&str> = fresh.iter().map(|p| p.arch.as_str()).collect();
        let epochs: Vec<i32> = fresh.iter().map(|p| p.epoch).collect();

        sqlx::query(
            "DELETE FROM upstream_packages \
             WHERE upstream_id = $1 \
             AND NOT (name, epoch, version, release, arch) IN ( \
                 SELECT * FROM UNNEST($2::text[], $3::int[], $4::text[], $5::text[], $6::text[]) \
             )",
        )
        .bind(upstream_id)
        .bind(&names)
        .bind(&epochs)
        .bind(&versions)
        .bind(&releases)
        .bind(&arches)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Upserts several synced packages in one transaction — the
    /// lazy-population path npm uses (see `upstreams` module docs):
    /// there's no wholesale upstream index to replace against, so each
    /// requested name's versions are synced on their own as the name is
    /// looked up, all in one round trip to the pool rather than one per
    /// version.
    pub async fn upsert_upstream_packages(
        &self,
        upstream_id: Uuid,
        packages: &[SyncedPackage],
    ) -> anyhow::Result<()> {
        if packages.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool().begin().await?;
        for pkg in packages {
            sqlx::query(
                "INSERT INTO upstream_packages (upstream_id, name, epoch, version, release, \
                     arch, filename, download_url, size_bytes, sha256, metadata) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) \
                 ON CONFLICT (upstream_id, name, epoch, version, release, arch) DO UPDATE SET \
                     filename = excluded.filename, \
                     download_url = excluded.download_url, \
                     size_bytes = excluded.size_bytes, \
                     sha256 = excluded.sha256, \
                     metadata = excluded.metadata, \
                     synced_at = now()",
            )
            .bind(upstream_id)
            .bind(&pkg.name)
            .bind(pkg.epoch)
            .bind(&pkg.version)
            .bind(&pkg.release)
            .bind(&pkg.arch)
            .bind(&pkg.filename)
            .bind(&pkg.download_url)
            .bind(pkg.size_bytes)
            .bind(&pkg.sha256)
            .bind(&pkg.metadata)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Every synced version of `name` for one upstream — what the
    /// pull-through decision step compares a local package against to
    /// decide whether upstream is fresher.
    pub async fn list_upstream_package_versions(
        &self,
        upstream_id: Uuid,
        name: &str,
    ) -> anyhow::Result<Vec<UpstreamPackageRow>> {
        Ok(sqlx::query_as(&format!(
            "SELECT {UP_COLUMNS} FROM upstream_packages WHERE upstream_id = $1 AND name = $2"
        ))
        .bind(upstream_id)
        .bind(name)
        .fetch_all(self.pool())
        .await?)
    }

    /// Every synced entry for one upstream, across every name — what index
    /// regeneration merges into the rendered index (filtered down to one
    /// format's `index_group` in the caller) and what a storage-miss
    /// artifact fetch resolves a requested filename against.
    pub async fn list_all_upstream_packages(
        &self,
        upstream_id: Uuid,
    ) -> anyhow::Result<Vec<UpstreamPackageRow>> {
        list_all_upstream_packages(self.pool(), upstream_id).await
    }

    /// Looks up one upstream's synced entry by filename — what the
    /// storage-miss path in `serve_package` resolves a requested object
    /// key's filename against to find a download URL and cache/no-cache
    /// disposition.
    pub async fn find_upstream_package_by_filename(
        &self,
        upstream_id: Uuid,
        filename: &str,
    ) -> anyhow::Result<Option<UpstreamPackageRow>> {
        Ok(sqlx::query_as(&format!(
            "SELECT {UP_COLUMNS} FROM upstream_packages WHERE upstream_id = $1 AND filename = $2"
        ))
        .bind(upstream_id)
        .bind(filename)
        .fetch_optional(self.pool())
        .await?)
    }

    /// `(repo, channel, name, synced package count)` for every upstream —
    /// what the `upstream_packages_synced` gauge refreshes itself from,
    /// the same "reset then repopulate from one query" shape
    /// `Metrics::refresh_inventory` already uses for `packages`.
    pub async fn upstream_package_counts(
        &self,
    ) -> anyhow::Result<Vec<(String, String, String, i64)>> {
        Ok(sqlx::query_as(
            "SELECT u.repo, u.channel, u.name, count(p.id) \
             FROM upstreams u LEFT JOIN upstream_packages p ON p.upstream_id = u.id \
             GROUP BY u.repo, u.channel, u.name \
             ORDER BY u.repo, u.channel, u.name",
        )
        .fetch_all(self.pool())
        .await?)
    }

    pub async fn count_upstream_packages(&self, upstream_id: Uuid) -> anyhow::Result<i64> {
        Ok(
            sqlx::query_scalar("SELECT count(*) FROM upstream_packages WHERE upstream_id = $1")
                .bind(upstream_id)
                .fetch_one(self.pool())
                .await?,
        )
    }
}

/// Same query as [`Db::list_all_upstream_packages`], over an explicit
/// executor — see [`list_upstreams`] for why a locked index regeneration
/// needs this instead of the pool-bound method.
pub async fn list_all_upstream_packages<'e, E: PgExecutor<'e>>(
    executor: E,
    upstream_id: Uuid,
) -> anyhow::Result<Vec<UpstreamPackageRow>> {
    Ok(sqlx::query_as(&format!(
        "SELECT {UP_COLUMNS} FROM upstream_packages WHERE upstream_id = $1"
    ))
    .bind(upstream_id)
    .fetch_all(executor)
    .await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    async fn db() -> Option<Db> {
        let url = std::env::var("SILO_TEST_DATABASE_URL").ok()?;
        if url.trim().is_empty() {
            return None;
        }
        Some(
            Db::connect(&crate::DbConfig {
                url,
                max_connections: 4,
                connect_timeout: std::time::Duration::from_secs(30),
                token_pepper: None,
            })
            .await
            .expect("connect to the test database"),
        )
    }

    fn unique(prefix: &str) -> String {
        format!(
            "{prefix}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        )
    }

    fn new_upstream(repo: &str, channel: &str, name: &str) -> NewUpstream {
        NewUpstream {
            repo: repo.to_string(),
            channel: channel.to_string(),
            name: name.to_string(),
            format: "rpm".to_string(),
            base_url: "https://example.com/repo".to_string(),
            cache_mode: "cache".to_string(),
            cache_index_in_memory: false,
            arches: vec![],
            suite: None,
            components: vec![],
            auth: None,
        }
    }

    fn synced(name: &str, version: &str) -> SyncedPackage {
        SyncedPackage {
            name: name.to_string(),
            epoch: 0,
            version: version.to_string(),
            release: "1".to_string(),
            arch: "x86_64".to_string(),
            filename: format!("{name}-{version}-1.x86_64.rpm"),
            download_url: format!("https://example.com/repo/{name}-{version}-1.x86_64.rpm"),
            size_bytes: Some(100),
            sha256: Some("abc".to_string()),
            metadata: json!({}),
        }
    }

    #[tokio::test]
    async fn create_get_and_list_round_trip() {
        let Some(db) = db().await else {
            eprintln!("skipping: set SILO_TEST_DATABASE_URL");
            return;
        };
        let repo = unique("up");
        let created = db
            .create_upstream(&new_upstream(&repo, "stable", "epel"))
            .await
            .unwrap();
        assert_eq!(created.status, "ok");
        assert!(created.auth_kind.is_none());

        let fetched = db
            .get_upstream(&repo, "stable", "epel")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched.id, created.id);

        let listed = db.list_upstreams(&repo, "stable").await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "epel");
    }

    #[tokio::test]
    async fn duplicate_name_within_repo_channel_is_rejected() {
        let Some(db) = db().await else {
            eprintln!("skipping: set SILO_TEST_DATABASE_URL");
            return;
        };
        let repo = unique("dup");
        db.create_upstream(&new_upstream(&repo, "stable", "epel"))
            .await
            .unwrap();
        assert!(db
            .create_upstream(&new_upstream(&repo, "stable", "epel"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn auth_kind_and_secret_columns_stay_consistent() {
        let Some(db) = db().await else {
            eprintln!("skipping: set SILO_TEST_DATABASE_URL");
            return;
        };
        let repo = unique("auth");
        let mut new = new_upstream(&repo, "stable", "priv");
        new.auth = Some(SealedAuth {
            kind: "basic".to_string(),
            username: Some("bot".to_string()),
            ciphertext: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
        });
        let row = db.create_upstream(&new).await.unwrap();
        assert_eq!(row.auth_kind.as_deref(), Some("basic"));
        assert_eq!(row.auth_username.as_deref(), Some("bot"));
        assert_eq!(row.auth_secret_ciphertext, Some(vec![1, 2, 3]));
    }

    #[tokio::test]
    async fn delete_upstream_clears_package_origin_but_keeps_the_package() {
        let Some(db) = db().await else {
            eprintln!("skipping: set SILO_TEST_DATABASE_URL");
            return;
        };
        let repo = unique("del");
        let upstream = db
            .create_upstream(&new_upstream(&repo, "stable", "epel"))
            .await
            .unwrap();

        sqlx::query(
            "INSERT INTO packages (repo, channel, format, name, version, filename, \
             storage_key, size_bytes, sha256, origin_upstream_id) \
             VALUES ($1, 'stable', 'rpm', 'pkg', '1.0', 'pkg.rpm', 'k', 0, 'x', $2)",
        )
        .bind(&repo)
        .bind(upstream.id)
        .execute(db.pool())
        .await
        .unwrap();

        assert!(db.delete_upstream(upstream.id).await.unwrap().is_some());

        let origin: Option<Uuid> =
            sqlx::query_scalar("SELECT origin_upstream_id FROM packages WHERE repo = $1")
                .bind(&repo)
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert!(
            origin.is_none(),
            "origin must be cleared, not the package deleted"
        );
    }

    #[tokio::test]
    async fn record_sync_outcomes() {
        let Some(db) = db().await else {
            eprintln!("skipping: set SILO_TEST_DATABASE_URL");
            return;
        };
        let repo = unique("sync");
        let upstream = db
            .create_upstream(&new_upstream(&repo, "stable", "epel"))
            .await
            .unwrap();

        db.record_upstream_sync_failure(upstream.id, "connection refused")
            .await
            .unwrap();
        let row = db.find_upstream(upstream.id).await.unwrap().unwrap();
        assert_eq!(row.status, "error");
        assert_eq!(row.last_sync_error.as_deref(), Some("connection refused"));
        assert!(row.last_success_at.is_none());

        db.record_upstream_sync_success(upstream.id).await.unwrap();
        let row = db.find_upstream(upstream.id).await.unwrap().unwrap();
        assert_eq!(row.status, "ok");
        assert!(row.last_sync_error.is_none());
        assert!(row.last_success_at.is_some());
    }

    #[tokio::test]
    async fn replace_upstream_packages_upserts_and_drops_missing_entries() {
        let Some(db) = db().await else {
            eprintln!("skipping: set SILO_TEST_DATABASE_URL");
            return;
        };
        let repo = unique("sync2");
        let upstream = db
            .create_upstream(&new_upstream(&repo, "stable", "epel"))
            .await
            .unwrap();

        db.replace_upstream_packages(upstream.id, &[synced("curl", "8.0"), synced("wget", "1.0")])
            .await
            .unwrap();
        assert_eq!(db.count_upstream_packages(upstream.id).await.unwrap(), 2);

        // A second sync that drops `wget` and bumps `curl` must remove the
        // former and update the latter, not just add rows.
        db.replace_upstream_packages(upstream.id, &[synced("curl", "8.1")])
            .await
            .unwrap();
        let versions = db
            .list_upstream_package_versions(upstream.id, "curl")
            .await
            .unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, "8.1");
        assert!(db
            .list_upstream_package_versions(upstream.id, "wget")
            .await
            .unwrap()
            .is_empty());
        assert_eq!(db.count_upstream_packages(upstream.id).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn upsert_upstream_packages_is_the_lazy_batch_entry_path() {
        let Some(db) = db().await else {
            eprintln!("skipping: set SILO_TEST_DATABASE_URL");
            return;
        };
        let repo = unique("lazy");
        let mut new = new_upstream(&repo, "stable", "npmjs");
        new.format = "npm".to_string();
        let upstream = db.create_upstream(&new).await.unwrap();

        db.upsert_upstream_packages(
            upstream.id,
            &[synced("left-pad", "1.0.0"), synced("left-pad", "1.0.1")],
        )
        .await
        .unwrap();
        let versions = db
            .list_upstream_package_versions(upstream.id, "left-pad")
            .await
            .unwrap();
        assert_eq!(versions.len(), 2);

        // Re-fetching the same name/version updates in place, not duplicates.
        db.upsert_upstream_packages(upstream.id, &[synced("left-pad", "1.0.0")])
            .await
            .unwrap();
        let versions = db
            .list_upstream_package_versions(upstream.id, "left-pad")
            .await
            .unwrap();
        assert_eq!(versions.len(), 2);

        // An empty batch is a no-op, not an error.
        db.upsert_upstream_packages(upstream.id, &[]).await.unwrap();
    }

    #[tokio::test]
    async fn find_upstream_package_by_filename_looks_up_across_names() {
        let Some(db) = db().await else {
            eprintln!("skipping: set SILO_TEST_DATABASE_URL");
            return;
        };
        let repo = unique("byfile");
        let upstream = db
            .create_upstream(&new_upstream(&repo, "stable", "epel"))
            .await
            .unwrap();
        db.replace_upstream_packages(upstream.id, &[synced("curl", "8.0")])
            .await
            .unwrap();

        let found = db
            .find_upstream_package_by_filename(upstream.id, "curl-8.0-1.x86_64.rpm")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.name, "curl");
        assert!(db
            .find_upstream_package_by_filename(upstream.id, "does-not-exist.rpm")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn list_all_upstream_packages_returns_every_synced_name() {
        let Some(db) = db().await else {
            eprintln!("skipping: set SILO_TEST_DATABASE_URL");
            return;
        };
        let repo = unique("listall");
        let upstream = db
            .create_upstream(&new_upstream(&repo, "stable", "epel"))
            .await
            .unwrap();
        db.replace_upstream_packages(upstream.id, &[synced("curl", "8.0"), synced("wget", "1.0")])
            .await
            .unwrap();

        let all = db.list_all_upstream_packages(upstream.id).await.unwrap();
        assert_eq!(all.len(), 2);
    }
}
