//! The package index.
//!
//! This table is what lets a publish avoid reading object storage at all.
//! Before it existed, regenerating an index meant a LIST plus a GET per
//! package just to find out what was already there; now the only
//! object-storage traffic on the publish path is writing the new package
//! and its index.
//!
//! `metadata` is what makes that true for every format. It holds whatever
//! the format's index needs that no column here could: APKINDEX fields,
//! an npm `package.json`, and for RPM the dependencies, file lists and
//! header byte ranges `primary.xml` publishes.
//!
//! Every query here takes an `Executor`, so callers can run them inside
//! the same transaction that holds the publish lock — the index is
//! rendered from rows that include the not-yet-committed publish, and a
//! rollback takes the row back out with it.

use serde_json::Value;
use silo_pkg::{PackageFormat, PackageRecord};
use sqlx::{FromRow, PgExecutor};
use uuid::Uuid;

use crate::{DateTime, Db};

#[derive(Debug, Clone, FromRow)]
pub struct PackageRow {
    pub id: i64,
    pub repo: String,
    pub channel: String,
    pub format: String,
    pub index_group: String,
    pub name: String,
    pub epoch: i32,
    pub version: String,
    pub release: String,
    pub arch: String,
    pub filename: String,
    pub storage_key: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub metadata: Value,
    pub published_at: DateTime,
    pub published_by_token: Option<Uuid>,
    pub published_by_user: Option<Uuid>,
}

impl PackageRow {
    pub fn to_record(&self) -> PackageRecord {
        PackageRecord {
            // A row whose format string doesn't parse can only come from a
            // future version writing to an older binary's database;
            // defaulting to rpm keeps the rest of the index renderable.
            format: self.format.parse().unwrap_or(PackageFormat::Rpm),
            name: self.name.clone(),
            epoch: self.epoch.max(0) as u32,
            version: self.version.clone(),
            release: self.release.clone(),
            arch: self.arch.clone(),
            filename: self.filename.clone(),
            storage_key: self.storage_key.clone(),
            size_bytes: self.size_bytes,
            sha256: self.sha256.clone(),
            metadata: self.metadata.clone(),
            published_at: self.published_at.timestamp(),
        }
    }
}

/// A package about to be recorded. Mirrors `PackageRow` minus the
/// database-assigned columns.
#[derive(Debug, Clone)]
pub struct NewPackage {
    pub repo: String,
    pub channel: String,
    pub format: PackageFormat,
    pub index_group: String,
    pub name: String,
    pub epoch: u32,
    pub version: String,
    pub release: String,
    pub arch: String,
    pub filename: String,
    pub storage_key: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub metadata: Value,
    pub published_by_token: Option<Uuid>,
    pub published_by_user: Option<Uuid>,
}

const COLUMNS: &str = "id, repo, channel, format, index_group, name, epoch, version, release, \
                       arch, filename, storage_key, size_bytes, sha256, metadata, published_at, \
                       published_by_token, published_by_user";

/// Inserts or replaces a package.
///
/// Republishing the same file name is an update, not a duplicate: two rows
/// for one storage key would render the package twice in the index, and
/// the bytes in object storage have already been overwritten by then
/// anyway.
pub async fn upsert<'e, E: PgExecutor<'e>>(
    executor: E,
    pkg: &NewPackage,
) -> anyhow::Result<PackageRow> {
    let row: PackageRow = sqlx::query_as(&format!(
        "INSERT INTO packages (repo, channel, format, index_group, name, epoch, version, \
                               release, arch, filename, storage_key, size_bytes, sha256, \
                               metadata, published_by_token, published_by_user) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) \
         ON CONFLICT (repo, channel, format, storage_key) DO UPDATE SET \
             index_group = EXCLUDED.index_group, \
             name = EXCLUDED.name, \
             epoch = EXCLUDED.epoch, \
             version = EXCLUDED.version, \
             release = EXCLUDED.release, \
             arch = EXCLUDED.arch, \
             filename = EXCLUDED.filename, \
             size_bytes = EXCLUDED.size_bytes, \
             sha256 = EXCLUDED.sha256, \
             metadata = EXCLUDED.metadata, \
             published_at = now(), \
             published_by_token = EXCLUDED.published_by_token, \
             published_by_user = EXCLUDED.published_by_user \
         RETURNING {COLUMNS}"
    ))
    .bind(&pkg.repo)
    .bind(&pkg.channel)
    .bind(pkg.format.as_str())
    .bind(&pkg.index_group)
    .bind(&pkg.name)
    .bind(pkg.epoch as i32)
    .bind(&pkg.version)
    .bind(&pkg.release)
    .bind(&pkg.arch)
    .bind(&pkg.filename)
    .bind(&pkg.storage_key)
    .bind(pkg.size_bytes)
    .bind(&pkg.sha256)
    .bind(&pkg.metadata)
    .bind(pkg.published_by_token)
    .bind(pkg.published_by_user)
    .fetch_one(executor)
    .await?;
    Ok(row)
}

/// Every package in one index group — exactly the input an index renderer
/// needs.
/// Every package in one index group.
pub async fn list_group<'e, E: PgExecutor<'e>>(
    executor: E,
    repo: &str,
    channel: &str,
    format: PackageFormat,
    index_group: &str,
) -> anyhow::Result<Vec<PackageRow>> {
    list_groups(
        executor,
        repo,
        channel,
        format,
        std::slice::from_ref(&index_group.to_string()),
    )
    .await
}

/// Every package in any of `index_groups`.
///
/// More than one group is an apk thing: an architecture's APKINDEX lists
/// that architecture's packages *and* the channel's `noarch` ones, since
/// apk-tools never looks in a noarch directory itself.
pub async fn list_groups<'e, E: PgExecutor<'e>>(
    executor: E,
    repo: &str,
    channel: &str,
    format: PackageFormat,
    index_groups: &[String],
) -> anyhow::Result<Vec<PackageRow>> {
    Ok(sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM packages \
         WHERE repo = $1 AND channel = $2 AND format = $3 AND index_group = ANY($4) \
         ORDER BY name, version"
    ))
    .bind(repo)
    .bind(channel)
    .bind(format.as_str())
    .bind(index_groups)
    .fetch_all(executor)
    .await?)
}

/// The distinct index groups a repo/channel has for one format.
///
/// Used to find every architecture whose APKINDEX a `noarch` publish has
/// invalidated.
pub async fn list_index_groups<'e, E: PgExecutor<'e>>(
    executor: E,
    repo: &str,
    channel: &str,
    format: PackageFormat,
) -> anyhow::Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT DISTINCT index_group FROM packages \
         WHERE repo = $1 AND channel = $2 AND format = $3 \
         ORDER BY index_group",
    )
    .bind(repo)
    .bind(channel)
    .bind(format.as_str())
    .fetch_all(executor)
    .await?;
    Ok(rows.into_iter().map(|(g,)| g).collect())
}

impl Db {
    /// Lists a repo/channel, optionally narrowed to one format. This is
    /// what `silo list` reads, and it never touches object storage.
    pub async fn list_packages(
        &self,
        repo: &str,
        channel: &str,
        format: Option<PackageFormat>,
    ) -> anyhow::Result<Vec<PackageRow>> {
        Ok(sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM packages \
             WHERE repo = $1 AND channel = $2 AND ($3::text IS NULL OR format = $3) \
             ORDER BY format, name, version"
        ))
        .bind(repo)
        .bind(channel)
        .bind(format.map(|f| f.as_str()))
        .fetch_all(self.pool())
        .await?)
    }

    /// Resolves a storage key back to its package row, so a download can
    /// be audited with real package identity instead of a raw path.
    pub async fn find_by_storage_key(&self, key: &str) -> anyhow::Result<Option<PackageRow>> {
        Ok(sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM packages WHERE storage_key = $1"
        ))
        .bind(key)
        .fetch_optional(self.pool())
        .await?)
    }

    /// Reads a package row by id without deleting it, so a caller can
    /// check the repo it belongs to *before* acting on it. `delete_package`
    /// deletes and returns in one statement, which is too late to refuse
    /// a caller whose token doesn't cover that repo.
    pub async fn find_package(&self, id: i64) -> anyhow::Result<Option<PackageRow>> {
        Ok(
            sqlx::query_as(&format!("SELECT {COLUMNS} FROM packages WHERE id = $1"))
                .bind(id)
                .fetch_optional(self.pool())
                .await?,
        )
    }

    pub async fn delete_package(&self, id: i64) -> anyhow::Result<Option<PackageRow>> {
        Ok(sqlx::query_as(&format!(
            "DELETE FROM packages WHERE id = $1 RETURNING {COLUMNS}"
        ))
        .bind(id)
        .fetch_optional(self.pool())
        .await?)
    }

    /// Every package in a repo, across all channels and formats. Used only
    /// by `repo delete --force` to enumerate everything that needs purging
    /// before the repo row itself can go.
    pub async fn list_all_in_repo(&self, repo: &str) -> anyhow::Result<Vec<PackageRow>> {
        Ok(sqlx::query_as(&format!(
            "SELECT {COLUMNS} FROM packages WHERE repo = $1 ORDER BY id"
        ))
        .bind(repo)
        .fetch_all(self.pool())
        .await?)
    }

    /// Distinct repo/channel pairs, for `silo repos` and the metrics
    /// gauges.
    pub async fn list_repos(&self) -> anyhow::Result<Vec<RepoSummary>> {
        // `sum()` over a bigint returns NUMERIC in Postgres, which will
        // not decode into i64 — hence the explicit cast. The join is full
        // rather than left so a repo created ahead of its first publish
        // (via `repo create`/`repo set`) still lists, with no packages —
        // hence `count(p.id)` rather than `count(*)`, so the synthetic
        // all-NULL row a full join produces for such a repo counts as 0
        // packages rather than 1. `coalesce(r.public, false)` covers a repo
        // that predates the `repos` table backfill (or was published to
        // before `ensure_repo` ran, in theory) — still lists, just private.
        Ok(sqlx::query_as(
            "SELECT coalesce(p.repo, r.repo) AS repo, \
                    coalesce(p.channel, '') AS channel, \
                    coalesce(p.format, '') AS format, \
                    count(p.id) AS packages, \
                    coalesce(sum(p.size_bytes), 0)::bigint AS total_bytes, \
                    coalesce(r.public, false) AS public \
             FROM packages p FULL JOIN repos r ON r.repo = p.repo \
             GROUP BY coalesce(p.repo, r.repo), coalesce(p.channel, ''), \
                      coalesce(p.format, ''), r.public \
             ORDER BY 1, 2, 3",
        )
        .fetch_all(self.pool())
        .await?)
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct RepoSummary {
    pub repo: String,
    pub channel: String,
    pub format: String,
    pub packages: i64,
    pub total_bytes: i64,
    pub public: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn row() -> PackageRow {
        PackageRow {
            id: 1,
            repo: "r".into(),
            channel: "c".into(),
            format: "apk".into(),
            index_group: "x86_64".into(),
            name: "foo".into(),
            epoch: 0,
            version: "1.0-r0".into(),
            release: String::new(),
            arch: "x86_64".into(),
            filename: "foo-1.0-r0.apk".into(),
            storage_key: "r/c/apk/x86_64/foo-1.0-r0.apk".into(),
            size_bytes: 99,
            sha256: "abc".into(),
            metadata: json!({"checksum": "Q1x"}),
            published_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            published_by_token: None,
            published_by_user: None,
        }
    }

    #[test]
    fn rows_convert_into_index_records() {
        let record = row().to_record();
        assert_eq!(record.format, PackageFormat::Apk);
        assert_eq!(record.name, "foo");
        assert_eq!(record.size_bytes, 99);
        assert_eq!(record.published_at, 1_700_000_000);
        assert_eq!(record.metadata["checksum"], "Q1x");
    }

    #[test]
    fn unparseable_format_strings_do_not_panic() {
        let mut row = row();
        row.format = "snap".into();
        assert_eq!(row.to_record().format, PackageFormat::Rpm);
    }

    #[test]
    fn negative_epochs_clamp_to_zero() {
        let mut row = row();
        row.epoch = -1;
        assert_eq!(row.to_record().epoch, 0);
    }
}
