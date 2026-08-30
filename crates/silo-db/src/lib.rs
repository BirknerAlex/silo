//! Postgres-backed state for Silo: the package index, tokens, users,
//! audit log, and the advisory locks that coordinate replicas.
//!
//! Migrations are embedded in the binary and applied on startup, so
//! deploying a new image is the whole upgrade procedure — there's no
//! separate migration job to sequence in Helm.
//!
//! Queries here are runtime-checked (`sqlx::query`) rather than
//! macro-checked (`sqlx::query!`). Macro-checked queries would need either
//! a reachable database or a checked-in `.sqlx` offline cache at *compile*
//! time, which would make `cargo build` fail for anyone without either.
//! The types are still recovered via `FromRow` derives.

pub mod audit;
pub mod lock;
pub mod packages;
pub mod prune;
pub mod repos;
pub mod tokens;
pub mod users;

use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;

pub use sqlx::types::Uuid;
pub use sqlx::Error as SqlxError;

pub type DateTime = chrono::DateTime<chrono::Utc>;

/// Embedded migration set. `sqlx::migrate!` reads the directory at compile
/// time, so the binary carries its own schema.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[derive(Clone)]
pub struct Db {
    pool: PgPool,
}

#[derive(Debug, Clone)]
pub struct DbConfig {
    pub url: String,
    pub max_connections: u32,
    pub connect_timeout: Duration,
    /// Optional server-side secret mixed into token hashes. See
    /// [`tokens`] for the threat model.
    pub token_pepper: Option<String>,
}

impl Db {
    /// Connects, waiting for the database to accept connections, then runs
    /// migrations. The retry loop matters in Kubernetes, where silo and
    /// its Postgres routinely start in the same instant.
    pub async fn connect(cfg: &DbConfig) -> anyhow::Result<Self> {
        let options: PgConnectOptions = cfg
            .url
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid database url: {e}"))?;

        let deadline = std::time::Instant::now() + cfg.connect_timeout;
        let mut backoff = Duration::from_millis(250);
        let pool = loop {
            let attempt = PgPoolOptions::new()
                .max_connections(cfg.max_connections)
                .acquire_timeout(Duration::from_secs(10))
                .connect_with(options.clone())
                .await;
            match attempt {
                Ok(pool) => break pool,
                Err(e) if std::time::Instant::now() + backoff < deadline => {
                    tracing::warn!(error = %e, "database not ready, retrying");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(5));
                }
                Err(e) => return Err(anyhow::anyhow!("could not reach the database: {e}")),
            }
        };

        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
    }

    /// Applies any pending migrations. Postgres advisory locking inside
    /// `sqlx`'s migrator makes this safe to run from every replica
    /// simultaneously during a rolling deploy.
    pub async fn migrate(&self) -> anyhow::Result<()> {
        MIGRATOR
            .run(&self.pool)
            .await
            .map_err(|e| anyhow::anyhow!("migration failed: {e}"))?;
        tracing::info!("database migrations are up to date");
        Ok(())
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Cheap liveness probe used by the HTTP health endpoint.
    pub async fn ping(&self) -> anyhow::Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    /// Wraps an existing pool. Used by tests that build a pool with
    /// different options — including a lazily-connected one that is never
    /// actually dialled.
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The URL can carry a password; never let it reach a log line.
        f.debug_struct("Db").finish_non_exhaustive()
    }
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            url: "postgres://silo:silo@localhost:5432/silo".to_string(),
            max_connections: 10,
            connect_timeout: Duration::from_secs(60),
            token_pepper: None,
        }
    }
}
