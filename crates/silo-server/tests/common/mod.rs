//! Shared harness for the database-backed integration tests.
//!
//! These tests need a real Postgres — the whole point of most of them is
//! the SQL, the transactions, and the advisory locks, none of which a mock
//! would exercise. Point `SILO_TEST_DATABASE_URL` at a throwaway database
//! and they run; leave it unset and they skip with a message rather than
//! failing, so `cargo test` still works on a machine without one.
//!
//! ```sh
//! docker run -d --name silo-test-pg -p 55432:5432 \
//!   -e POSTGRES_USER=silo -e POSTGRES_PASSWORD=silo -e POSTGRES_DB=silo \
//!   postgres:16-alpine
//! export SILO_TEST_DATABASE_URL=postgres://silo:silo@localhost:55432/silo
//! ```
//!
//! Tests share one database and isolate themselves by using a unique repo
//! name per test, which is also what makes them safe to run concurrently
//! (and what exercises the per-repo lock scoping for free).

#![allow(dead_code)] // each integration test binary uses a different subset

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use silo_core::config::{
    AuditConfig, AuthConfig, Config, DatabaseConfig, JobsConfig, MetricsConfig, PruneConfig,
    SigningConfig, StorageConfig,
};
use silo_core::{PublishContext, Signers, Storage};
use silo_db::tokens::{IssuedToken, NewToken, Permission, Scope, TokenKind};
use silo_db::{Db, DbConfig};
use silo_server::metrics::Metrics;
use silo_server::AppState;

/// Returns the test database URL, or `None` when the suite should skip.
pub fn database_url() -> Option<String> {
    std::env::var("SILO_TEST_DATABASE_URL")
        .ok()
        .filter(|u| !u.trim().is_empty())
}

/// Prints the skip reason once per test. Returning `None` from a test's
/// setup and bailing keeps the skip visible in `cargo test -- --nocapture`
/// instead of silently passing.
#[macro_export]
macro_rules! require_db {
    () => {
        match $crate::common::database_url() {
            Some(url) => url,
            None => {
                eprintln!("skipping: set SILO_TEST_DATABASE_URL to run the database-backed tests");
                return;
            }
        }
    };
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A repo name unique to this process and call, so concurrent tests never
/// contend on the same rows or the same index lock.
pub fn unique_repo(prefix: &str) -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{}-{n}", std::process::id())
}

pub struct Harness {
    pub state: Arc<AppState>,
    pub db: Db,
}

impl Harness {
    pub async fn new(url: &str) -> Self {
        Self::with_config(url, |_| {}).await
    }

    pub async fn with_config(url: &str, tweak: impl FnOnce(&mut Config)) -> Self {
        let db = Db::connect(&DbConfig {
            url: url.to_string(),
            max_connections: 8,
            connect_timeout: std::time::Duration::from_secs(30),
            token_pepper: None,
        })
        .await
        .expect("connect to the test database");

        let mut config = Config {
            addr: "127.0.0.1:0".into(),
            public_base_url: Some("https://silo.test".into()),
            database: DatabaseConfig {
                url: url.to_string(),
                max_connections: 8,
                connect_timeout_seconds: 30,
            },
            storage: StorageConfig {
                bucket: "test".into(),
                endpoint: None,
                region: "us-east-1".into(),
                access_key_id: "x".into(),
                secret_access_key: "x".into(),
                allow_http: false,
            },
            auth: AuthConfig::default(),
            oidc: None,
            signing: SigningConfig::default(),
            audit: AuditConfig::default(),
            metrics: MetricsConfig::default(),
            prune: PruneConfig::default(),
            jobs: JobsConfig::default(),
        };
        tweak(&mut config);

        // In-memory object storage: these tests are about the database and
        // the index contents, and a real bucket would make them slow and
        // order-dependent without covering anything extra.
        let storage = Storage::in_memory();

        let state = Arc::new(AppState {
            publish: PublishContext {
                storage: storage.clone(),
                db: db.clone(),
                signers: Signers::default(),
                public_base_url: config.public_base_url.clone(),
            },
            config,
            storage,
            db: db.clone(),
            oidc: None,
            metrics: Metrics::new().expect("build metrics"),
        });

        Self { state, db }
    }

    /// Mints a token with the given reach.
    pub async fn token(&self, name: &str, permission: Permission, scope: Scope) -> IssuedToken {
        self.db
            .create_token(
                NewToken {
                    name: format!("{name}-{}", unique_repo("t")),
                    permission,
                    kind: TokenKind::Api,
                    scope,
                    user_id: None,
                    created_by: None,
                    expires_at: None,
                },
                None,
            )
            .await
            .expect("create a test token")
    }

    pub async fn admin_token(&self) -> IssuedToken {
        self.token("admin", Permission::Admin, Scope::All).await
    }

    pub async fn publisher_token(&self, repo: &str) -> IssuedToken {
        self.token(
            "publisher",
            Permission::Write,
            Scope::Repos(vec![repo.to_string()]),
        )
        .await
    }
}
