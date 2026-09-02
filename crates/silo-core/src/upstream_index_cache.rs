//! The opt-in in-memory read accelerator for a synced upstream index.
//!
//! Per-request lookups against `upstream_packages` are indexed btree
//! point-lookups — flat latency regardless of table size, so even a
//! huge mirror doesn't make a single lookup meaningfully slower than any
//! other query this server already makes. What actually costs time at
//! that scale is the *sync* job (parsing and upserting a huge index), not
//! reading it back. So this exists purely as an opt-in accelerator for
//! operators who've measured otherwise for a specific upstream — never a
//! correctness dependency: every read here falls through to the database
//! on a miss, and a lookup against an upstream with the flag off never
//! touches this at all.
//!
//! Deliberately *not* incrementally maintained: it's rebuilt wholesale
//! (read-through, then [`UpstreamIndexCache::invalidate`] after every
//! sync so the next read repopulates) rather than patched entry by entry,
//! so there's no per-write invalidation logic to get subtly wrong. Each
//! server replica keeps its own copy — this is process-local, not shared
//! — so it can lag another replica's view by up to one sync interval,
//! the same staleness window pull-through already tolerates elsewhere.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use silo_db::upstreams::UpstreamPackageRow;
use silo_db::Uuid;

#[derive(Default)]
pub struct UpstreamIndexCache {
    entries: RwLock<HashMap<Uuid, Arc<Vec<UpstreamPackageRow>>>>,
}

impl UpstreamIndexCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a cheap `Arc` clone (a refcount bump), not a deep copy of
    /// the underlying `Vec` — the whole point of caching a large mirror's
    /// index is to avoid paying its clone cost on every request.
    pub fn get(&self, upstream_id: Uuid) -> Option<Arc<Vec<UpstreamPackageRow>>> {
        self.entries
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&upstream_id)
            .cloned()
    }

    pub fn put(&self, upstream_id: Uuid, rows: Arc<Vec<UpstreamPackageRow>>) {
        self.entries
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(upstream_id, rows);
    }

    /// Drops any cached copy, so the next read repopulates from the
    /// database — called after every sync (successful or not: a failed
    /// sync's stale cache entry is worse than none) and after an
    /// upstream is removed.
    pub fn invalidate(&self, upstream_id: Uuid) {
        self.entries
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&upstream_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn row(name: &str) -> UpstreamPackageRow {
        UpstreamPackageRow {
            id: 1,
            upstream_id: Uuid::nil(),
            name: name.to_string(),
            epoch: 0,
            version: "1.0".into(),
            release: String::new(),
            arch: "x86_64".into(),
            filename: format!("{name}-1.0.apk"),
            download_url: "https://example.com/x".into(),
            size_bytes: None,
            sha256: None,
            metadata: json!({}),
            synced_at: chrono::DateTime::from_timestamp(0, 0).unwrap(),
        }
    }

    #[test]
    fn a_miss_returns_none_and_a_put_is_visible_afterward() {
        let cache = UpstreamIndexCache::new();
        let id = Uuid::from_u128(1);
        assert!(cache.get(id).is_none());
        cache.put(id, Arc::new(vec![row("curl")]));
        assert_eq!(cache.get(id).unwrap().len(), 1);
    }

    #[test]
    fn invalidate_clears_only_the_named_upstream() {
        let cache = UpstreamIndexCache::new();
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        cache.put(a, Arc::new(vec![row("curl")]));
        cache.put(b, Arc::new(vec![row("wget")]));

        cache.invalidate(a);
        assert!(cache.get(a).is_none());
        assert!(cache.get(b).is_some());
    }
}
