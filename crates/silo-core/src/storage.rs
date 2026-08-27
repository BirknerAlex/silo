use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use object_store::aws::AmazonS3Builder;
use object_store::path::Path as ObjectPath;
use object_store::signer::Signer;
use object_store::{Attribute, Attributes, ObjectStore, PutOptions, PutPayload};

use crate::config::StorageConfig;

#[derive(Clone)]
pub struct Storage {
    store: Arc<dyn ObjectStore>,
    signer: Option<Arc<dyn Signer>>,
}

impl Storage {
    pub fn from_config(cfg: &StorageConfig) -> anyhow::Result<Self> {
        let mut builder = AmazonS3Builder::new()
            .with_bucket_name(&cfg.bucket)
            .with_region(&cfg.region)
            .with_access_key_id(&cfg.access_key_id)
            .with_secret_access_key(&cfg.secret_access_key)
            .with_allow_http(cfg.allow_http);
        if let Some(endpoint) = &cfg.endpoint {
            builder = builder
                .with_endpoint(endpoint)
                .with_virtual_hosted_style_request(false);
        }
        let store = builder.build()?;
        let store = Arc::new(store);
        Ok(Self {
            signer: Some(store.clone() as Arc<dyn Signer>),
            store,
        })
    }

    #[cfg(any(test, feature = "test-util"))]
    pub fn in_memory() -> Self {
        Self {
            store: Arc::new(object_store::memory::InMemory::new()),
            signer: None,
        }
    }

    /// A time-limited GET URL for a package that clients can be redirected
    /// to, bypassing this server for the actual download. Returns `None`
    /// for backends that don't support presigning (e.g. the in-memory
    /// store used in tests) — callers should fall back to proxying bytes.
    pub async fn presigned_get_url(&self, key: &str) -> anyhow::Result<Option<String>> {
        let Some(signer) = &self.signer else {
            return Ok(None);
        };
        let path = ObjectPath::from(key);
        let url = signer
            .signed_url(reqwest::Method::GET, &path, Duration::from_secs(300))
            .await?;
        Ok(Some(url.to_string()))
    }

    pub async fn put(&self, key: &str, bytes: Vec<u8>) -> anyhow::Result<()> {
        let path = ObjectPath::from(key);
        self.store
            .put(&path, PutPayload::from_bytes(Bytes::from(bytes)))
            .await?;
        Ok(())
    }

    /// Writes an object with an explicit `Content-Type`.
    ///
    /// This matters for the objects clients fetch *directly* from S3 via a
    /// presigned redirect: the server never sees those requests, so the
    /// only chance to get the header right is at upload time. npm in
    /// particular refuses a packument that doesn't come back as JSON.
    pub async fn put_typed(
        &self,
        key: &str,
        bytes: Vec<u8>,
        content_type: &str,
    ) -> anyhow::Result<()> {
        let path = ObjectPath::from(key);
        let mut attributes = Attributes::new();
        attributes.insert(Attribute::ContentType, content_type.to_string().into());
        self.store
            .put_opts(
                &path,
                PutPayload::from_bytes(Bytes::from(bytes)),
                PutOptions {
                    attributes,
                    ..Default::default()
                },
            )
            .await?;
        Ok(())
    }

    pub async fn delete(&self, key: &str) -> anyhow::Result<()> {
        let path = ObjectPath::from(key);
        match self.store.delete(&path).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn get(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let path = ObjectPath::from(key);
        match self.store.get(&path).await {
            Ok(result) => Ok(Some(result.bytes().await?.to_vec())),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Whether an object exists, without transferring it.
    ///
    /// A HEAD rather than a GET matters here: this is used to choose
    /// between two candidate keys for a package that may be tens of
    /// megabytes, and the loser would be downloaded for nothing.
    pub async fn head(&self, key: &str) -> anyhow::Result<bool> {
        let path = ObjectPath::from(key);
        match self.store.head(&path).await {
            Ok(_) => Ok(true),
            Err(object_store::Error::NotFound { .. }) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    pub async fn list(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
        Ok(self
            .list_sized(prefix)
            .await?
            .into_iter()
            .map(|(key, _)| key)
            .collect())
    }

    /// Like `list`, but also returns each object's size in bytes.
    pub async fn list_sized(&self, prefix: &str) -> anyhow::Result<Vec<(String, u64)>> {
        use futures::StreamExt;
        let prefix_path = ObjectPath::from(prefix);
        let mut stream = self.store.list(Some(&prefix_path));
        let mut entries = Vec::new();
        while let Some(meta) = stream.next().await {
            let meta = meta?;
            entries.push((meta.location.to_string(), meta.size as u64));
        }
        Ok(entries)
    }

    pub fn store(&self) -> Arc<dyn ObjectStore> {
        self.store.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn put_typed_roundtrips_like_put() {
        let storage = Storage::in_memory();
        storage
            .put_typed(
                "r/c/npm/foo/packument.json",
                b"{}".to_vec(),
                "application/json",
            )
            .await
            .unwrap();
        assert_eq!(
            storage.get("r/c/npm/foo/packument.json").await.unwrap(),
            Some(b"{}".to_vec())
        );
    }

    #[tokio::test]
    async fn delete_removes_an_object_and_tolerates_a_missing_one() {
        let storage = Storage::in_memory();
        storage.put("a/b.rpm", b"x".to_vec()).await.unwrap();
        storage.delete("a/b.rpm").await.unwrap();
        assert_eq!(storage.get("a/b.rpm").await.unwrap(), None);
        // Deleting again must not error: index cleanup races with itself
        // across replicas, and "already gone" is the desired end state.
        storage.delete("a/b.rpm").await.unwrap();
    }

    #[tokio::test]
    async fn put_get_roundtrip() {
        let storage = Storage::in_memory();
        storage
            .put("repo/channel/Packages/foo.rpm", b"hello".to_vec())
            .await
            .unwrap();
        let got = storage.get("repo/channel/Packages/foo.rpm").await.unwrap();
        assert_eq!(got, Some(b"hello".to_vec()));
    }

    #[tokio::test]
    async fn get_missing_key_returns_none() {
        let storage = Storage::in_memory();
        let got = storage.get("does/not/exist.rpm").await.unwrap();
        assert_eq!(got, None);
    }

    #[tokio::test]
    async fn list_returns_keys_under_prefix() {
        let storage = Storage::in_memory();
        storage
            .put("repo/channel/Packages/a.rpm", b"a".to_vec())
            .await
            .unwrap();
        storage
            .put("repo/channel/Packages/b.rpm", b"b".to_vec())
            .await
            .unwrap();
        storage
            .put("other/channel/Packages/c.rpm", b"c".to_vec())
            .await
            .unwrap();

        let keys = storage.list("repo/channel").await.unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.iter().all(|k| k.starts_with("repo/channel")));
    }
}
