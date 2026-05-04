use super::{ObjectMeta, ObjectStore};
use anyhow::{bail, Result};
use async_trait::async_trait;

pub struct HttpStore {
    base_url: String,
}

impl HttpStore {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
        }
    }

    fn url(&self, path: &str) -> Result<String> {
        if path.starts_with('/') || path.contains("..") {
            bail!("unsafe http object path {path}");
        }
        Ok(format!("{}/{}", self.base_url, path))
    }
}

#[async_trait]
impl ObjectStore for HttpStore {
    async fn get(&self, path: &str) -> Result<Vec<u8>> {
        let res = reqwest::get(self.url(path)?).await?;
        if !res.status().is_success() {
            bail!("http get {path} failed with {}", res.status());
        }
        Ok(res.bytes().await?.to_vec())
    }

    async fn put(&self, _path: &str, _bytes: &[u8]) -> Result<()> {
        bail!("http source is read-only")
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        let res = reqwest::Client::new().head(self.url(path)?).send().await?;
        Ok(res.status().is_success())
    }

    async fn list_prefix(&self, _prefix: &str) -> Result<Vec<ObjectMeta>> {
        bail!("http list requires an index; configure a file or s3 source for listing")
    }

    async fn delete(&self, _path: &str) -> Result<()> {
        bail!("http source is read-only")
    }
}
