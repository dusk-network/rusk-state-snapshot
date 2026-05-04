use super::{ObjectMeta, ObjectStore};
use anyhow::{bail, Result};
use async_trait::async_trait;
use futures_util::StreamExt;
use serde::Deserialize;
use std::path::Path;
use tokio::io::AsyncWriteExt;

pub struct HttpStore {
    base_url: String,
}

#[derive(Debug, Deserialize)]
struct HttpIndex {
    format: String,
    objects: Vec<ObjectMeta>,
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
        let path = if self.base_url.ends_with("/v1") {
            path.strip_prefix("v1/").unwrap_or(path)
        } else {
            path
        };
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

    async fn get_to_file(&self, path: &str, destination: &Path) -> Result<()> {
        if let Some(parent) = destination.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let res = reqwest::get(self.url(path)?).await?;
        if !res.status().is_success() {
            bail!("http get {path} failed with {}", res.status());
        }
        let mut file = tokio::fs::File::create(destination).await?;
        let mut stream = res.bytes_stream();
        while let Some(chunk) = stream.next().await {
            file.write_all(&chunk?).await?;
        }
        Ok(())
    }

    async fn put(&self, _path: &str, _bytes: &[u8]) -> Result<()> {
        bail!("http source is read-only")
    }

    async fn stat(&self, path: &str) -> Result<Option<ObjectMeta>> {
        let res = reqwest::Client::new().head(self.url(path)?).send().await?;
        if res.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !res.status().is_success() {
            bail!("http head {path} failed with {}", res.status());
        }
        let size = res
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        Ok(Some(ObjectMeta {
            path: path.to_string(),
            size,
            modified: None,
        }))
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        Ok(self.stat(path).await?.is_some())
    }

    async fn list_prefix(&self, _prefix: &str) -> Result<Vec<ObjectMeta>> {
        let index = self.get("index.json").await?;
        list_from_index_bytes(_prefix, &index)
    }

    async fn delete(&self, _path: &str) -> Result<()> {
        bail!("http source is read-only")
    }
}

pub(crate) fn list_from_index_bytes(prefix: &str, bytes: &[u8]) -> Result<Vec<ObjectMeta>> {
    let index: HttpIndex = serde_json::from_slice(bytes)?;
    if index.format != "rusk-state-snapshot-index/v1" {
        bail!("unsupported http index format {}", index.format);
    }
    let prefix = prefix.trim_end_matches('/');
    let mut objects: Vec<_> = index
        .objects
        .into_iter()
        .filter(|meta| meta.path == prefix || meta.path.starts_with(&format!("{prefix}/")))
        .collect();
    objects.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(objects)
}
