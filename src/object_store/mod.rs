pub mod file;
pub mod http;
pub mod s3;

use crate::config::Endpoint;
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Reject remote endpoints that would send requests (and, for S3, the signed
/// `Authorization` header) in cleartext. `https` is always accepted; `http` is
/// accepted only for loopback hosts so local development and tests still work.
pub(crate) fn require_secure_url(url: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(url).with_context(|| format!("parse url {url}"))?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" => {
            let host = parsed.host_str().unwrap_or("");
            let loopback = host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .map(|ip| ip.is_loopback())
                    .unwrap_or(false);
            if loopback {
                Ok(())
            } else {
                bail!(
                    "refusing insecure http endpoint {url}: use https \
                     (http is permitted only for loopback hosts)"
                )
            }
        }
        other => bail!("unsupported url scheme `{other}` in {url}"),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectMeta {
    pub path: String,
    pub size: u64,
    #[serde(default)]
    pub modified: Option<DateTime<Utc>>,
}

#[async_trait]
pub trait ObjectStore: Send + Sync {
    /// Small objects only (manifests, pointers, blob objects). Buffers the whole
    /// object in memory; use [`get_to_file`](Self::get_to_file) for artifacts.
    async fn get(&self, path: &str) -> Result<Vec<u8>>;
    /// Small objects only. Buffers `bytes` in memory; use
    /// [`put_file`](Self::put_file) for artifacts.
    async fn put(&self, path: &str, bytes: &[u8]) -> Result<()>;
    /// Stream a (potentially multi-gigabyte) object to a file. Required rather
    /// than defaulted so no backend silently buffers a whole artifact in RAM.
    async fn get_to_file(&self, path: &str, destination: &Path) -> Result<()>;
    /// Stream a (potentially multi-gigabyte) file to the object store. Required
    /// rather than defaulted so no backend silently buffers a whole artifact.
    async fn put_file(&self, path: &str, source: &Path) -> Result<()>;
    /// Small objects only (server-side copy is capped at 5 GiB on most
    /// providers). Large artifacts are uploaded directly to their final key.
    #[allow(dead_code)]
    async fn copy(&self, from: &str, to: &str) -> Result<()> {
        let bytes = self.get(from).await?;
        self.put(to, &bytes).await
    }
    async fn stat(&self, path: &str) -> Result<Option<ObjectMeta>>;
    async fn exists(&self, path: &str) -> Result<bool>;
    async fn list_prefix(&self, prefix: &str) -> Result<Vec<ObjectMeta>>;
    async fn delete(&self, path: &str) -> Result<()>;
}

pub fn from_endpoint(endpoint: &Endpoint) -> Result<Box<dyn ObjectStore>> {
    match endpoint {
        Endpoint::File { path, .. } => Ok(Box::new(file::FileStore::new(path))),
        Endpoint::Https { base_url, .. } => Ok(Box::new(http::HttpStore::new(base_url)?)),
        Endpoint::S3 { .. } => Ok(Box::new(s3::S3Store::new(endpoint.clone())?)),
    }
}
