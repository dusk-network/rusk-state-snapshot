pub mod file;
pub mod http;
pub mod s3;

use crate::config::Endpoint;
use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct ObjectMeta {
    pub path: String,
    pub size: u64,
    pub modified: Option<DateTime<Utc>>,
}

#[async_trait]
pub trait ObjectStore: Send + Sync {
    async fn get(&self, path: &str) -> Result<Vec<u8>>;
    async fn put(&self, path: &str, bytes: &[u8]) -> Result<()>;
    async fn exists(&self, path: &str) -> Result<bool>;
    async fn list_prefix(&self, prefix: &str) -> Result<Vec<ObjectMeta>>;
    async fn delete(&self, path: &str) -> Result<()>;
}

pub fn from_endpoint(endpoint: &Endpoint) -> Result<Box<dyn ObjectStore>> {
    match endpoint {
        Endpoint::File { path, .. } => Ok(Box::new(file::FileStore::new(path))),
        Endpoint::Https { base_url, .. } => Ok(Box::new(http::HttpStore::new(base_url))),
        Endpoint::S3 { .. } => Ok(Box::new(s3::S3Store::new(endpoint.clone()))),
    }
}
