use super::{ObjectMeta, ObjectStore};
use crate::config::Endpoint;
use anyhow::{bail, Result};
use async_trait::async_trait;

pub struct S3Store {
    _endpoint: Endpoint,
}

impl S3Store {
    pub fn new(endpoint: Endpoint) -> Self {
        Self {
            _endpoint: endpoint,
        }
    }
}

#[async_trait]
impl ObjectStore for S3Store {
    async fn get(&self, _path: &str) -> Result<Vec<u8>> {
        bail!("s3 backend is factored but not enabled in this build; use local file backend for tests/dev")
    }

    async fn put(&self, _path: &str, _bytes: &[u8]) -> Result<()> {
        bail!("s3 backend is factored but not enabled in this build; use local file backend for tests/dev")
    }

    async fn exists(&self, _path: &str) -> Result<bool> {
        bail!("s3 backend is factored but not enabled in this build; use local file backend for tests/dev")
    }

    async fn list_prefix(&self, _prefix: &str) -> Result<Vec<ObjectMeta>> {
        bail!("s3 backend is factored but not enabled in this build; use local file backend for tests/dev")
    }

    async fn delete(&self, _path: &str) -> Result<()> {
        bail!("s3 backend is factored but not enabled in this build; use local file backend for tests/dev")
    }
}
