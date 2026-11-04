use super::{ObjectMeta, ObjectStore};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::{
    io::ErrorKind,
    path::Path as StdPath,
    path::{Component, Path, PathBuf},
};
use walkdir::WalkDir;

pub struct FileStore {
    root: PathBuf,
}

impl FileStore {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            root: path.as_ref().to_path_buf(),
        }
    }

    fn resolve(&self, path: &str) -> Result<PathBuf> {
        let rel = Path::new(path);
        if rel.is_absolute()
            || rel
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
        {
            bail!("unsafe object path {path}");
        }
        Ok(self.root.join(rel))
    }
}

#[async_trait]
impl ObjectStore for FileStore {
    async fn get(&self, path: &str) -> Result<Vec<u8>> {
        let full = self.resolve(path)?;
        tokio::fs::read(&full)
            .await
            .with_context(|| format!("read object {}", full.display()))
    }

    async fn put(&self, path: &str, bytes: &[u8]) -> Result<()> {
        let full = self.resolve(path)?;
        if let Some(parent) = full.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(&full, bytes)
            .await
            .with_context(|| format!("write object {}", full.display()))
    }

    async fn get_to_file(&self, path: &str, destination: &StdPath) -> Result<()> {
        if let Some(parent) = destination.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::copy(self.resolve(path)?, destination).await?;
        Ok(())
    }

    async fn put_file(&self, path: &str, source: &StdPath) -> Result<()> {
        let full = self.resolve(path)?;
        if let Some(parent) = full.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::copy(source, full).await?;
        Ok(())
    }

    async fn copy(&self, from: &str, to: &str) -> Result<()> {
        let from = self.resolve(from)?;
        let to = self.resolve(to)?;
        if let Some(parent) = to.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::copy(from, to).await?;
        Ok(())
    }

    async fn stat(&self, path: &str) -> Result<Option<ObjectMeta>> {
        let full = self.resolve(path)?;
        let meta = match tokio::fs::metadata(&full).await {
            Ok(meta) => meta,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        Ok(Some(ObjectMeta {
            path: path.to_string(),
            size: meta.len(),
            modified: meta.modified().ok().map(DateTime::<Utc>::from),
        }))
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        Ok(self.stat(path).await?.is_some())
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<ObjectMeta>> {
        let start = self.resolve(prefix)?;
        let root = self.root.clone();
        // walkdir is synchronous; run it off the async runtime.
        tokio::task::spawn_blocking(move || -> Result<Vec<ObjectMeta>> {
            if !start.exists() {
                return Ok(Vec::new());
            }
            let mut out = Vec::new();
            for entry in WalkDir::new(&start).follow_links(false) {
                let entry = entry?;
                if !entry.file_type().is_file() {
                    continue;
                }
                let meta = entry.metadata()?;
                let rel = entry.path().strip_prefix(&root)?.to_string_lossy();
                out.push(ObjectMeta {
                    path: rel.replace('\\', "/"),
                    size: meta.len(),
                    modified: meta.modified().ok().map(DateTime::<Utc>::from),
                });
            }
            out.sort_by(|a, b| a.path.cmp(&b.path));
            Ok(out)
        })
        .await?
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let full = self.resolve(path)?;
        match tokio::fs::remove_file(&full).await {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err.into()),
        }
    }
}
