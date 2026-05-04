use super::{ObjectMeta, ObjectStore};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::{
    fs,
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
        fs::read(&full).with_context(|| format!("read object {}", full.display()))
    }

    async fn put(&self, path: &str, bytes: &[u8]) -> Result<()> {
        let full = self.resolve(path)?;
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&full, bytes).with_context(|| format!("write object {}", full.display()))
    }

    async fn exists(&self, path: &str) -> Result<bool> {
        Ok(self.resolve(path)?.exists())
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<ObjectMeta>> {
        let start = self.resolve(prefix)?;
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
            let rel = entry.path().strip_prefix(&self.root)?.to_string_lossy();
            out.push(ObjectMeta {
                path: rel.replace('\\', "/"),
                size: meta.len(),
                modified: meta.modified().ok().map(DateTime::<Utc>::from),
            });
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let full = self.resolve(path)?;
        if full.exists() {
            fs::remove_file(full)?;
        }
        Ok(())
    }
}
