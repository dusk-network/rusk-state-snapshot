use crate::archive::SnapshotCompression;
use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;
use std::{
    fs::{self, File},
    io::Read,
    path::{Component, Path, PathBuf},
};
use tar::{Archive, EntryType};

pub fn extract_snapshot_tar_safe(archive_path: &Path, destination: &Path) -> Result<()> {
    let compression = SnapshotCompression::from_path(archive_path)?;
    extract_tar_safe(archive_path, destination, compression)
}

pub fn extract_tar_safe(
    archive_path: &Path,
    destination: &Path,
    compression: SnapshotCompression,
) -> Result<()> {
    fs::create_dir_all(destination)?;
    let file =
        File::open(archive_path).with_context(|| format!("open {}", archive_path.display()))?;
    let reader: Box<dyn Read> = match compression {
        SnapshotCompression::Gzip => Box::new(GzDecoder::new(file)),
        SnapshotCompression::Zstd => Box::new(zstd::Decoder::new(file)?),
    };
    let mut archive = Archive::new(reader);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        validate_archive_path(&path)?;
        let out = destination.join(&path);
        ensure_inside(destination, &out)?;

        match entry.header().entry_type() {
            EntryType::Regular => {
                if let Some(parent) = out.parent() {
                    fs::create_dir_all(parent)?;
                }
                entry.unpack(&out)?;
            }
            EntryType::Directory => {
                fs::create_dir_all(&out)?;
            }
            EntryType::Symlink => {
                let link = entry
                    .link_name()?
                    .ok_or_else(|| anyhow::anyhow!("symlink without target"))?;
                let target = if link.is_absolute() {
                    link.into_owned()
                } else {
                    out.parent().unwrap_or(destination).join(link.as_ref())
                };
                ensure_inside(destination, &normalize_no_require_exists(&target))?;
                entry.unpack(&out)?;
            }
            other => bail!("unsupported archive entry type {:?}", other),
        }
    }
    Ok(())
}

pub fn validate_archive_safe(archive_path: &Path) -> Result<()> {
    let tmp = tempfile::tempdir()?;
    extract_snapshot_tar_safe(archive_path, tmp.path())
}

pub fn validate_archive_path(path: &Path) -> Result<()> {
    if path.is_absolute() {
        bail!("archive path is absolute: {}", path.display());
    }
    for component in path.components() {
        match component {
            Component::Normal(_) => {}
            _ => bail!("unsafe archive path: {}", path.display()),
        }
    }
    Ok(())
}

fn ensure_inside(root: &Path, path: &Path) -> Result<()> {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let parent = path.parent().unwrap_or(path);
    let base = parent
        .canonicalize()
        .unwrap_or_else(|_| normalize_no_require_exists(parent));
    if !base.starts_with(&root) && !path.starts_with(&root) {
        bail!("archive entry escapes extraction root: {}", path.display());
    }
    Ok(())
}

fn normalize_no_require_exists(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}
