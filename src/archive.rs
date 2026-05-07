use anyhow::{bail, Context, Result};
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
};
use tar::Builder;
use walkdir::WalkDir;

pub fn create_snapshot_archive(state_dir: &Path, chain_db_dir: &Path, out: &Path) -> Result<()> {
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = File::create(out).with_context(|| format!("create {}", out.display()))?;
    let encoder = zstd::Encoder::new(file, 3)?;
    let mut tar = Builder::new(encoder);
    append_dir_stable(&mut tar, state_dir, "state")?;
    append_dir_stable(&mut tar, chain_db_dir, "chain.db")?;
    let encoder = tar.into_inner()?;
    encoder.finish()?;
    Ok(())
}

fn append_dir_stable<W: std::io::Write>(
    tar: &mut Builder<W>,
    source: &Path,
    archive_root: &str,
) -> Result<()> {
    let source = source
        .canonicalize()
        .with_context(|| format!("canonicalize {}", source.display()))?;
    let mut entries: Vec<PathBuf> = WalkDir::new(&source)
        .follow_links(false)
        .into_iter()
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .map(|e| e.path().to_path_buf())
        .collect();
    entries.sort();

    for path in entries {
        let rel = path.strip_prefix(&source)?;
        if rel.as_os_str().is_empty() {
            continue;
        }
        if is_forbidden_snapshot_path(archive_root, rel) {
            continue;
        }
        let archive_path = Path::new(archive_root).join(rel);
        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            let target = fs::read_link(&path)?;
            let resolved = if target.is_absolute() {
                target
            } else {
                path.parent().unwrap_or(&source).join(target)
            };
            let resolved = resolved.canonicalize().unwrap_or(resolved);
            if !resolved.starts_with(&source) {
                bail!("refusing symlink escaping input root: {}", path.display());
            }
            tar.append_path_with_name(&path, &archive_path)?;
        } else if meta.is_dir() {
            tar.append_dir(&archive_path, &path)?;
        } else if meta.is_file() {
            tar.append_path_with_name(&path, &archive_path)?;
        }
    }
    Ok(())
}

fn is_forbidden_snapshot_path(archive_root: &str, path: &Path) -> bool {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    let is_chain_db = archive_root == "chain.db";
    lower.contains("wallet")
        || lower.contains("consensus")
        || lower.contains("credential")
        || lower.contains("secret")
        || lower.contains("signing")
        || (!is_chain_db && lower.ends_with(".log"))
        || lower.contains("/logs/")
        || lower.starts_with("logs/")
}

pub fn read_state_id(state_dir: &Path) -> Result<String> {
    let bytes = fs::read(state_dir.join("state.id"))
        .with_context(|| format!("read {}", state_dir.join("state.id").display()))?;
    if bytes.len() != 32 {
        bail!("state.id must be exactly 32 bytes, got {}", bytes.len());
    }
    Ok(hex::encode(bytes))
}
