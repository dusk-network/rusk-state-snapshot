use crate::{
    cli::PublishArgs,
    config::Config,
    hashing,
    manifest::{snapshot_id, SignedManifest},
    object_store,
};
use anyhow::{bail, Context, Result};
use std::{fs, path::Path};
use uuid::Uuid;

pub async fn run(args: PublishArgs) -> Result<()> {
    let cfg = Config::load(&args.config)?;
    let target = cfg.target(&args.target)?;
    let store = object_store::from_endpoint(target)?;
    let manifest_bytes = fs::read(&args.manifest)?;
    let manifest: SignedManifest = serde_json::from_slice(&manifest_bytes)?;
    manifest.validate_schema()?;
    let candidate_dir = args.manifest.parent().context("manifest has no parent")?;
    let artifact = &manifest.body.artifacts[0];
    let artifact_path = candidate_dir.join(&artifact.path);
    let local_hash = hashing::hash_file(&artifact_path)?;
    if local_hash.size != artifact.size
        || local_hash.sha256 != artifact.sha256
        || local_hash.blake3 != artifact.blake3
    {
        bail!("local artifact does not match manifest");
    }
    let id = snapshot_id(manifest.body.height, &manifest.body.state_root);
    let final_manifest = format!("v1/snapshots/full/{id}/manifest.json");
    let final_artifact = format!("v1/snapshots/full/{id}/snapshot.tar.zst");
    put_immutable_file(store.as_ref(), &final_artifact, &artifact_path, &local_hash).await?;
    put_immutable_bytes(store.as_ref(), &final_manifest, &manifest_bytes).await?;

    println!("{final_manifest}");
    Ok(())
}

async fn put_immutable_bytes(
    store: &dyn object_store::ObjectStore,
    path: &str,
    bytes: &[u8],
) -> Result<()> {
    if store.exists(path).await? {
        let existing = store.get(path).await?;
        if existing != bytes {
            bail!("immutable object exists with different content: {path}");
        }
        return Ok(());
    }
    let staging = format!(
        "v1/staging/{}/{}",
        Uuid::new_v4(),
        path.rsplit('/').next().unwrap_or("object")
    );
    store.put(&staging, bytes).await?;
    let staged = store.get(&staging).await?;
    if staged.len() != bytes.len() || staged != bytes {
        bail!("staged object verification failed for {path}");
    }
    store.put(path, bytes).await?;
    Ok(())
}

async fn put_immutable_file(
    store: &dyn object_store::ObjectStore,
    path: &str,
    source: &Path,
    expected: &hashing::Hashes,
) -> Result<()> {
    if let Some(meta) = store.stat(path).await? {
        if meta.size != expected.size {
            bail!("immutable object exists with different size: {path}");
        }
        let tmp = tempfile::NamedTempFile::new()?;
        store.get_to_file(path, tmp.path()).await?;
        let existing = hashing::hash_file(tmp.path())?;
        if existing.sha256 != expected.sha256 || existing.blake3 != expected.blake3 {
            bail!("immutable object exists with different hash: {path}");
        }
        return Ok(());
    }
    let staging = format!(
        "v1/staging/{}/{}",
        Uuid::new_v4(),
        path.rsplit('/').next().unwrap_or("object")
    );
    store.put_file(&staging, source).await?;
    let staged_meta = store
        .stat(&staging)
        .await?
        .ok_or_else(|| anyhow::anyhow!("staged object missing after upload: {staging}"))?;
    if staged_meta.size != expected.size {
        bail!("staged object size mismatch for {path}");
    }
    let tmp = tempfile::NamedTempFile::new()?;
    store.get_to_file(&staging, tmp.path()).await?;
    let staged = hashing::hash_file(tmp.path())?;
    if staged.sha256 != expected.sha256 || staged.blake3 != expected.blake3 {
        bail!("staged object hash mismatch for {path}");
    }
    store.copy(&staging, path).await?;
    let final_meta = store
        .stat(path)
        .await?
        .ok_or_else(|| anyhow::anyhow!("final object missing after copy: {path}"))?;
    if final_meta.size != expected.size {
        bail!("final object size mismatch for {path}");
    }
    Ok(())
}
