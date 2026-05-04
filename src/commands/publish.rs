use crate::{
    cli::PublishArgs,
    config::Config,
    hashing,
    manifest::{snapshot_id, SignedManifest},
    object_store,
};
use anyhow::{bail, Context, Result};
use std::{fs, path::Path};

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

    // Upload the artifact directly to its final key so we never depend on
    // server-side single-PUT copies (limited to 5 GiB on S3-compatible
    // backends). The manifest is written LAST so that a partial publish never
    // leaves a manifest pointing at a missing or shorter artifact.
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
    store.put(path, bytes).await?;
    let written = store.get(path).await?;
    if written != bytes {
        bail!("post-write read-back mismatch for {path}");
    }
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
    // Direct upload to the final key, then re-stat and re-hash by streaming
    // the object back into a temp file. This avoids server-side multipart copy
    // and keeps memory bounded for large archives.
    store.put_file(path, source).await?;
    let final_meta = store
        .stat(path)
        .await?
        .ok_or_else(|| anyhow::anyhow!("final object missing after upload: {path}"))?;
    if final_meta.size != expected.size {
        bail!(
            "final object size mismatch for {path}: expected {}, got {}",
            expected.size,
            final_meta.size
        );
    }
    let tmp = tempfile::NamedTempFile::new()?;
    store.get_to_file(path, tmp.path()).await?;
    let written = hashing::hash_file(tmp.path())?;
    if written.sha256 != expected.sha256 || written.blake3 != expected.blake3 {
        bail!("post-upload hash mismatch for {path}");
    }
    Ok(())
}
