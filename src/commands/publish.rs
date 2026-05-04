use crate::{
    cli::PublishArgs,
    config::Config,
    hashing,
    manifest::{snapshot_id, SignedManifest},
    object_store,
};
use anyhow::{bail, Context, Result};
use std::fs;
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
    let artifact_bytes = fs::read(&artifact_path)?;
    let local_hash = hashing::hash_file(&artifact_path)?;
    if local_hash.size != artifact.size || local_hash.sha256 != artifact.sha256 {
        bail!("local artifact does not match manifest");
    }
    let id = snapshot_id(manifest.body.height, &manifest.body.state_root);
    let final_manifest = format!("v1/snapshots/full/{id}/manifest.json");
    let final_artifact = format!("v1/snapshots/full/{id}/snapshot.tar.zst");
    put_immutable(store.as_ref(), &final_manifest, &manifest_bytes).await?;
    put_immutable(store.as_ref(), &final_artifact, &artifact_bytes).await?;

    println!("{final_manifest}");
    Ok(())
}

async fn put_immutable(
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
