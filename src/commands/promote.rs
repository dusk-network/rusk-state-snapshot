use crate::{
    cli::PromoteArgs,
    config::Config,
    hashing,
    manifest::{snapshot_id, SignedManifest},
    object_store,
    pointer::{pointer_path, PointerBody, SignedPointer, POINTER_FORMAT},
    signing,
};
use anyhow::Result;
use chrono::Utc;

pub async fn run(args: PromoteArgs) -> Result<()> {
    let cfg = Config::load(&args.config)?;
    let target = cfg.target(&args.target)?;
    let key_spec = target.signing_key()?;
    let store = object_store::from_endpoint(target)?;
    let manifest_bytes = store.get(&args.manifest_path).await?;
    let manifest: SignedManifest = serde_json::from_slice(&manifest_bytes)?;
    manifest.validate_schema()?;
    let manifest_sha256 = hashing::sha256_bytes(&manifest_bytes);
    let id = snapshot_id(manifest.body.height, &manifest.body.state_root);
    let key_id = manifest
        .signature
        .as_ref()
        .map(|s| s.key_id.clone())
        .unwrap_or_else(|| "local-dev".to_string());
    let body = PointerBody {
        format: POINTER_FORMAT.to_string(),
        network: manifest.body.network,
        role: manifest.body.role,
        label: args.label.clone(),
        snapshot_id: id,
        manifest_path: args.manifest_path.clone(),
        manifest_sha256,
        height: manifest.body.height,
        state_root: manifest.body.state_root,
        block_hash: manifest.body.block_hash,
        updated_at: Utc::now(),
    };
    let signature = signing::sign_body(&body, &key_id, key_spec)?;
    let pointer = SignedPointer { body, signature };
    pointer.validate_schema()?;

    if args.label == "latest"
        && args.update_previous
        && store.exists("v1/pointers/latest.json").await?
    {
        let prev = store.get("v1/pointers/latest.json").await?;
        store.put("v1/pointers/previous.json", &prev).await?;
    }
    let path = pointer_path(&args.label)?;
    store
        .put(&path, &serde_json::to_vec_pretty(&pointer)?)
        .await?;
    println!("{path}");
    Ok(())
}
