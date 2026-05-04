use crate::{
    cli::PromoteArgs,
    config::Config,
    hashing,
    manifest::{snapshot_id, SignedManifest},
    object_store::{self, ObjectStore},
    pointer::{pointer_path, PointerBody, SignedPointer, POINTER_FORMAT},
    signing,
};
use anyhow::{bail, Result};
use chrono::Utc;

pub async fn run(args: PromoteArgs) -> Result<()> {
    let cfg = Config::load(&args.config)?;
    let target = cfg.target(&args.target)?;
    let key_spec = target.signing_key()?;
    let key_id = target.signing_key_id()?;
    let trusted_manifest_keys = cfg.trusted_for_endpoint(target)?;
    let store = object_store::from_endpoint(target)?;

    let manifest_bytes = store.get(&args.manifest_path).await?;
    let manifest: SignedManifest = serde_json::from_slice(&manifest_bytes)?;
    manifest.validate_schema()?;

    // Optional but strongly recommended for production: refuse to promote a
    // manifest unless it is signed by a trusted publisher key.
    if args.require_signed_manifest {
        if trusted_manifest_keys.is_empty() {
            bail!(
                "--require-signed-manifest set but target has no trusted_keys configured"
            );
        }
        manifest.verify_signature(&trusted_manifest_keys)?;
    } else if manifest.signature.is_some() && !trusted_manifest_keys.is_empty() {
        // If the manifest is signed and we have trust keys, still verify it.
        manifest.verify_signature(&trusted_manifest_keys)?;
    }

    // Verify referenced artifact exists at the expected size before publishing
    // any pointer that would direct restorers at it.
    let manifest_dir = args
        .manifest_path
        .rsplit_once('/')
        .map(|(d, _)| d)
        .ok_or_else(|| anyhow::anyhow!("manifest path has no parent"))?;
    for artifact in &manifest.body.artifacts {
        let artifact_path = format!("{manifest_dir}/{}", artifact.path);
        let meta = store
            .stat(&artifact_path)
            .await?
            .ok_or_else(|| anyhow::anyhow!("artifact missing on target: {artifact_path}"))?;
        if meta.size != artifact.size {
            bail!(
                "artifact size mismatch for {artifact_path}: manifest says {}, store reports {}",
                artifact.size,
                meta.size
            );
        }
    }

    let manifest_sha256 = hashing::sha256_bytes(&manifest_bytes);
    let id = snapshot_id(manifest.body.height, &manifest.body.state_root);

    // Generate a fresh signed previous pointer rather than byte-copying the
    // current latest. Byte-copying would publish a "previous" object whose
    // body is still labelled "latest" and signed for that label. We rewrite
    // the body, update its label and timestamp, and re-sign with the
    // operator's current target key.
    if args.label == "latest" && args.update_previous {
        if let Some(prev) = read_existing_pointer(store.as_ref(), "v1/pointers/latest.json").await?
        {
            let previous_body = PointerBody {
                label: "previous".to_string(),
                updated_at: Utc::now(),
                ..prev.body
            };
            let previous_signature = signing::sign_body(&previous_body, key_id, key_spec)?;
            let previous_pointer = SignedPointer {
                body: previous_body,
                signature: previous_signature,
            };
            previous_pointer.validate_schema()?;
            store
                .put(
                    "v1/pointers/previous.json",
                    &serde_json::to_vec_pretty(&previous_pointer)?,
                )
                .await?;
        }
    }

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
    let signature = signing::sign_body(&body, key_id, key_spec)?;
    let pointer = SignedPointer { body, signature };
    pointer.validate_schema()?;

    let path = pointer_path(&args.label)?;
    store
        .put(&path, &serde_json::to_vec_pretty(&pointer)?)
        .await?;
    println!("{path}");
    Ok(())
}

async fn read_existing_pointer(
    store: &dyn ObjectStore,
    path: &str,
) -> Result<Option<SignedPointer>> {
    if !store.exists(path).await? {
        return Ok(None);
    }
    let bytes = store.get(path).await?;
    let pointer: SignedPointer = serde_json::from_slice(&bytes)?;
    Ok(Some(pointer))
}
