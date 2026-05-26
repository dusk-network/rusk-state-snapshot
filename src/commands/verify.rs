use crate::{cli::VerifyArgs, config::Config, hashing, manifest::SignedManifest, safe_extract};
use anyhow::{bail, Context, Result};
use futures_util::StreamExt;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};
use tokio::io::AsyncWriteExt;

pub async fn run(args: VerifyArgs) -> Result<()> {
    if args.manifest.starts_with("http://") || args.manifest.starts_with("https://") {
        verify_remote(args).await?;
        return Ok(());
    }
    let manifest_path = PathBuf::from(&args.manifest);
    let bytes =
        fs::read(&manifest_path).with_context(|| format!("read {}", manifest_path.display()))?;
    let manifest: SignedManifest = serde_json::from_slice(&bytes)?;
    verify_manifest_local(&manifest, &manifest_path, args).await?;
    println!("verified {}", manifest_path.display());
    Ok(())
}

async fn verify_remote(args: VerifyArgs) -> Result<()> {
    let manifest_url = args.manifest.clone();
    let manifest_res = reqwest::get(&manifest_url).await?;
    if !manifest_res.status().is_success() {
        bail!("fetch {manifest_url} failed with {}", manifest_res.status());
    }
    let bytes = manifest_res.bytes().await?.to_vec();
    let manifest: SignedManifest = serde_json::from_slice(&bytes)?;
    let artifact = manifest
        .body
        .artifacts
        .first()
        .ok_or_else(|| anyhow::anyhow!("manifest has no artifacts"))?;
    let base = manifest_url
        .rsplit_once('/')
        .map(|(base, _)| base)
        .ok_or_else(|| anyhow::anyhow!("invalid manifest URL"))?;
    let artifact_url = format!("{base}/{}", artifact.path);
    let tmp = tempfile::tempdir()?;
    let manifest_path = tmp.path().join("manifest.json");
    fs::write(&manifest_path, &bytes)?;

    // Stream the artifact to a temp file rather than buffering the entire
    // archive in memory. Production artifacts can be many gigabytes.
    let artifact_path = tmp.path().join(&artifact.path);
    let res = reqwest::get(&artifact_url).await?;
    if !res.status().is_success() {
        bail!("fetch {artifact_url} failed with {}", res.status());
    }
    {
        let mut file = tokio::fs::File::create(&artifact_path).await?;
        let mut stream = res.bytes_stream();
        while let Some(chunk) = stream.next().await {
            file.write_all(&chunk?).await?;
        }
        file.flush().await?;
    }

    verify_manifest_local(&manifest, &manifest_path, args).await?;
    println!("verified {manifest_url}");
    Ok(())
}

pub async fn verify_manifest_local(
    manifest: &SignedManifest,
    manifest_path: &Path,
    args: VerifyArgs,
) -> Result<()> {
    manifest.validate_schema()?;
    if let Some(expected) = &args.network {
        if &manifest.body.network != expected {
            bail!(
                "manifest network mismatch: expected {expected}, got {}",
                manifest.body.network
            );
        }
    }
    if let Some(expected) = &args.role {
        if &manifest.body.role != expected {
            bail!(
                "manifest role mismatch: expected {expected}, got {}",
                manifest.body.role
            );
        }
    }

    let mut trust = HashMap::new();
    if let Some(config_path) = &args.config {
        trust.extend(Config::load(config_path)?.trust);
    }
    for key in &args.trusted_key {
        let (id, public_key) = key
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("--trusted-key must be key_id=hex_public_key"))?;
        trust.insert(
            id.to_string(),
            crate::signing::TrustKey {
                scheme: "ed25519".to_string(),
                public_key: public_key.to_string(),
            },
        );
    }
    if args.require_signature || manifest.signature.is_some() {
        manifest.verify_signature(&trust)?;
    }

    let candidate_dir = manifest_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("manifest has no parent directory"))?;
    let artifact = &manifest.body.artifacts[0];
    let archive_path = candidate_dir.join(&artifact.path);
    let hashes = hashing::hash_file(&archive_path)?;
    if hashes.size != artifact.size
        || hashes.sha256 != artifact.sha256
        || hashes.blake3 != artifact.blake3
    {
        bail!("artifact hash/size mismatch");
    }
    safe_extract::validate_archive_safe(&archive_path)?;
    let tmp = tempfile::tempdir()?;
    safe_extract::extract_snapshot_tar_safe(&archive_path, tmp.path())?;
    let state_id = fs::read(tmp.path().join("state/state.id"))?;
    if hex::encode(state_id) != manifest.body.state_id {
        bail!("archive state/state.id does not match manifest state_id");
    }
    Ok(())
}
