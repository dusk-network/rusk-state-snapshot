use crate::{
    cli::RestoreArgs,
    config::Config,
    hashing,
    manifest::SignedManifest,
    object_store,
    pointer::{label_from_selector, pointer_path, SignedPointer},
    safe_extract,
};
use anyhow::{bail, Context, Result};
use chrono::Utc;
use std::{fs, path::PathBuf, process::Command};

pub async fn run(args: RestoreArgs) -> Result<()> {
    let cfg = Config::load(&args.config)?;
    let source = cfg.source(&args.source)?;
    let trust = cfg.trusted_for_endpoint(source)?;
    let store = object_store::from_endpoint(source)?;

    let manifest_path = if let Some(path) = &args.manifest_path {
        path.clone()
    } else {
        let label = label_from_selector(
            args.latest,
            &args.daily,
            &args.monthly,
            &args.yearly,
            &args.pin,
        )?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "select --latest, --daily, --monthly, --yearly, --pin, or --manifest-path"
            )
        })?;
        let ptr_path = pointer_path(&label)?;
        let ptr_bytes = store.get(&ptr_path).await?;
        let pointer: SignedPointer = serde_json::from_slice(&ptr_bytes)?;
        pointer.validate_schema()?;
        if !trust.is_empty() {
            pointer.verify_signature(&trust)?;
        }
        pointer.body.manifest_path
    };

    let manifest_bytes = store.get(&manifest_path).await?;
    let manifest_hash = hashing::sha256_bytes(&manifest_bytes);
    let manifest: SignedManifest = serde_json::from_slice(&manifest_bytes)?;
    manifest.validate_schema()?;
    if !trust.is_empty() || manifest.signature.is_some() {
        manifest.verify_signature(&trust)?;
    }

    let artifact = &manifest.body.artifacts[0];
    let artifact_remote_path = manifest_path
        .rsplit_once('/')
        .map(|(dir, _)| format!("{dir}/{}", artifact.path))
        .context("invalid manifest path")?;
    let temp_parent = args
        .destination_profile
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(&temp_parent)?;
    let temp = tempfile::tempdir_in(&temp_parent)?;
    let archive_path = temp.path().join("snapshot.tar.zst");
    let artifact_bytes = store.get(&artifact_remote_path).await?;
    fs::write(&archive_path, &artifact_bytes)?;
    let hashes = hashing::hash_file(&archive_path)?;
    if hashes.size != artifact.size
        || hashes.sha256 != artifact.sha256
        || hashes.blake3 != artifact.blake3
    {
        bail!("artifact hash/size mismatch");
    }
    let extract_dir = temp.path().join("extract");
    safe_extract::extract_zstd_tar_safe(&archive_path, &extract_dir)?;
    let state_id = fs::read(extract_dir.join("state/state.id"))?;
    if hex::encode(state_id) != manifest.body.state_id {
        bail!("extracted state.id does not match manifest");
    }

    if let Some(service) = &args.manage_service {
        service_cmd("stop", service)?;
    }
    replace_profile(&args.destination_profile, &extract_dir)?;
    if let Some(owner) = &args.owner {
        chown_recursive(&args.destination_profile, owner)?;
    }
    if let Some(service) = &args.manage_service {
        service_cmd("start", service)?;
    }
    println!("restored {} ({manifest_hash})", manifest.body.state_id);
    Ok(())
}

fn replace_profile(destination: &PathBuf, extracted: &std::path::Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    let backup = destination
        .join("backups")
        .join(format!("restore-{}", Utc::now().format("%Y%m%dT%H%M%SZ")));
    fs::create_dir_all(&backup)?;
    for name in ["state", "chain.db"] {
        let live = destination.join(name);
        if live.exists() {
            fs::rename(&live, backup.join(name))?;
        }
        fs::rename(extracted.join(name), &live)?;
    }
    Ok(())
}

fn service_cmd(action: &str, service: &str) -> Result<()> {
    let status = Command::new("systemctl")
        .arg(action)
        .arg(service)
        .status()?;
    if !status.success() {
        bail!("systemctl {action} {service} failed");
    }
    Ok(())
}

fn chown_recursive(path: &PathBuf, owner: &str) -> Result<()> {
    let status = Command::new("chown")
        .arg("-R")
        .arg(owner)
        .arg(path)
        .status()?;
    if !status.success() {
        bail!("chown -R {owner} {} failed", path.display());
    }
    Ok(())
}
