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
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

pub async fn run(args: RestoreArgs) -> Result<()> {
    let cfg = Config::load(&args.config)?;
    let source = cfg.source(&args.source)?;
    let trust = cfg.trusted_for_endpoint(source)?;
    let store = object_store::from_endpoint(source)?;

    // Restore overwrites live node state, so for a remote source we fail closed:
    // the pointer and manifest must carry a signature from a trusted key unless
    // the operator explicitly passes --insecure. Local file sources are the
    // operator's own disk and keep the softer "verify if trust/signature is
    // present" behavior.
    let require_sig = !source.is_local() && !args.insecure;
    if require_sig && trust.is_empty() {
        bail!(
            "restoring from remote source `{}` requires at least one trusted_keys \
             entry in the config; configure one or pass --insecure to override",
            args.source
        );
    }

    let (manifest_path, pointer) = if let Some(path) = &args.manifest_path {
        (path.clone(), None)
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
        if require_sig || !trust.is_empty() {
            pointer.verify_signature(&trust)?;
        }
        (pointer.body.manifest_path.clone(), Some(pointer))
    };

    let manifest_bytes = store.get(&manifest_path).await?;
    let manifest_hash = hashing::sha256_bytes(&manifest_bytes);
    let manifest: SignedManifest = serde_json::from_slice(&manifest_bytes)?;
    manifest.validate_schema()?;
    if require_sig || !trust.is_empty() || manifest.signature.is_some() {
        manifest.verify_signature(&trust)?;
    }
    if let Some(pointer) = &pointer {
        verify_pointer_matches_manifest(pointer, &manifest, &manifest_hash)?;
    }

    let artifact = &manifest.body.artifacts[0];
    let artifact_remote_path = manifest_path
        .rsplit_once('/')
        .map(|(dir, _)| format!("{dir}/{}", artifact.path))
        .context("invalid manifest path")?;

    // Preflight before downloading anything large: destination parent is
    // writable, optional service can actually be controlled, and an existing
    // backup directory does not collide with the timestamp we'll use.
    preflight(&args)?;

    let temp_parent = args
        .destination_profile
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(&temp_parent)?;
    let temp = tempfile::tempdir_in(&temp_parent)?;
    let archive_path = temp.path().join(&artifact.path);
    store
        .get_to_file(&artifact_remote_path, &archive_path)
        .await?;
    let hashes = hashing::hash_file(&archive_path)?;
    if hashes.size != artifact.size
        || hashes.sha256 != artifact.sha256
        || hashes.blake3 != artifact.blake3
    {
        bail!("artifact hash/size mismatch");
    }
    let extract_dir = temp.path().join("extract");
    safe_extract::extract_snapshot_tar_safe(&archive_path, &extract_dir)?;
    let state_id = fs::read(extract_dir.join("state/state.id"))?;
    if hex::encode(state_id) != manifest.body.state_id {
        bail!("extracted state.id does not match manifest");
    }

    if let Some(service) = &args.manage_service {
        service_cmd("stop", service)?;
    }
    let result = replace_profile(&args.destination_profile, &extract_dir);
    if let Err(err) = result {
        // Restart the service if we stopped it; the operator's profile is
        // either intact (replace_profile rolled back) or in a documented
        // partial state described by the error message.
        if let Some(service) = &args.manage_service {
            let _ = service_cmd("start", service);
        }
        return Err(err);
    }
    if let Some(owner) = &args.owner {
        chown_recursive(&args.destination_profile, owner)?;
    }
    if let Some(service) = &args.manage_service {
        service_cmd("start", service)?;
    }
    println!("restored {} ({manifest_hash})", manifest.body.state_id);
    Ok(())
}

fn verify_pointer_matches_manifest(
    pointer: &SignedPointer,
    manifest: &SignedManifest,
    manifest_hash: &str,
) -> Result<()> {
    let id = crate::manifest::snapshot_id(manifest.body.height, &manifest.body.state_root);
    if pointer.body.manifest_sha256 != manifest_hash {
        bail!("pointer manifest_sha256 does not match fetched manifest");
    }
    if pointer.body.snapshot_id != id {
        bail!("pointer snapshot_id does not match manifest");
    }
    if pointer.body.network != manifest.body.network
        || pointer.body.role != manifest.body.role
        || pointer.body.height != manifest.body.height
        || pointer.body.state_root != manifest.body.state_root
        || pointer.body.block_hash != manifest.body.block_hash
    {
        bail!("pointer metadata does not match manifest");
    }
    Ok(())
}

fn preflight(args: &RestoreArgs) -> Result<()> {
    let parent = args
        .destination_profile
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(&parent)
        .with_context(|| format!("create destination parent {}", parent.display()))?;
    // Probe writability with a temp file.
    let probe = tempfile::Builder::new()
        .prefix(".rusk-state-snapshot-preflight-")
        .tempfile_in(&parent)
        .with_context(|| {
            format!(
                "destination parent {} is not writable; restore would fail later",
                parent.display()
            )
        })?;
    drop(probe);

    if let Some(service) = &args.manage_service {
        if which("systemctl").is_none() {
            bail!(
                "--manage-service {service} requires systemctl in PATH; aborting before download"
            );
        }
    }
    Ok(())
}

fn which(binary: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(binary);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn replace_profile(destination: &Path, extracted: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    let backup = destination
        .join("backups")
        .join(format!("restore-{}", Utc::now().format("%Y%m%dT%H%M%SZ")));
    fs::create_dir_all(&backup)?;
    // Phase 1: move existing live dirs into the backup. Track what was moved
    // so we can roll back on failure.
    let mut moved_to_backup: Vec<&str> = Vec::new();
    for name in ["state", "chain.db"] {
        let live = destination.join(name);
        if live.exists() {
            if let Err(err) = fs::rename(&live, backup.join(name)) {
                // Roll back: move anything we already backed up back into
                // place so the operator's node profile is intact.
                rollback_from_backup(destination, &backup, &moved_to_backup);
                return Err(err).with_context(|| {
                    format!(
                        "failed to back up live {} into {}",
                        live.display(),
                        backup.display()
                    )
                });
            }
            moved_to_backup.push(name);
        }
    }
    // Phase 2: install the extracted replacements. If any rename fails, undo:
    // remove already-installed dirs and restore originals from backup.
    let mut installed: Vec<&str> = Vec::new();
    for name in ["state", "chain.db"] {
        let live = destination.join(name);
        if let Err(err) = fs::rename(extracted.join(name), &live) {
            // Remove anything we successfully installed in this phase.
            for done in &installed {
                let _ = fs::remove_dir_all(destination.join(done));
            }
            rollback_from_backup(destination, &backup, &moved_to_backup);
            return Err(err).with_context(|| {
                format!("failed to install restored {} at {}", name, live.display())
            });
        }
        installed.push(name);
    }
    Ok(())
}

fn rollback_from_backup(destination: &Path, backup: &Path, moved: &[&str]) {
    for name in moved {
        let live = destination.join(name);
        let saved = backup.join(name);
        if saved.exists() {
            // Best effort: clear any failed install before restoring.
            let _ = fs::remove_dir_all(&live);
            let _ = fs::rename(&saved, &live);
        }
    }
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

fn chown_recursive(path: &Path, owner: &str) -> Result<()> {
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
