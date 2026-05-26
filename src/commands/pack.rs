use crate::{
    archive,
    cli::PackArgs,
    hashing,
    manifest::{
        snapshot_id, Artifact, ComponentEntry, Components, ManifestBody, Publisher, SignedManifest,
        MANIFEST_FORMAT,
    },
    signing,
};
use anyhow::{Context, Result};
use chrono::Utc;
use std::fs;

pub async fn run(args: PackArgs) -> Result<()> {
    let state_id = archive::read_state_id(&args.state_dir)?;
    let id = snapshot_id(args.height, &args.state_root.to_lowercase());
    let candidate_dir = args.out.join(&id);
    fs::create_dir_all(&candidate_dir)?;
    let artifact_name = args.compression.artifact_path();
    let archive_path = candidate_dir.join(artifact_name);
    archive::create_snapshot_archive(
        &args.state_dir,
        &args.chain_db_dir,
        &archive_path,
        args.compression,
    )?;
    let hashes = hashing::hash_file(&archive_path)?;

    let key_id = args
        .key_id
        .clone()
        .unwrap_or_else(|| "local-dev".to_string());
    let publisher = args.publisher_name.map(|name| Publisher {
        name,
        key_id: key_id.clone(),
    });
    let body = ManifestBody {
        format: MANIFEST_FORMAT.to_string(),
        network: args.network,
        role: args.role,
        kind: "full".to_string(),
        height: args.height,
        block_hash: args.block_hash.to_lowercase(),
        block_timestamp: args.block_timestamp,
        state_root: args.state_root.to_lowercase(),
        state_id,
        rusk_version: args.rusk_version,
        created_at: Utc::now(),
        artifacts: vec![Artifact {
            name: "state-chain".to_string(),
            path: artifact_name.to_string(),
            size: hashes.size,
            sha256: hashes.sha256,
            blake3: hashes.blake3,
        }],
        components: Components {
            state: ComponentEntry {
                included: true,
                path: Some("state".to_string()),
            },
            chain_db: ComponentEntry {
                included: true,
                path: Some("chain.db".to_string()),
            },
            archive: ComponentEntry {
                included: false,
                path: None,
            },
        },
        publisher,
    };
    let signature = match args.signing_key {
        Some(spec) => Some(signing::sign_body(&body, &key_id, &spec)?),
        None => None,
    };
    let manifest = SignedManifest { body, signature };
    manifest.validate_schema()?;
    fs::write(
        candidate_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )
    .with_context(|| format!("write {}", candidate_dir.join("manifest.json").display()))?;
    println!("{}", candidate_dir.display());
    Ok(())
}
