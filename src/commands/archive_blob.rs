use crate::{
    archive_blob,
    archive_blob::{ArchivePackOptions, PackBlobRangeOptions},
    cli::{
        ArchivePackArgs, ArchiveRestoreCompleteArgs, BlobsPackRangeArgs, BlobsPublishRangeArgs,
        BlobsVerifyCoverageArgs, BlobsWriteCoverageArgs, VerifyArchiveCompleteArgs,
    },
    config::Config,
    object_store,
};
use anyhow::Result;

pub async fn blobs_pack_range(args: BlobsPackRangeArgs) -> Result<()> {
    let path = archive_blob::pack_blob_range(PackBlobRangeOptions {
        network: args.network,
        from_height: args.from_height,
        to_height: args.to_height,
        chain_db_dir: args.chain_db_dir,
        out: args.out,
        previous_range_sha256: args.previous_range_sha256,
        signing_key: args.signing_key,
        key_id: args.key_id,
    })?;
    println!("{}", path.display());
    Ok(())
}

pub async fn blobs_publish_range(args: BlobsPublishRangeArgs) -> Result<()> {
    let cfg = Config::load(&args.config)?;
    let target = cfg.target(&args.target)?;
    let store = object_store::from_endpoint(target)?;
    let remote = archive_blob::publish_blob_range(store.as_ref(), &args.manifest).await?;
    println!("{remote}");
    Ok(())
}

pub async fn blobs_write_coverage(args: BlobsWriteCoverageArgs) -> Result<()> {
    let path = archive_blob::write_blob_coverage(
        &args.out,
        &args.network,
        &args.ranges,
        args.signing_key.as_deref(),
        args.key_id.as_deref(),
    )?;
    println!("{}", path.display());
    Ok(())
}

pub async fn blobs_verify_coverage(args: BlobsVerifyCoverageArgs) -> Result<()> {
    let cfg = Config::load(&args.config)?;
    let source = cfg.source(&args.source)?;
    let trust = cfg.trusted_for_endpoint(source)?;
    let store = object_store::from_endpoint(source)?;
    let objects = archive_blob::verify_blob_coverage(
        store.as_ref(),
        &args.coverage_manifest,
        args.from_height,
        args.to_height,
        &trust,
    )
    .await?;
    println!("verified blob coverage with {objects} unique blob objects");
    Ok(())
}

pub async fn archive_pack(args: ArchivePackArgs) -> Result<()> {
    let path = archive_blob::pack_archive(ArchivePackOptions {
        network: args.network,
        archive_dir: args.archive_dir,
        height: args.height,
        block_hash: args.block_hash,
        state_root: args.state_root,
        block_timestamp: args.block_timestamp,
        state_manifest_path: args.state_manifest_path,
        state_manifest_sha256: args.state_manifest_sha256,
        blob_coverage_path: args.blob_coverage_path,
        blob_coverage_sha256: args.blob_coverage_sha256,
        blob_coverage_from_height: args.blob_coverage_from_height,
        blob_coverage_to_height: args.blob_coverage_to_height,
        blob_coverage_to_block_hash: args.blob_coverage_to_block_hash,
        out: args.out,
        signing_key: args.signing_key,
        key_id: args.key_id,
    })?;
    println!("{}", path.display());
    Ok(())
}

pub async fn verify_archive_complete(args: VerifyArchiveCompleteArgs) -> Result<()> {
    let cfg = Config::load(&args.config)?;
    let source = cfg.source(&args.source)?;
    let trust = cfg.trusted_for_endpoint(source)?;
    let store = object_store::from_endpoint(source)?;
    let proof = archive_blob::verify_archive_complete(
        store.as_ref(),
        &args.archive_manifest,
        args.target_height,
        &trust,
    )
    .await?;
    println!("{}", serde_json::to_string_pretty(&proof)?);
    Ok(())
}

pub async fn archive_restore_complete(args: ArchiveRestoreCompleteArgs) -> Result<()> {
    let cfg = Config::load(&args.config)?;
    let source = cfg.source(&args.source)?;
    let trust = cfg.trusted_for_endpoint(source)?;
    let store = object_store::from_endpoint(source)?;
    let proof = archive_blob::restore_archive_complete(
        store.as_ref(),
        &args.archive_manifest,
        args.target_height,
        &trust,
        &args.destination_profile,
        &args.archive_dir,
        args.replace,
    )
    .await?;
    println!("{}", serde_json::to_string_pretty(&proof)?);
    Ok(())
}
