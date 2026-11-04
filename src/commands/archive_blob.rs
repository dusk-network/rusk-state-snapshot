use crate::{
    archive_blob,
    archive_blob::{
        ArchiveBlobVerifyOptions, ArchivePackOptions, ExportBlobRangeOptions, PackBlobRangeOptions,
        RestoreArchiveOptions,
    },
    cli::{
        ArchivePackArgs, ArchivePromoteArgs, ArchivePublishArgs, ArchiveRestoreCompleteArgs,
        BlobsExportRangeArgs, BlobsPackRangeArgs, BlobsPublishCoverageArgs, BlobsPublishRangeArgs,
        BlobsVerifyCoverageArgs, BlobsWriteCoverageArgs, VerifyArchiveCompleteArgs,
    },
    config::Config,
    object_store,
};
use anyhow::{bail, Result};

pub async fn blobs_export_range(args: BlobsExportRangeArgs) -> Result<()> {
    let path = archive_blob::export_blob_range(ExportBlobRangeOptions {
        network: args.network,
        rusk_url: args.rusk_url,
        from_height: args.from_height,
        to_height: args.to_height,
        out: args.out,
    })
    .await?;
    println!("{}", path.display());
    Ok(())
}

pub async fn blobs_pack_range(args: BlobsPackRangeArgs) -> Result<()> {
    let path = archive_blob::pack_blob_range(PackBlobRangeOptions {
        network: args.network,
        from_height: args.from_height,
        to_height: args.to_height,
        descriptor_dir: args.descriptor_dir,
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

pub async fn blobs_publish_coverage(args: BlobsPublishCoverageArgs) -> Result<()> {
    let cfg = Config::load(&args.config)?;
    let target = cfg.target(&args.target)?;
    let trust = cfg.trusted_for_endpoint(target)?;
    let verify = ArchiveBlobVerifyOptions::from(&cfg.archive_blob);
    let store = object_store::from_endpoint(target)?;
    let remote = archive_blob::publish_blob_coverage_with_options(
        store.as_ref(),
        &args.manifest,
        &trust,
        verify,
    )
    .await?;
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
    let verify = ArchiveBlobVerifyOptions::from(&cfg.archive_blob);
    let store = object_store::from_endpoint(source)?;
    let objects = archive_blob::verify_blob_coverage_with_options(
        store.as_ref(),
        &args.coverage_manifest,
        args.from_height,
        args.to_height,
        &trust,
        verify,
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

pub async fn archive_publish(args: ArchivePublishArgs) -> Result<()> {
    let cfg = Config::load(&args.config)?;
    let target = cfg.target(&args.target)?;
    let trust = cfg.trusted_for_endpoint(target)?;
    let verify = ArchiveBlobVerifyOptions::from(&cfg.archive_blob);
    let store = object_store::from_endpoint(target)?;
    let remote =
        archive_blob::publish_archive_with_options(store.as_ref(), &args.manifest, &trust, verify)
            .await?;
    println!("{remote}");
    Ok(())
}

pub async fn archive_promote(args: ArchivePromoteArgs) -> Result<()> {
    let cfg = Config::load(&args.config)?;
    let target = cfg.target(&args.target)?;
    let key_spec = target.signing_key()?;
    let key_id = target.signing_key_id()?;
    let trust = cfg.trusted_for_endpoint(target)?;
    let verify = ArchiveBlobVerifyOptions::from(&cfg.archive_blob);
    let store = object_store::from_endpoint(target)?;
    let path = archive_blob::promote_archive_manifest_with_options(
        store.as_ref(),
        &args.archive_manifest,
        &args.label,
        key_spec,
        key_id,
        &trust,
        verify,
    )
    .await?;
    println!("{path}");
    Ok(())
}

pub async fn verify_archive_complete(args: VerifyArchiveCompleteArgs) -> Result<()> {
    let cfg = Config::load(&args.config)?;
    let source = cfg.source(&args.source)?;
    let trust = cfg.trusted_for_endpoint(source)?;
    let verify = ArchiveBlobVerifyOptions::from(&cfg.archive_blob);
    let store = object_store::from_endpoint(source)?;
    let proof = archive_blob::verify_archive_complete_with_options(
        store.as_ref(),
        &args.archive_manifest,
        args.target_height,
        &trust,
        verify,
    )
    .await?;
    println!("{}", serde_json::to_string_pretty(&proof)?);
    Ok(())
}

pub async fn archive_restore_complete(args: ArchiveRestoreCompleteArgs) -> Result<()> {
    let cfg = Config::load(&args.config)?;
    let source = cfg.source(&args.source)?;
    let trust = cfg.trusted_for_endpoint(source)?;
    let mut verify = ArchiveBlobVerifyOptions::from(&cfg.archive_blob);
    // Archive restore overwrites node state, so fail closed for remote sources:
    // require trusted signatures on the archive, blob ranges, coverage, and
    // pointers unless the operator passes --insecure.
    if !source.is_local() && !args.insecure {
        if trust.is_empty() {
            bail!(
                "restoring an archive from remote source `{}` requires at least one \
                 trusted_keys entry in the config; configure one or pass --insecure",
                args.source
            );
        }
        verify.require_signed_blob_ranges = true;
        verify.require_signed_blob_coverage = true;
        verify.require_signed_archive = true;
        verify.require_signed_archive_pointers = true;
    }
    let store = object_store::from_endpoint(source)?;
    let proof = archive_blob::restore_archive_complete_with_options(
        store.as_ref(),
        RestoreArchiveOptions {
            archive_manifest_path: &args.archive_manifest,
            target_height: args.target_height,
            trust: &trust,
            verify,
            destination_profile: &args.destination_profile,
            archive_dir: &args.archive_dir,
            replace: args.replace,
        },
    )
    .await?;
    println!("{}", serde_json::to_string_pretty(&proof)?);
    Ok(())
}
