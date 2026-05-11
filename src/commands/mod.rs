pub mod archive_blob;
pub mod capture;
pub mod gc;
pub mod index;
pub mod list;
pub mod pack;
pub mod plan;
pub mod promote;
pub mod publish;
pub mod restore;
pub mod verify;
pub mod watch;

use crate::cli::{Cli, Command};
use anyhow::Result;

pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Pack(args) => pack::run(args).await,
        Command::Verify(args) => verify::run(args).await,
        Command::Publish(args) => publish::run(args).await,
        Command::Promote(args) => promote::run(args).await,
        Command::List(args) => list::run(args).await,
        Command::Restore(args) => restore::run(args).await,
        Command::Gc(args) => gc::run(args).await,
        Command::RebuildIndex(args) => index::run(args).await,
        Command::Plan(args) => plan::run(args).await,
        Command::Watch(args) => watch::run(args).await,
        Command::Capture(args) => capture::run(args).await,
        Command::BlobsPackRange(args) => archive_blob::blobs_pack_range(args).await,
        Command::BlobsPublishRange(args) => archive_blob::blobs_publish_range(args).await,
        Command::BlobsPublishCoverage(args) => archive_blob::blobs_publish_coverage(args).await,
        Command::BlobsWriteCoverage(args) => archive_blob::blobs_write_coverage(args).await,
        Command::BlobsVerifyCoverage(args) => archive_blob::blobs_verify_coverage(args).await,
        Command::ArchivePack(args) => archive_blob::archive_pack(args).await,
        Command::ArchivePublish(args) => archive_blob::archive_publish(args).await,
        Command::ArchivePromote(args) => archive_blob::archive_promote(args).await,
        Command::VerifyArchiveComplete(args) => archive_blob::verify_archive_complete(args).await,
        Command::ArchiveRestoreComplete(args) => archive_blob::archive_restore_complete(args).await,
    }
}
