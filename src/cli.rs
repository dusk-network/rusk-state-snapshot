use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "rusk-state-snapshot")]
#[command(about = "Standalone signed Rusk state snapshot distribution tool")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Pack(PackArgs),
    Verify(VerifyArgs),
    Publish(PublishArgs),
    Promote(PromoteArgs),
    List(ListArgs),
    Restore(RestoreArgs),
    Gc(GcArgs),
    RebuildIndex(RebuildIndexArgs),
    Plan(PlanArgs),
    Watch(WatchArgs),
    Capture(CaptureArgs),
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Json,
    Text,
}

#[derive(Debug, Args)]
pub struct PackArgs {
    #[arg(long)]
    pub network: String,
    #[arg(long, default_value = "provisioner")]
    pub role: String,
    #[arg(long)]
    pub state_dir: PathBuf,
    #[arg(long)]
    pub chain_db_dir: PathBuf,
    #[arg(long)]
    pub height: u64,
    #[arg(long)]
    pub block_hash: String,
    #[arg(long)]
    pub state_root: String,
    #[arg(long)]
    pub block_timestamp: String,
    #[arg(long)]
    pub rusk_version: String,
    #[arg(long)]
    pub out: PathBuf,
    #[arg(long)]
    pub signing_key: Option<String>,
    #[arg(long)]
    pub key_id: Option<String>,
    #[arg(long)]
    pub publisher_name: Option<String>,
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    pub manifest: String,
    #[arg(long)]
    pub config: Option<PathBuf>,
    #[arg(long)]
    pub trusted_key: Vec<String>,
    #[arg(long)]
    pub require_signature: bool,
    #[arg(long)]
    pub network: Option<String>,
    #[arg(long)]
    pub role: Option<String>,
}

#[derive(Debug, Args)]
pub struct PublishArgs {
    #[arg(long)]
    pub target: String,
    #[arg(long)]
    pub config: PathBuf,
    pub manifest: PathBuf,
}

#[derive(Debug, Args)]
pub struct PromoteArgs {
    #[arg(long)]
    pub target: String,
    #[arg(long)]
    pub config: PathBuf,
    #[arg(long)]
    pub manifest_path: String,
    #[arg(long)]
    pub label: String,
    #[arg(long, default_value_t = true)]
    pub update_previous: bool,
    /// Refuse to promote a manifest that is not signed by a key listed in the
    /// target's `trusted_keys`. Recommended for production.
    #[arg(long)]
    pub require_signed_manifest: bool,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    #[arg(long)]
    pub source: String,
    #[arg(long)]
    pub config: PathBuf,
    #[arg(long)]
    pub label: Option<String>,
}

#[derive(Debug, Args)]
pub struct RestoreArgs {
    #[arg(long)]
    pub source: String,
    #[arg(long)]
    pub config: PathBuf,
    #[arg(long)]
    pub latest: bool,
    #[arg(long)]
    pub monthly: Option<String>,
    #[arg(long)]
    pub daily: Option<String>,
    #[arg(long)]
    pub yearly: Option<String>,
    #[arg(long)]
    pub pin: Option<String>,
    #[arg(long)]
    pub manifest_path: Option<String>,
    #[arg(long)]
    pub destination_profile: PathBuf,
    #[arg(long)]
    pub manage_service: Option<String>,
    #[arg(long)]
    pub owner: Option<String>,
}

#[derive(Debug, Args)]
pub struct GcArgs {
    #[arg(long)]
    pub target: String,
    #[arg(long)]
    pub config: PathBuf,
    #[arg(long)]
    pub policy: PathBuf,
    #[arg(long)]
    pub dry_run: bool,
    #[arg(long)]
    pub delete: bool,
}

/// Walk the target's `v1/` namespace and write a fresh `v1/index.json` so HTTP
/// public sources (which have no native bucket listing) can serve a directory
/// equivalent to the operator-published store.
#[derive(Debug, Args)]
pub struct RebuildIndexArgs {
    #[arg(long)]
    pub target: String,
    #[arg(long)]
    pub config: PathBuf,
}

#[derive(Debug, Args)]
pub struct PlanArgs {
    #[arg(long)]
    pub network: String,
    #[arg(long)]
    pub policy: PathBuf,
    #[arg(long)]
    pub source: Option<String>,
    #[arg(long)]
    pub config: Option<PathBuf>,
    #[arg(long)]
    pub now: Option<String>,
    #[arg(long)]
    pub genesis_time: Option<String>,
    #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
    pub format: OutputFormat,
}

#[derive(Debug, Args)]
pub struct WatchArgs {
    #[arg(long)]
    pub network: String,
    #[arg(long)]
    pub policy: PathBuf,
    #[arg(long)]
    pub config: PathBuf,
    #[arg(long)]
    pub source: String,
    #[arg(long)]
    pub target: String,
    #[arg(long)]
    pub state_dir: PathBuf,
    #[arg(long)]
    pub chain_db_dir: PathBuf,
    #[arg(long)]
    pub tip_command: Option<String>,
    #[arg(long)]
    pub tip_file: Option<PathBuf>,
    #[arg(long)]
    pub network_tip_command: Option<String>,
    #[arg(long)]
    pub network_tip_file: Option<PathBuf>,
    #[arg(long)]
    pub manage_service: Option<String>,
    #[arg(long)]
    pub manifest_signing_key: Option<String>,
    #[arg(long)]
    pub manifest_key_id: Option<String>,
    #[arg(long)]
    pub publisher_name: Option<String>,
    #[arg(long)]
    pub require_signed_manifest: bool,
    #[arg(long)]
    pub journal: PathBuf,
    #[arg(long)]
    pub spool_dir: Option<PathBuf>,
    #[arg(long, default_value = "10s")]
    pub poll_interval: String,
    #[arg(long, default_value = "1h")]
    pub max_capture_lag: String,
    #[arg(long, default_value = "24h")]
    pub latest_freshness_window: String,
    #[arg(long, default_value = "24h")]
    pub latest_min_interval: String,
    #[arg(long)]
    pub genesis_time: Option<String>,
    #[arg(long, default_value = "unknown")]
    pub rusk_version: String,
    #[arg(long)]
    pub allow_prestop_tip: bool,
}

#[derive(Debug, Args, Clone)]
pub struct CaptureArgs {
    #[arg(long)]
    pub network: String,
    #[arg(long, value_delimiter = ',')]
    pub labels: Vec<String>,
    #[arg(long)]
    pub cutoff: Option<String>,
    #[arg(long)]
    pub config: PathBuf,
    #[arg(long)]
    pub target: String,
    #[arg(long)]
    pub state_dir: PathBuf,
    #[arg(long)]
    pub chain_db_dir: PathBuf,
    #[arg(long)]
    pub spool_dir: Option<PathBuf>,
    #[arg(long)]
    pub tip_command: Option<String>,
    #[arg(long)]
    pub tip_file: Option<PathBuf>,
    #[arg(long)]
    pub manage_service: Option<String>,
    #[arg(long)]
    pub manifest_signing_key: Option<String>,
    #[arg(long)]
    pub manifest_key_id: Option<String>,
    #[arg(long)]
    pub publisher_name: Option<String>,
    #[arg(long)]
    pub require_signed_manifest: bool,
    #[arg(long)]
    pub rebuild_index: bool,
    #[arg(long)]
    pub leave_stopped_on_error: bool,
    #[arg(long)]
    pub allow_prestop_tip: bool,
    #[arg(long)]
    pub allow_stale_calendar: bool,
    #[arg(long, default_value = "1h")]
    pub max_capture_lag: String,
    #[arg(long, default_value = "unknown")]
    pub rusk_version: String,
    #[arg(long)]
    pub delete_candidate_after_publish: bool,
}
