use crate::{
    archive,
    cli::{CaptureArgs, PromoteArgs, PublishArgs, RebuildIndexArgs},
    commands::{index, promote, publish},
    hashing,
    manifest::{
        snapshot_id, Artifact, ComponentEntry, Components, ManifestBody, Publisher, SignedManifest,
        MANIFEST_FORMAT,
    },
    retention::parse_duration,
    signing,
    tip::{Tip, TipSource},
};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Datelike, Duration as ChronoDuration, Months, NaiveDate, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::process::Command;

#[derive(Debug, Clone)]
pub struct CaptureResult {
    pub snapshot_id: String,
    pub manifest_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackedCandidate {
    pub snapshot_id: String,
    pub labels: Vec<String>,
    pub cutoff: Option<DateTime<Utc>>,
    pub stopped_tip: Tip,
    pub candidate_dir: PathBuf,
    pub artifact_path_local: PathBuf,
    pub manifest_path_local: PathBuf,
    pub manifest_path_remote: String,
}

/// Lightweight proof trace used by tests to lock down phase ordering. Runtime
/// behavior does not depend on it.
#[derive(Clone, Default)]
pub struct CaptureEventLog {
    events: Arc<Mutex<Vec<String>>>,
}

impl CaptureEventLog {
    pub fn record(&self, event: impl Into<String>) {
        self.events.lock().unwrap().push(event.into());
    }

    pub fn snapshot(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }
}

#[async_trait]
pub trait ServiceController {
    async fn stop(&mut self, service: &str) -> Result<()>;
    async fn start(&mut self, service: &str) -> Result<()>;
}

pub struct SystemctlServiceController;

#[async_trait]
impl ServiceController for SystemctlServiceController {
    async fn stop(&mut self, service: &str) -> Result<()> {
        service_command("stop", service).await
    }

    async fn start(&mut self, service: &str) -> Result<()> {
        service_command("start", service).await
    }
}

#[async_trait]
pub trait PublicationOps {
    async fn publish(&mut self, args: &CaptureArgs, candidate: &PackedCandidate) -> Result<()>;
    async fn promote_label(
        &mut self,
        args: &CaptureArgs,
        candidate: &PackedCandidate,
        label: &str,
    ) -> Result<()>;
    async fn rebuild_index(&mut self, args: &CaptureArgs) -> Result<()>;
}

pub struct CommandPublicationOps;

#[async_trait]
impl PublicationOps for CommandPublicationOps {
    async fn publish(&mut self, args: &CaptureArgs, candidate: &PackedCandidate) -> Result<()> {
        publish::run(PublishArgs {
            target: args.target.clone(),
            config: args.config.clone(),
            manifest: candidate.manifest_path_local.clone(),
        })
        .await
    }

    async fn promote_label(
        &mut self,
        args: &CaptureArgs,
        candidate: &PackedCandidate,
        label: &str,
    ) -> Result<()> {
        promote::run(PromoteArgs {
            target: args.target.clone(),
            config: args.config.clone(),
            manifest_path: candidate.manifest_path_remote.clone(),
            label: label.to_string(),
            update_previous: label == "latest",
            require_signed_manifest: args.require_signed_manifest,
        })
        .await
    }

    async fn rebuild_index(&mut self, args: &CaptureArgs) -> Result<()> {
        index::run(RebuildIndexArgs {
            target: args.target.clone(),
            config: args.config.clone(),
        })
        .await
    }
}

pub async fn run(args: CaptureArgs) -> Result<()> {
    let result = capture(args).await?;
    println!("{}", result.manifest_path);
    Ok(())
}

pub async fn capture(args: CaptureArgs) -> Result<CaptureResult> {
    let candidate = pack_stopped_candidate(&args).await?;
    publish_candidate_and_promote(&args, &candidate).await
}

pub async fn pack_stopped_candidate(args: &CaptureArgs) -> Result<PackedCandidate> {
    let mut service = SystemctlServiceController;
    pack_stopped_candidate_with_service(args, &mut service, None).await
}

pub async fn pack_stopped_candidate_with_service(
    args: &CaptureArgs,
    service: &mut dyn ServiceController,
    events: Option<&CaptureEventLog>,
) -> Result<PackedCandidate> {
    if args.labels.is_empty() {
        bail!("--labels must include at least one label");
    }
    let service_name = args.manage_service.as_deref().ok_or_else(|| {
        anyhow::anyhow!("capture requires --manage-service for stopped-state consistency")
    })?;
    let cutoff = parse_cutoff(args.cutoff.as_deref())?;
    let max_capture_lag = parse_duration(&args.max_capture_lag)?;
    let tip_source = TipSource::required(args.tip_command.clone(), args.tip_file.clone(), "tip")?;

    events.map(|e| e.record("read-prestop-tip"));
    let pre_stop_tip = tip_source.read().await?;

    events.map(|e| e.record("stop"));
    service.stop(service_name).await?;

    let packed = async {
        events.map(|e| e.record("read-stopped-tip"));
        let stopped_tip = select_stopped_tip(
            pre_stop_tip,
            tip_source.read().await,
            args.allow_prestop_tip,
        )?;
        validate_tip_for_labels(
            &stopped_tip,
            &args.labels,
            cutoff,
            max_capture_lag,
            args.allow_stale_calendar,
        )?;

        events.map(|e| e.record("pack"));
        let candidate = pack_candidate_files(args, stopped_tip, cutoff)?;
        verify_candidate_complete(&candidate)?;
        write_candidate_marker(&candidate)?;
        Ok(candidate)
    }
    .await;

    match packed {
        Ok(candidate) => {
            events.map(|e| e.record("start"));
            service.start(service_name).await?;
            Ok(candidate)
        }
        Err(err) => {
            if !args.leave_stopped_on_error {
                events.map(|e| e.record("start"));
                let _ = service.start(service_name).await;
            }
            Err(err)
        }
    }
}

pub async fn publish_candidate_and_promote(
    args: &CaptureArgs,
    candidate: &PackedCandidate,
) -> Result<CaptureResult> {
    let mut ops = CommandPublicationOps;
    publish_candidate_and_promote_with_ops(args, candidate, &mut ops, None).await
}

pub async fn publish_candidate_and_promote_with_ops(
    args: &CaptureArgs,
    candidate: &PackedCandidate,
    ops: &mut dyn PublicationOps,
    events: Option<&CaptureEventLog>,
) -> Result<CaptureResult> {
    verify_candidate_complete(candidate)?;
    events.map(|e| e.record("publish"));
    ops.publish(args, candidate)
        .await
        .context("publish capture snapshot")?;

    for label in &candidate.labels {
        events.map(|e| e.record(format!("promote:{label}")));
        ops.promote_label(args, candidate, label)
            .await
            .with_context(|| format!("promote label {label}"))?;
    }
    if args.rebuild_index {
        events.map(|e| e.record("rebuild-index"));
        ops.rebuild_index(args).await.context("rebuild index")?;
    }
    if args.delete_candidate_after_publish {
        fs::remove_dir_all(&candidate.candidate_dir)
            .with_context(|| format!("remove {}", candidate.candidate_dir.display()))?;
    }
    Ok(CaptureResult {
        snapshot_id: candidate.snapshot_id.clone(),
        manifest_path: candidate.manifest_path_remote.clone(),
    })
}

pub fn load_publishable_candidate(marker: &Path) -> Result<PackedCandidate> {
    let bytes = fs::read(marker).with_context(|| format!("read {}", marker.display()))?;
    let candidate: PackedCandidate =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", marker.display()))?;
    verify_candidate_complete(&candidate)?;
    Ok(candidate)
}

pub fn candidate_marker_path(candidate: &PackedCandidate) -> PathBuf {
    candidate.candidate_dir.join("candidate.json")
}

pub fn verify_candidate_complete(candidate: &PackedCandidate) -> Result<()> {
    if !candidate.candidate_dir.is_dir() {
        bail!(
            "candidate dir does not exist: {}",
            candidate.candidate_dir.display()
        );
    }
    if !candidate.artifact_path_local.is_file() {
        bail!(
            "candidate artifact missing: {}",
            candidate.artifact_path_local.display()
        );
    }
    if !candidate.manifest_path_local.is_file() {
        bail!(
            "candidate manifest missing: {}",
            candidate.manifest_path_local.display()
        );
    }

    let manifest_bytes = fs::read(&candidate.manifest_path_local)
        .with_context(|| format!("read {}", candidate.manifest_path_local.display()))?;
    let manifest: SignedManifest = serde_json::from_slice(&manifest_bytes)?;
    manifest.validate_schema()?;
    let artifact = &manifest.body.artifacts[0];
    if artifact.path != "snapshot.tar.zst" {
        bail!("manifest artifact path must be snapshot.tar.zst");
    }
    if manifest.body.height != candidate.stopped_tip.height {
        bail!("manifest height does not match stopped tip");
    }
    if manifest.body.block_hash != candidate.stopped_tip.block_hash.to_lowercase() {
        bail!("manifest block_hash does not match stopped tip");
    }
    if manifest.body.state_root != candidate.stopped_tip.state_root.to_lowercase() {
        bail!("manifest state_root does not match stopped tip");
    }
    if manifest.body.block_timestamp
        != candidate
            .stopped_tip
            .block_timestamp
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    {
        bail!("manifest block_timestamp does not match stopped tip");
    }

    File::open(&candidate.artifact_path_local)
        .with_context(|| format!("open {}", candidate.artifact_path_local.display()))?;
    let hashes = hashing::hash_file(&candidate.artifact_path_local)?;
    if hashes.size != artifact.size {
        bail!("candidate artifact size does not match manifest");
    }
    if hashes.sha256 != artifact.sha256 {
        bail!("candidate artifact sha256 does not match manifest");
    }
    if hashes.blake3 != artifact.blake3 {
        bail!("candidate artifact blake3 does not match manifest");
    }
    let archived_state_id = read_archived_state_id(&candidate.artifact_path_local)?;
    if archived_state_id != manifest.body.state_id {
        bail!("archived state/state.id does not match manifest state_id");
    }
    Ok(())
}

pub fn validate_tip_for_labels(
    tip: &Tip,
    labels: &[String],
    cutoff: Option<DateTime<Utc>>,
    max_capture_lag: Duration,
    allow_stale_calendar: bool,
) -> Result<()> {
    let has_calendar = labels.iter().any(|label| is_calendar_label(label));
    if !has_calendar {
        return Ok(());
    }
    let cutoff =
        cutoff.ok_or_else(|| anyhow::anyhow!("--cutoff is required for calendar labels"))?;
    validate_calendar_labels_match_cutoff(labels, cutoff)?;
    if tip.block_timestamp < cutoff {
        bail!(
            "local tip timestamp {} is before requested cutoff {}",
            tip.block_timestamp,
            cutoff
        );
    }
    let lag = (tip.block_timestamp - cutoff)
        .to_std()
        .unwrap_or_else(|_| Duration::from_secs(0));
    if lag > max_capture_lag && !allow_stale_calendar {
        bail!(
            "local tip timestamp {} is outside max capture lag from cutoff {}",
            tip.block_timestamp,
            cutoff
        );
    }
    Ok(())
}

pub fn validate_calendar_labels_match_cutoff(
    labels: &[String],
    cutoff: DateTime<Utc>,
) -> Result<()> {
    for label in labels {
        let Some(expected) = expected_cutoff_for_calendar_label(label)? else {
            continue;
        };
        if expected != cutoff {
            bail!("calendar label {label} requires cutoff {expected}, got {cutoff}");
        }
    }
    Ok(())
}

pub fn select_stopped_tip(
    pre_stop_tip: Tip,
    stopped_tip: Result<Tip>,
    allow_prestop_tip: bool,
) -> Result<Tip> {
    match stopped_tip {
        Ok(tip) => Ok(tip),
        Err(err) if allow_prestop_tip => {
            eprintln!(
                "warning: could not read tip after stopping service, using pre-stop tip metadata: {err}"
            );
            Ok(pre_stop_tip)
        }
        Err(err) => Err(err).context(
            "could not read tip after stopping service; refusing to use pre-stop tip metadata without --allow-prestop-tip",
        ),
    }
}

fn pack_candidate_files(
    args: &CaptureArgs,
    stopped_tip: Tip,
    cutoff: Option<DateTime<Utc>>,
) -> Result<PackedCandidate> {
    let id = snapshot_id(stopped_tip.height, &stopped_tip.state_root.to_lowercase());
    let candidate_dir = candidate_root(args).join(&id);
    fs::create_dir_all(&candidate_dir)
        .with_context(|| format!("create {}", candidate_dir.display()))?;

    let artifact_path = candidate_dir.join("snapshot.tar.zst");
    let artifact_tmp = candidate_dir.join("snapshot.tar.zst.tmp");
    let manifest_path = candidate_dir.join("manifest.json");
    let manifest_tmp = candidate_dir.join("manifest.json.tmp");
    let marker_path = candidate_dir.join("candidate.json");
    let marker_tmp = candidate_dir.join("candidate.json.tmp");
    for tmp in [&artifact_tmp, &manifest_tmp, &marker_tmp] {
        if tmp.exists() {
            fs::remove_file(tmp).with_context(|| format!("remove stale {}", tmp.display()))?;
        }
    }
    if marker_path.exists() {
        fs::remove_file(&marker_path)
            .with_context(|| format!("remove stale {}", marker_path.display()))?;
    }

    archive::create_snapshot_archive(&args.state_dir, &args.chain_db_dir, &artifact_tmp)?;
    sync_file(&artifact_tmp)?;
    fs::rename(&artifact_tmp, &artifact_path).with_context(|| {
        format!(
            "rename {} to {}",
            artifact_tmp.display(),
            artifact_path.display()
        )
    })?;
    sync_dir(&candidate_dir);

    let hashes = hashing::hash_file(&artifact_path)?;
    let state_id = read_archived_state_id(&artifact_path)?;
    let key_id = args
        .manifest_key_id
        .clone()
        .unwrap_or_else(|| "local-dev".to_string());
    let publisher = args.publisher_name.clone().map(|name| Publisher {
        name,
        key_id: key_id.clone(),
    });
    let body = ManifestBody {
        format: MANIFEST_FORMAT.to_string(),
        network: args.network.clone(),
        role: "provisioner".to_string(),
        kind: "full".to_string(),
        height: stopped_tip.height,
        block_hash: stopped_tip.block_hash.to_lowercase(),
        block_timestamp: stopped_tip
            .block_timestamp
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        state_root: stopped_tip.state_root.to_lowercase(),
        state_id,
        rusk_version: args.rusk_version.clone(),
        created_at: Utc::now(),
        artifacts: vec![Artifact {
            name: "state-chain".to_string(),
            path: "snapshot.tar.zst".to_string(),
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
    let signature = match args.manifest_signing_key.clone() {
        Some(spec) => Some(signing::sign_body(&body, &key_id, &spec)?),
        None => None,
    };
    let manifest = SignedManifest { body, signature };
    manifest.validate_schema()?;
    write_atomic(
        &manifest_path,
        &manifest_tmp,
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    sync_dir(&candidate_dir);

    Ok(PackedCandidate {
        snapshot_id: id.clone(),
        labels: args.labels.clone(),
        cutoff,
        stopped_tip,
        candidate_dir,
        artifact_path_local: artifact_path,
        manifest_path_local: manifest_path,
        manifest_path_remote: format!("v1/snapshots/full/{id}/manifest.json"),
    })
}

fn write_candidate_marker(candidate: &PackedCandidate) -> Result<()> {
    let marker = candidate_marker_path(candidate);
    let marker_tmp = candidate.candidate_dir.join("candidate.json.tmp");
    write_atomic(&marker, &marker_tmp, &serde_json::to_vec_pretty(candidate)?)?;
    sync_dir(&candidate.candidate_dir);
    Ok(())
}

fn candidate_root(args: &CaptureArgs) -> PathBuf {
    args.spool_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("target/rusk-state-snapshot-spool"))
        .join("candidates")
}

fn write_atomic(path: &Path, tmp: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = tmp.parent() {
        fs::create_dir_all(parent)?;
    }
    {
        let mut file = File::create(tmp).with_context(|| format!("create {}", tmp.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("write {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("fsync {}", tmp.display()))?;
    }
    fs::rename(tmp, path)
        .with_context(|| format!("rename {} to {}", tmp.display(), path.display()))?;
    Ok(())
}

fn sync_file(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("open {}", path.display()))?
        .sync_all()
        .with_context(|| format!("fsync {}", path.display()))
}

fn sync_dir(path: &Path) {
    if let Ok(dir) = File::open(path) {
        let _ = dir.sync_all();
    }
}

fn read_archived_state_id(artifact_path: &Path) -> Result<String> {
    let file =
        File::open(artifact_path).with_context(|| format!("open {}", artifact_path.display()))?;
    let decoder = zstd::Decoder::new(file)?;
    let mut archive = tar::Archive::new(decoder);
    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.path()?.as_ref() == Path::new("state/state.id") {
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            if bytes.len() != 32 {
                bail!("archived state/state.id must be exactly 32 bytes");
            }
            return Ok(hex::encode(bytes));
        }
    }
    bail!("archive missing state/state.id")
}

fn is_calendar_label(label: &str) -> bool {
    label.starts_with("daily:") || label.starts_with("monthly:") || label.starts_with("yearly:")
}

fn expected_cutoff_for_calendar_label(label: &str) -> Result<Option<DateTime<Utc>>> {
    if let Some(day) = label.strip_prefix("daily:") {
        let day = NaiveDate::parse_from_str(day, "%Y-%m-%d")
            .with_context(|| format!("daily label {label} must use YYYY-MM-DD"))?;
        return Ok(Some(utc_midnight(day + ChronoDuration::days(1))));
    }
    if let Some(month) = label.strip_prefix("monthly:") {
        let month = NaiveDate::parse_from_str(&format!("{month}-01"), "%Y-%m-%d")
            .with_context(|| format!("monthly label {label} must use YYYY-MM"))?;
        let cutoff = month
            .checked_add_months(Months::new(1))
            .ok_or_else(|| anyhow::anyhow!("monthly label {label} is out of range"))?;
        return Ok(Some(utc_midnight(cutoff)));
    }
    if let Some(year) = label.strip_prefix("yearly:") {
        let year: i32 = year
            .parse()
            .with_context(|| format!("yearly label {label} must use YYYY"))?;
        let cutoff = Utc
            .with_ymd_and_hms(year + 1, 1, 1, 0, 0, 0)
            .single()
            .ok_or_else(|| anyhow::anyhow!("yearly label {label} is out of range"))?;
        return Ok(Some(cutoff));
    }
    Ok(None)
}

fn utc_midnight(date: NaiveDate) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(date.year(), date.month(), date.day(), 0, 0, 0)
        .single()
        .unwrap()
}

fn parse_cutoff(input: Option<&str>) -> Result<Option<DateTime<Utc>>> {
    input
        .map(|s| {
            DateTime::parse_from_rfc3339(s)
                .with_context(|| format!("parse cutoff {s}"))
                .map(|dt| dt.with_timezone(&Utc))
        })
        .transpose()
}

async fn service_command(action: &str, service: &str) -> Result<()> {
    let status = Command::new("systemctl")
        .arg(action)
        .arg(service)
        .status()
        .await
        .with_context(|| format!("run systemctl {action} {service}"))?;
    if !status.success() {
        bail!("systemctl {action} {service} failed with {status}");
    }
    Ok(())
}
