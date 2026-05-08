use crate::{
    cli::{CaptureArgs, PackArgs, PromoteArgs, PublishArgs, RebuildIndexArgs},
    commands::{index, pack, promote, publish},
    manifest::snapshot_id,
    retention::parse_duration,
    tip::{Tip, TipSource},
};
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use std::time::Duration;
use tokio::process::Command;

#[derive(Debug, Clone)]
pub struct CaptureResult {
    pub snapshot_id: String,
    pub manifest_path: String,
}

pub async fn run(args: CaptureArgs) -> Result<()> {
    let result = capture(args).await?;
    println!("{}", result.manifest_path);
    Ok(())
}

pub async fn capture(args: CaptureArgs) -> Result<CaptureResult> {
    if args.labels.is_empty() {
        bail!("--labels must include at least one label");
    }
    if args.manage_service.is_none() {
        bail!("capture requires --manage-service for stopped-state consistency");
    }
    let cutoff = parse_cutoff(args.cutoff.as_deref())?;
    let max_capture_lag = parse_duration(&args.max_capture_lag)?;
    let tip_source = TipSource::required(args.tip_command.clone(), args.tip_file.clone(), "tip")?;
    let pre_stop_tip = tip_source.read().await?;
    validate_tip_for_labels(
        &pre_stop_tip,
        &args.labels,
        cutoff,
        max_capture_lag,
        args.allow_stale_calendar,
    )?;

    let service = args.manage_service.clone().expect("checked above");
    let leave_stopped_on_error = args.leave_stopped_on_error;
    service_command("stop", &service).await?;
    let result = capture_while_stopped(args, &tip_source, pre_stop_tip).await;
    match result {
        Ok(result) => {
            service_command("start", &service).await?;
            Ok(result)
        }
        Err(err) => {
            if !leave_stopped_on_error {
                let _ = service_command("start", &service).await;
            }
            Err(err)
        }
    }
}

async fn capture_while_stopped(
    args: CaptureArgs,
    tip_source: &TipSource,
    pre_stop_tip: Tip,
) -> Result<CaptureResult> {
    let cutoff = parse_cutoff(args.cutoff.as_deref())?;
    let max_capture_lag = parse_duration(&args.max_capture_lag)?;
    let stopped_tip = match tip_source.read().await {
        Ok(tip) => tip,
        Err(err) => {
            if !args.allow_prestop_tip {
                eprintln!(
                    "warning: could not read tip after stopping service, using pre-stop tip metadata: {err}"
                );
            }
            pre_stop_tip
        }
    };
    validate_tip_for_labels(
        &stopped_tip,
        &args.labels,
        cutoff,
        max_capture_lag,
        args.allow_stale_calendar,
    )?;

    let id = snapshot_id(stopped_tip.height, &stopped_tip.state_root.to_lowercase());
    let tmp = tempfile::tempdir()?;
    let out = tmp.path().join("candidates");
    pack::run(PackArgs {
        network: args.network.clone(),
        role: "provisioner".to_string(),
        state_dir: args.state_dir.clone(),
        chain_db_dir: args.chain_db_dir.clone(),
        height: stopped_tip.height,
        block_hash: stopped_tip.block_hash.clone(),
        state_root: stopped_tip.state_root.clone(),
        block_timestamp: stopped_tip
            .block_timestamp
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        rusk_version: args.rusk_version.clone(),
        out: out.clone(),
        signing_key: args.manifest_signing_key.clone(),
        key_id: args.manifest_key_id.clone(),
        publisher_name: args.publisher_name.clone(),
    })
    .await
    .context("pack capture snapshot")?;
    let manifest = out.join(&id).join("manifest.json");
    publish::run(PublishArgs {
        target: args.target.clone(),
        config: args.config.clone(),
        manifest,
    })
    .await
    .context("publish capture snapshot")?;

    let manifest_path = format!("v1/snapshots/full/{id}/manifest.json");
    for label in &args.labels {
        promote::run(PromoteArgs {
            target: args.target.clone(),
            config: args.config.clone(),
            manifest_path: manifest_path.clone(),
            label: label.clone(),
            update_previous: label == "latest",
            require_signed_manifest: args.require_signed_manifest,
        })
        .await
        .with_context(|| format!("promote label {label}"))?;
    }
    if args.rebuild_index {
        index::run(RebuildIndexArgs {
            target: args.target.clone(),
            config: args.config.clone(),
        })
        .await
        .context("rebuild index")?;
    }
    Ok(CaptureResult {
        snapshot_id: id,
        manifest_path,
    })
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

fn is_calendar_label(label: &str) -> bool {
    label.starts_with("daily:") || label.starts_with("monthly:") || label.starts_with("yearly:")
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
