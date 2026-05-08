use crate::{
    cli::{CaptureArgs, WatchArgs},
    commands::capture,
    config::Config,
    journal::{self, LatestEntry, WatchJournal},
    object_store,
    planner::{desired_targets, Target},
    pointer::pointer_path,
    retention::{parse_duration, RetentionPolicy},
    tip::{Tip, TipSource},
};
use anyhow::{Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use std::{collections::BTreeMap, path::PathBuf, time::Duration};

pub async fn run(args: WatchArgs) -> Result<()> {
    let policy = RetentionPolicy::load(&args.policy)?;
    let poll_interval = parse_duration(&args.poll_interval)?;
    let max_capture_lag = parse_duration(&args.max_capture_lag)?;
    let latest_freshness_window = parse_duration(&args.latest_freshness_window)?;
    let latest_min_interval = parse_duration(&args.latest_min_interval)?;
    let genesis_time = crate::commands::plan::parse_optional_time(args.genesis_time.as_deref())?;
    let tip_source = TipSource::required(args.tip_command.clone(), args.tip_file.clone(), "tip")?;
    let network_tip_source = TipSource::new(
        args.network_tip_command.clone(),
        args.network_tip_file.clone(),
        "network-tip",
    )?;

    let mut journal = journal::load_or_create(&args.journal, &args.network, Utc::now())?;

    loop {
        let now = Utc::now();
        let local_tip = tip_source.read().await.context("read local tip")?;
        let desired = desired_targets(now, &policy, genesis_time);
        let existing = existing_labels(&args.config, &args.source, &args.target, &desired).await?;

        if journal.last_seen_tip.is_none() {
            classify_startup(&mut journal, &desired, &existing, &local_tip, now);
            journal.last_seen_tip = Some(local_tip);
            journal::save_atomic(&args.journal, &mut journal, now)?;
            tokio::time::sleep(poll_interval).await;
            continue;
        }

        let previous_tip = journal.last_seen_tip.clone().unwrap();
        let grouped = classify_crossings(
            &mut journal,
            &desired,
            &existing,
            &previous_tip,
            &local_tip,
            max_capture_lag,
            now,
        );
        for (cutoff, targets) in grouped {
            let labels: Vec<String> = targets.iter().map(|target| target.label.clone()).collect();
            let result = capture::capture(capture_args_for_labels(&args, labels.clone(), cutoff))
                .await
                .with_context(|| format!("capture labels at cutoff {cutoff}"))?;
            journal.record_captured(&labels, cutoff, result.snapshot_id, now);
        }

        maybe_capture_latest(
            &args,
            &mut journal,
            &network_tip_source,
            &local_tip,
            latest_freshness_window,
            latest_min_interval,
            now,
        )
        .await?;

        journal.last_seen_tip = Some(local_tip);
        journal::save_atomic(&args.journal, &mut journal, now)?;
        tokio::time::sleep(poll_interval).await;
    }
}

pub fn classify_startup(
    journal: &mut WatchJournal,
    desired: &[Target],
    existing: &std::collections::BTreeSet<String>,
    local_tip: &Tip,
    now: DateTime<Utc>,
) {
    for target in desired {
        if existing.contains(&target.label)
            || journal.has_captured_label(&target.label)
            || journal.has_missed_label(&target.label)
        {
            continue;
        }
        if target.cutoff <= local_tip.block_timestamp {
            journal.record_missed(
                target.label.clone(),
                target.cutoff,
                "local tip was already past cutoff before watcher observed it",
                now,
            );
        }
    }
}

pub fn classify_crossings(
    journal: &mut WatchJournal,
    desired: &[Target],
    existing: &std::collections::BTreeSet<String>,
    previous_tip: &Tip,
    local_tip: &Tip,
    max_capture_lag: Duration,
    now: DateTime<Utc>,
) -> BTreeMap<DateTime<Utc>, Vec<Target>> {
    let mut grouped: BTreeMap<DateTime<Utc>, Vec<Target>> = BTreeMap::new();
    for target in desired {
        if existing.contains(&target.label)
            || journal.has_captured_label(&target.label)
            || journal.has_missed_label(&target.label)
        {
            continue;
        }
        if target.cutoff <= previous_tip.block_timestamp {
            journal.record_missed(
                target.label.clone(),
                target.cutoff,
                "cutoff was already behind the last observed local tip",
                now,
            );
            continue;
        }
        if previous_tip.block_timestamp < target.cutoff
            && target.cutoff <= local_tip.block_timestamp
        {
            let lag = (local_tip.block_timestamp - target.cutoff)
                .to_std()
                .unwrap_or_else(|_| Duration::from_secs(0));
            if lag <= max_capture_lag {
                grouped
                    .entry(target.cutoff)
                    .or_default()
                    .push(target.clone());
            } else {
                journal.record_missed(
                    target.label.clone(),
                    target.cutoff,
                    "local tip crossed cutoff outside max capture lag",
                    now,
                );
            }
            continue;
        }
        if let Ok(lag) = (local_tip.block_timestamp - target.cutoff).to_std() {
            if lag > max_capture_lag {
                journal.record_missed(
                    target.label.clone(),
                    target.cutoff,
                    "local tip was too far past cutoff before capture",
                    now,
                );
            }
        }
    }
    grouped
}

pub fn latest_is_fresh(
    local_tip_time: DateTime<Utc>,
    freshness_reference: DateTime<Utc>,
    freshness_window: Duration,
) -> bool {
    let threshold = ChronoDuration::from_std(freshness_window).unwrap_or(ChronoDuration::MAX);
    local_tip_time + threshold >= freshness_reference
}

pub fn latest_interval_elapsed(
    journal: &WatchJournal,
    latest_min_interval: Duration,
    now: DateTime<Utc>,
) -> bool {
    match &journal.latest {
        None => true,
        Some(latest) => (now - latest.last_promoted_at)
            .to_std()
            .map(|elapsed| elapsed >= latest_min_interval)
            .unwrap_or(false),
    }
}

async fn maybe_capture_latest(
    args: &WatchArgs,
    journal: &mut WatchJournal,
    network_tip_source: &TipSource,
    local_tip: &Tip,
    latest_freshness_window: Duration,
    latest_min_interval: Duration,
    now: DateTime<Utc>,
) -> Result<()> {
    let freshness_reference = if network_tip_source.is_configured() {
        match network_tip_source.read().await {
            Ok(tip) => tip.block_timestamp,
            Err(err) => {
                eprintln!("warning: could not read network tip, using wall clock for latest freshness: {err}");
                now
            }
        }
    } else {
        now
    };
    if !latest_is_fresh(
        local_tip.block_timestamp,
        freshness_reference,
        latest_freshness_window,
    ) {
        return Ok(());
    }
    if !latest_interval_elapsed(journal, latest_min_interval, now) {
        return Ok(());
    }
    let result = capture::capture(capture_args_for_latest(args))
        .await
        .context("capture latest")?;
    journal.latest = Some(LatestEntry {
        last_promoted_at: now,
        last_snapshot_id: result.snapshot_id,
    });
    Ok(())
}

async fn existing_labels(
    config: &PathBuf,
    source_name: &str,
    target_name: &str,
    desired: &[Target],
) -> Result<std::collections::BTreeSet<String>> {
    let cfg = Config::load(config)?;
    let source = object_store::from_endpoint(cfg.source(source_name)?)?;
    let target = object_store::from_endpoint(cfg.target(target_name)?)?;
    let mut existing = std::collections::BTreeSet::new();
    for target_label in desired {
        let path = pointer_path(&target_label.label)?;
        if source.exists(&path).await? || target.exists(&path).await? {
            existing.insert(target_label.label.clone());
        }
    }
    Ok(existing)
}

fn capture_args_for_labels(
    args: &WatchArgs,
    labels: Vec<String>,
    cutoff: DateTime<Utc>,
) -> CaptureArgs {
    CaptureArgs {
        network: args.network.clone(),
        labels,
        cutoff: Some(cutoff.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
        config: args.config.clone(),
        target: args.target.clone(),
        state_dir: args.state_dir.clone(),
        chain_db_dir: args.chain_db_dir.clone(),
        tip_command: args.tip_command.clone(),
        tip_file: args.tip_file.clone(),
        manage_service: args.manage_service.clone(),
        manifest_signing_key: args.manifest_signing_key.clone(),
        manifest_key_id: args.manifest_key_id.clone(),
        publisher_name: args.publisher_name.clone(),
        require_signed_manifest: args.require_signed_manifest,
        rebuild_index: true,
        leave_stopped_on_error: false,
        allow_prestop_tip: args.allow_prestop_tip,
        allow_stale_calendar: false,
        max_capture_lag: args.max_capture_lag.clone(),
        rusk_version: args.rusk_version.clone(),
    }
}

fn capture_args_for_latest(args: &WatchArgs) -> CaptureArgs {
    CaptureArgs {
        network: args.network.clone(),
        labels: vec!["latest".to_string()],
        cutoff: None,
        config: args.config.clone(),
        target: args.target.clone(),
        state_dir: args.state_dir.clone(),
        chain_db_dir: args.chain_db_dir.clone(),
        tip_command: args.tip_command.clone(),
        tip_file: args.tip_file.clone(),
        manage_service: args.manage_service.clone(),
        manifest_signing_key: args.manifest_signing_key.clone(),
        manifest_key_id: args.manifest_key_id.clone(),
        publisher_name: args.publisher_name.clone(),
        require_signed_manifest: args.require_signed_manifest,
        rebuild_index: true,
        leave_stopped_on_error: false,
        allow_prestop_tip: args.allow_prestop_tip,
        allow_stale_calendar: false,
        max_capture_lag: args.max_capture_lag.clone(),
        rusk_version: args.rusk_version.clone(),
    }
}
