use crate::{
    cli::{OutputFormat, PlanArgs},
    config::Config,
    object_store,
    planner::{desired_targets, Target, TargetKind},
    pointer::pointer_path,
    retention::RetentionPolicy,
};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Debug, Serialize)]
struct PlanOutput {
    network: String,
    wall_clock_now: DateTime<Utc>,
    targets: Vec<PlanTarget>,
}

#[derive(Debug, Serialize)]
struct PlanTarget {
    label: String,
    kind: TargetKind,
    period: String,
    cutoff: DateTime<Utc>,
    status: String,
}

pub async fn run(args: PlanArgs) -> Result<()> {
    if args.source.is_some() && args.config.is_none() {
        anyhow::bail!("--config is required when --source is provided");
    }
    let now = parse_optional_time(args.now.as_deref())?.unwrap_or_else(Utc::now);
    let genesis_time = parse_optional_time(args.genesis_time.as_deref())?;
    let policy = RetentionPolicy::load(&args.policy)?;
    let targets = desired_targets(now, &policy, genesis_time);

    let existing_labels = if let Some(source_name) = args.source.as_deref() {
        let cfg = Config::load(args.config.as_ref().unwrap())?;
        let source = cfg.source(source_name)?;
        let store = object_store::from_endpoint(source)?;
        let mut existing = std::collections::BTreeSet::new();
        for target in &targets {
            if store.exists(&pointer_path(&target.label)?).await? {
                existing.insert(target.label.clone());
            }
        }
        existing
    } else {
        std::collections::BTreeSet::new()
    };

    let output = PlanOutput {
        network: args.network,
        wall_clock_now: now,
        targets: targets
            .into_iter()
            .map(|target| plan_target(target, args.source.is_some(), &existing_labels))
            .collect(),
    };
    match args.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&output)?),
        OutputFormat::Text => {
            for target in output.targets {
                println!(
                    "{}\t{:?}\t{}\t{}\t{}",
                    target.status, target.kind, target.period, target.cutoff, target.label
                );
            }
        }
    }
    Ok(())
}

pub fn parse_optional_time(input: Option<&str>) -> Result<Option<DateTime<Utc>>> {
    input
        .map(|s| {
            DateTime::parse_from_rfc3339(s)
                .with_context(|| format!("parse RFC3339 time {s}"))
                .map(|dt| dt.with_timezone(&Utc))
        })
        .transpose()
}

fn plan_target(
    target: Target,
    checked_existing: bool,
    existing_labels: &std::collections::BTreeSet<String>,
) -> PlanTarget {
    let status = if checked_existing {
        if existing_labels.contains(&target.label) {
            "existing"
        } else {
            "missing"
        }
    } else {
        "desired"
    };
    PlanTarget {
        label: target.label,
        kind: target.kind,
        period: target.period,
        cutoff: target.cutoff,
        status: status.to_string(),
    }
}
