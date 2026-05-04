use crate::{
    cli::GcArgs, config::Config, manifest::SignedManifest, object_store, pointer::SignedPointer,
    retention::RetentionPolicy,
};
use anyhow::Result;
use chrono::Utc;
use serde::Serialize;
use std::collections::{BTreeSet, HashSet};

#[derive(Debug, Serialize)]
struct GcReport {
    generated_at: chrono::DateTime<Utc>,
    dry_run: bool,
    marked: Vec<String>,
    prunable_pointers: Vec<String>,
    deletable: Vec<String>,
    deleted: Vec<String>,
}

pub async fn run(args: GcArgs) -> Result<()> {
    let cfg = Config::load(&args.config)?;
    let policy = RetentionPolicy::load(&args.policy)?;
    let target = cfg.target(&args.target)?;
    let store = object_store::from_endpoint(target)?;
    let grace = policy.grace_period()?;
    // --delete is the only way to actually mutate state; otherwise we run as
    // a dry run regardless of whether --dry-run was passed.
    let dry_run = !args.delete;

    // Compute the set of pointers that retention would prune. On a real run
    // we delete them up-front. On a dry run we DON'T delete, but we still
    // exclude them from reachability marking so the report accurately
    // reflects what `--delete` would later remove.
    let prunable_pointers = simulate_prune_pointers(store.as_ref(), &policy).await?;
    if !dry_run {
        for path in &prunable_pointers {
            store.delete(path).await?;
        }
    }
    let pruned: HashSet<&str> = prunable_pointers.iter().map(|s| s.as_str()).collect();

    let mut marked = HashSet::new();
    for prefix in [
        "v1/pointers",
        "v1/calendar/daily",
        "v1/calendar/monthly",
        "v1/calendar/yearly",
        "v1/pins",
    ] {
        for meta in store.list_prefix(prefix).await? {
            if !meta.path.ends_with(".json") {
                continue;
            }
            // Skip pointers we just simulated/performed pruning of so that
            // their referenced manifests/artifacts aren't kept alive on a
            // dry run.
            if pruned.contains(meta.path.as_str()) {
                continue;
            }
            marked.insert(meta.path.clone());
            let bytes = store.get(&meta.path).await?;
            if let Ok(pointer) = serde_json::from_slice::<SignedPointer>(&bytes) {
                marked.insert(pointer.body.manifest_path.clone());
                if let Ok(manifest_bytes) = store.get(&pointer.body.manifest_path).await {
                    if let Ok(manifest) = serde_json::from_slice::<SignedManifest>(&manifest_bytes)
                    {
                        if let Some((dir, _)) = pointer.body.manifest_path.rsplit_once('/') {
                            for artifact in manifest.body.artifacts {
                                marked.insert(format!("{dir}/{}", artifact.path));
                            }
                        }
                    }
                }
            }
        }
    }

    let now = std::time::SystemTime::now();
    let mut deletable = Vec::new();
    for prefix in ["v1/snapshots", "v1/staging"] {
        for meta in store.list_prefix(prefix).await? {
            if marked.contains(&meta.path) {
                continue;
            }
            let old_enough = meta
                .modified
                .and_then(|m| {
                    let st: std::time::SystemTime = m.into();
                    now.duration_since(st).ok()
                })
                .map(|age| age >= grace)
                .unwrap_or(true);
            if old_enough {
                deletable.push(meta.path);
            }
        }
    }
    deletable.sort();
    let mut deleted = Vec::new();
    if !dry_run {
        for path in &deletable {
            store.delete(path).await?;
            deleted.push(path.clone());
        }
    }
    let mut marked_vec: Vec<_> = marked.into_iter().collect();
    marked_vec.sort();
    let report = GcReport {
        generated_at: Utc::now(),
        dry_run,
        marked: marked_vec,
        prunable_pointers,
        deletable,
        deleted,
    };
    let report_path = format!(
        "v1/gc/reports/{}.json",
        Utc::now().format("%Y-%m-%dT%H-%M-%SZ")
    );
    store
        .put(&report_path, &serde_json::to_vec_pretty(&report)?)
        .await?;
    println!("{report_path}");
    Ok(())
}

/// Compute the set of pointer object paths that retention policy would prune.
/// This is a side-effect-free simulation; callers decide whether to apply it.
pub async fn simulate_prune_pointers(
    store: &dyn object_store::ObjectStore,
    policy: &RetentionPolicy,
) -> Result<Vec<String>> {
    let mut prunable = Vec::new();
    if !policy.rolling.keep_latest && store.exists("v1/pointers/latest.json").await? {
        prunable.push("v1/pointers/latest.json".to_string());
    }
    if !policy.rolling.keep_previous && store.exists("v1/pointers/previous.json").await? {
        prunable.push("v1/pointers/previous.json".to_string());
    }
    prunable.extend(
        prune_calendar_prefix(store, "v1/calendar/daily", policy.rolling.keep_daily).await?,
    );
    prunable.extend(
        prune_calendar_prefix(store, "v1/calendar/monthly", policy.monthly.keep_months).await?,
    );
    if policy.yearly.keep_years > 0 {
        prunable.extend(
            prune_calendar_prefix(store, "v1/calendar/yearly", policy.yearly.keep_years).await?,
        );
    }
    prunable.sort();
    prunable.dedup();
    Ok(prunable)
}

async fn prune_calendar_prefix(
    store: &dyn object_store::ObjectStore,
    prefix: &str,
    keep: usize,
) -> Result<Vec<String>> {
    let mut dated: Vec<String> = store
        .list_prefix(prefix)
        .await?
        .into_iter()
        .filter(|meta| meta.path.ends_with(".json"))
        .map(|meta| meta.path)
        .collect();
    dated.sort();
    let keep_set: BTreeSet<String> = dated.iter().rev().take(keep).cloned().collect();
    Ok(dated
        .into_iter()
        .filter(|path| !keep_set.contains(path))
        .collect())
}
