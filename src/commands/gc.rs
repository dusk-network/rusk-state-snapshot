use crate::{
    archive_blob, cli::GcArgs, config::Config, hashing, manifest::SignedManifest, object_store,
    pointer::SignedPointer, retention::RetentionPolicy,
};
use anyhow::{bail, Context, Result};
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

    // Compute (but do NOT yet delete) the pointers retention would prune, and
    // exclude them from reachability marking so the report reflects what a real
    // run would remove. Nothing is deleted until marking and sweep planning
    // fully succeed, so an abort mid-marking leaves the store untouched.
    let prunable_pointers = simulate_prune_pointers(store.as_ref(), &policy).await?;
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
            // Fail closed: a read OR parse error on a listed pointer aborts GC
            // rather than silently under-marking. A corrupt-but-real pointer
            // would otherwise be skipped, leaving its snapshot deletable. (All
            // pointers the tool writes are valid JSON; there is no opaque-marker
            // format under these prefixes.)
            let bytes = store
                .get(&meta.path)
                .await
                .with_context(|| format!("gc: read pointer {}", meta.path))?;
            let pointer: SignedPointer = serde_json::from_slice(&bytes).with_context(|| {
                format!(
                    "gc: parse pointer {}; refusing to GC with an unreadable pointer",
                    meta.path
                )
            })?;
            // Validate the pointer (constrains its manifest_path) before trusting
            // the reference it hands us.
            pointer
                .validate_schema()
                .with_context(|| format!("gc: invalid pointer {}", meta.path))?;
            marked.insert(pointer.body.manifest_path.clone());
            // From here fail closed: a valid pointer's manifest MUST resolve. A
            // transient read error or a corrupt manifest would otherwise leave a
            // live snapshot's artifacts unmarked and deletable under `--delete`.
            let manifest_bytes =
                store
                    .get(&pointer.body.manifest_path)
                    .await
                    .with_context(|| {
                        format!(
                            "gc: read manifest {} referenced by pointer {}",
                            pointer.body.manifest_path, meta.path
                        )
                    })?;
            // Bind the manifest to the pointer: its bytes must match the digest
            // the pointer committed to, or a substituted manifest could redirect
            // reachability.
            let digest = hashing::sha256_bytes(&manifest_bytes);
            if digest != pointer.body.manifest_sha256 {
                bail!(
                    "gc: manifest {} digest {digest} does not match pointer {} ({})",
                    pointer.body.manifest_path,
                    meta.path,
                    pointer.body.manifest_sha256
                );
            }
            let manifest: SignedManifest = serde_json::from_slice(&manifest_bytes)
                .with_context(|| format!("gc: parse manifest {}", pointer.body.manifest_path))?;
            // Validate the schema before trusting its artifact list: a manifest
            // tampered to `artifacts: []` would otherwise mark nothing and leave
            // its real artifact deletable.
            manifest
                .validate_schema()
                .with_context(|| format!("gc: invalid manifest {}", pointer.body.manifest_path))?;
            if let Some((dir, _)) = pointer.body.manifest_path.rsplit_once('/') {
                for artifact in manifest.body.artifacts {
                    marked.insert(format!("{dir}/{}", artifact.path));
                }
            }
        }
    }
    archive_blob::mark_archive_blob_reachable(store.as_ref(), &mut marked).await?;

    let now = std::time::SystemTime::now();
    let mut deletable = Vec::new();
    for prefix in ["v1/snapshots", "v1/staging", "v1/archive"] {
        for meta in store.list_prefix(prefix).await? {
            if marked.contains(&meta.path) {
                continue;
            }
            // Retain when the modified time is unknown: deleting an object we
            // cannot age-check could remove something still within its grace
            // period. Better to keep (possible garbage) than risk data loss.
            let old_enough = meta
                .modified
                .and_then(|m| {
                    let st: std::time::SystemTime = m.into();
                    now.duration_since(st).ok()
                })
                .map(|age| age >= grace)
                .unwrap_or(false);
            if old_enough {
                deletable.push(meta.path);
            }
        }
    }
    deletable.sort();
    let mut deleted = Vec::new();
    if !dry_run {
        // Only now, after marking and sweep planning have succeeded, do we
        // mutate the store: prune the retention pointers, then delete the
        // unreferenced objects.
        for path in &prunable_pointers {
            store.delete(path).await?;
        }
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
