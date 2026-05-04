use crate::{
    cli::GcArgs, config::Config, manifest::SignedManifest, object_store, pointer::SignedPointer,
    retention::RetentionPolicy,
};
use anyhow::Result;
use chrono::Utc;
use serde::Serialize;
use std::collections::HashSet;

#[derive(Debug, Serialize)]
struct GcReport {
    generated_at: chrono::DateTime<Utc>,
    dry_run: bool,
    marked: Vec<String>,
    deletable: Vec<String>,
    deleted: Vec<String>,
}

pub async fn run(args: GcArgs) -> Result<()> {
    let cfg = Config::load(&args.config)?;
    let policy = RetentionPolicy::load(&args.policy)?;
    let target = cfg.target(&args.target)?;
    let store = object_store::from_endpoint(target)?;
    let grace = policy.grace_period()?;
    let dry_run = if args.delete { false } else { true };

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
