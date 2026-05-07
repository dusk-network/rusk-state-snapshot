use crate::{
    cli::RebuildIndexArgs,
    config::Config,
    object_store::{self, ObjectMeta},
};
use anyhow::Result;
use serde::Serialize;
use std::collections::BTreeMap;

pub const INDEX_FORMAT: &str = "rusk-state-snapshot-index/v1";
pub const INDEX_PATH: &str = "v1/index.json";

#[derive(Debug, Serialize)]
pub struct IndexFile {
    pub format: String,
    pub objects: Vec<IndexEntry>,
}

#[derive(Debug, Serialize)]
pub struct IndexEntry {
    pub path: String,
    pub size: u64,
}

pub async fn run(args: RebuildIndexArgs) -> Result<()> {
    let cfg = Config::load(&args.config)?;
    let target = cfg.target(&args.target)?;
    let store = object_store::from_endpoint(target)?;
    let entries = build_index_entries(store.as_ref()).await?;
    let index = IndexFile {
        format: INDEX_FORMAT.to_string(),
        objects: entries,
    };
    let bytes = serde_json::to_vec_pretty(&index)?;
    store.put(INDEX_PATH, &bytes).await?;
    println!("{INDEX_PATH}");
    Ok(())
}

/// Collect every reachable object under `v1/` (excluding the index itself) into
/// a stable, deduplicated, lexicographically-sorted entry list.
pub async fn build_index_entries(store: &dyn object_store::ObjectStore) -> Result<Vec<IndexEntry>> {
    // Use BTreeMap to deduplicate by path and sort.
    let mut map: BTreeMap<String, u64> = BTreeMap::new();
    for prefix in [
        "v1/snapshots",
        "v1/pointers",
        "v1/calendar/daily",
        "v1/calendar/monthly",
        "v1/calendar/yearly",
        "v1/pins",
    ] {
        for ObjectMeta { path, size, .. } in store.list_prefix(prefix).await? {
            // Skip a possibly stale index file under v1/. The index never
            // describes itself.
            if path == INDEX_PATH {
                continue;
            }
            map.insert(path, size);
        }
    }
    Ok(map
        .into_iter()
        .map(|(path, size)| IndexEntry { path, size })
        .collect())
}
