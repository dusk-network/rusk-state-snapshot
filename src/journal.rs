use crate::tip::Tip;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    path::Path,
};

pub const WATCH_JOURNAL_FORMAT: &str = "rusk-state-snapshot-watch-journal/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchJournal {
    pub format: String,
    pub network: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_tip: Option<Tip>,
    #[serde(default)]
    pub captured: Vec<CapturedEntry>,
    #[serde(default)]
    pub missed: Vec<MissedEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest: Option<LatestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedEntry {
    pub label: String,
    pub cutoff: DateTime<Utc>,
    pub snapshot_id: String,
    pub captured_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissedEntry {
    pub label: String,
    pub cutoff: DateTime<Utc>,
    pub reason: String,
    pub marked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatestEntry {
    pub last_promoted_at: DateTime<Utc>,
    pub last_snapshot_id: String,
}

impl WatchJournal {
    pub fn new(network: String, now: DateTime<Utc>) -> Self {
        Self {
            format: WATCH_JOURNAL_FORMAT.to_string(),
            network,
            created_at: now,
            updated_at: now,
            last_seen_tip: None,
            captured: Vec::new(),
            missed: Vec::new(),
            latest: None,
        }
    }

    pub fn has_captured_label(&self, label: &str) -> bool {
        self.captured.iter().any(|entry| entry.label == label)
    }

    pub fn has_missed_label(&self, label: &str) -> bool {
        self.missed.iter().any(|entry| entry.label == label)
    }

    pub fn record_missed(
        &mut self,
        label: String,
        cutoff: DateTime<Utc>,
        reason: impl Into<String>,
        now: DateTime<Utc>,
    ) {
        if self.has_missed_label(&label) || self.has_captured_label(&label) {
            return;
        }
        self.missed.push(MissedEntry {
            label,
            cutoff,
            reason: reason.into(),
            marked_at: now,
        });
    }

    pub fn record_captured(
        &mut self,
        labels: &[String],
        cutoff: DateTime<Utc>,
        snapshot_id: String,
        now: DateTime<Utc>,
    ) {
        for label in labels {
            if self.has_captured_label(label) {
                continue;
            }
            self.captured.push(CapturedEntry {
                label: label.clone(),
                cutoff,
                snapshot_id: snapshot_id.clone(),
                captured_at: now,
            });
        }
    }
}

pub fn load_or_create(path: &Path, network: &str, now: DateTime<Utc>) -> Result<WatchJournal> {
    if path.exists() {
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let journal: WatchJournal =
            serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
        if journal.format != WATCH_JOURNAL_FORMAT {
            anyhow::bail!("unsupported journal format {}", journal.format);
        }
        if journal.network != network {
            anyhow::bail!(
                "journal network mismatch: journal has {}, command requested {network}",
                journal.network
            );
        }
        Ok(journal)
    } else {
        Ok(WatchJournal::new(network.to_string(), now))
    }
}

pub fn save_atomic(path: &Path, journal: &mut WatchJournal, now: DateTime<Utc>) -> Result<()> {
    journal.updated_at = now;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension().and_then(|s| s.to_str()).unwrap_or("json")
    ));
    let bytes = serde_json::to_vec_pretty(journal)?;
    {
        let mut file = File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
        use std::io::Write;
        file.write_all(&bytes)
            .with_context(|| format!("write {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("fsync {}", tmp.display()))?;
    }
    fs::rename(&tmp, path)
        .with_context(|| format!("rename {} to {}", tmp.display(), path.display()))?;
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}
