use crate::signing::{self, SignatureBlock, TrustKey};
use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const POINTER_FORMAT: &str = "rusk-state-pointer/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PointerBody {
    pub format: String,
    pub network: String,
    pub role: String,
    pub label: String,
    pub snapshot_id: String,
    pub manifest_path: String,
    pub manifest_sha256: String,
    pub height: u64,
    pub state_root: String,
    pub block_hash: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedPointer {
    #[serde(flatten)]
    pub body: PointerBody,
    pub signature: SignatureBlock,
}

impl SignedPointer {
    pub fn validate_schema(&self) -> Result<()> {
        if self.body.format != POINTER_FORMAT {
            bail!("unsupported pointer format {}", self.body.format);
        }
        if !self.body.manifest_path.starts_with("v1/snapshots/full/") {
            bail!("pointer manifest path must reference immutable full snapshot path");
        }
        Ok(())
    }

    pub fn verify_signature(&self, trusted: &HashMap<String, TrustKey>) -> Result<()> {
        let key = trusted
            .get(&self.signature.key_id)
            .ok_or_else(|| anyhow::anyhow!("untrusted pointer key id {}", self.signature.key_id))?;
        signing::verify_body(&self.body, &self.signature, &key.public_key)
    }
}

pub fn pointer_path(label: &str) -> Result<String> {
    if label == "latest" {
        Ok("v1/pointers/latest.json".to_string())
    } else if label == "previous" {
        Ok("v1/pointers/previous.json".to_string())
    } else if let Some(date) = label.strip_prefix("daily:") {
        Ok(format!("v1/calendar/daily/{date}.json"))
    } else if let Some(month) = label.strip_prefix("monthly:") {
        Ok(format!("v1/calendar/monthly/{month}.json"))
    } else if let Some(year) = label.strip_prefix("yearly:") {
        Ok(format!("v1/calendar/yearly/{year}.json"))
    } else if let Some(pin) = label.strip_prefix("pin:") {
        Ok(format!("v1/pins/{pin}.json"))
    } else {
        bail!("unsupported label {label}");
    }
}

pub fn label_from_selector(
    latest: bool,
    daily: &Option<String>,
    monthly: &Option<String>,
    yearly: &Option<String>,
    pin: &Option<String>,
) -> Result<Option<String>> {
    let mut labels = Vec::new();
    if latest {
        labels.push("latest".to_string());
    }
    if let Some(v) = daily {
        labels.push(format!("daily:{v}"));
    }
    if let Some(v) = monthly {
        labels.push(format!("monthly:{v}"));
    }
    if let Some(v) = yearly {
        labels.push(format!("yearly:{v}"));
    }
    if let Some(v) = pin {
        labels.push(format!("pin:{v}"));
    }
    if labels.len() > 1 {
        bail!("select exactly one pointer label");
    }
    Ok(labels.pop())
}
