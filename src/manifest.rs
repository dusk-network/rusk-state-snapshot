use crate::{
    archive::SnapshotCompression,
    signing::{self, SignatureBlock, TrustKey},
};
use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const MANIFEST_FORMAT: &str = "rusk-state-snapshot/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Artifact {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub blake3: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComponentEntry {
    pub included: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Components {
    pub state: ComponentEntry,
    pub chain_db: ComponentEntry,
    pub archive: ComponentEntry,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Publisher {
    pub name: String,
    pub key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestBody {
    pub format: String,
    pub network: String,
    pub role: String,
    pub kind: String,
    pub height: u64,
    pub block_hash: String,
    pub block_timestamp: String,
    pub state_root: String,
    pub state_id: String,
    pub rusk_version: String,
    pub created_at: DateTime<Utc>,
    pub artifacts: Vec<Artifact>,
    pub components: Components,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publisher: Option<Publisher>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedManifest {
    #[serde(flatten)]
    pub body: ManifestBody,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureBlock>,
}

impl SignedManifest {
    pub fn validate_schema(&self) -> Result<()> {
        if self.body.format != MANIFEST_FORMAT {
            bail!("unsupported manifest format {}", self.body.format);
        }
        if self.body.kind != "full" {
            bail!("only full snapshots are implemented in v0");
        }
        if self.body.components.state.path.as_deref() != Some("state") {
            bail!("manifest state component path must be state");
        }
        if self.body.components.chain_db.path.as_deref() != Some("chain.db") {
            bail!("manifest chain_db component path must be chain.db");
        }
        if self.body.components.archive.included {
            bail!("archive component is schema-only future work in v0");
        }
        if self.body.artifacts.len() != 1 {
            bail!("manifest must contain exactly one artifact");
        }
        let artifact = &self.body.artifacts[0];
        SnapshotCompression::from_artifact_path(&artifact.path)?;
        require_hex("block_hash", &self.body.block_hash, 32)?;
        require_hex("state_root", &self.body.state_root, 32)?;
        require_hex("state_id", &self.body.state_id, 32)?;
        require_hex("artifact sha256", &artifact.sha256, 32)?;
        require_hex("artifact blake3", &artifact.blake3, 32)?;
        Ok(())
    }

    pub fn verify_signature(
        &self,
        trusted: &std::collections::HashMap<String, TrustKey>,
    ) -> Result<()> {
        let sig = self
            .signature
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("manifest is unsigned"))?;
        let key = trusted
            .get(&sig.key_id)
            .ok_or_else(|| anyhow::anyhow!("untrusted manifest key id {}", sig.key_id))?;
        signing::verify_body(&self.body, sig, &key.public_key)
    }
}

pub fn snapshot_id(height: u64, state_root: &str) -> String {
    let prefix_len = state_root.len().min(8);
    format!("h{height:09}-sr_{}", &state_root[..prefix_len])
}

fn require_hex(name: &str, value: &str, bytes: usize) -> Result<()> {
    let decoded = hex::decode(value).map_err(|_| anyhow::anyhow!("{name} must be hex"))?;
    if decoded.len() != bytes {
        bail!("{name} must be {bytes} bytes");
    }
    Ok(())
}
