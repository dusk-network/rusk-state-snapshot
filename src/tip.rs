use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tip {
    pub height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub block_timestamp: DateTime<Utc>,
}

impl Tip {
    pub fn validate(&self) -> Result<()> {
        require_32_byte_hex("block_hash", &self.block_hash)?;
        require_32_byte_hex("state_root", &self.state_root)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct TipSource {
    command: Option<String>,
    file: Option<PathBuf>,
}

impl TipSource {
    pub fn new(command: Option<String>, file: Option<PathBuf>, name: &str) -> Result<Self> {
        if command.is_some() && file.is_some() {
            bail!("provide only one of --{name}-command or --{name}-file");
        }
        Ok(Self { command, file })
    }

    pub fn required(command: Option<String>, file: Option<PathBuf>, name: &str) -> Result<Self> {
        let source = Self::new(command, file, name)?;
        if source.command.is_none() && source.file.is_none() {
            bail!("provide --{name}-command or --{name}-file");
        }
        Ok(source)
    }

    pub fn is_configured(&self) -> bool {
        self.command.is_some() || self.file.is_some()
    }

    pub async fn read(&self) -> Result<Tip> {
        match (&self.command, &self.file) {
            (Some(command), None) => read_tip_command(command).await,
            (None, Some(path)) => read_tip_file(path),
            (None, None) => bail!("tip source is not configured"),
            (Some(_), Some(_)) => bail!("tip source cannot use both command and file"),
        }
    }
}

pub fn read_tip_file(path: &Path) -> Result<Tip> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    parse_tip_json(&bytes).with_context(|| format!("parse {}", path.display()))
}

pub async fn read_tip_command(command: &str) -> Result<Tip> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()
        .await
        .with_context(|| format!("run tip command `{command}`"))?;
    if !output.status.success() {
        bail!(
            "tip command failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    parse_tip_json(&output.stdout).with_context(|| "parse tip command output")
}

pub fn parse_tip_json(bytes: &[u8]) -> Result<Tip> {
    let tip: Tip = serde_json::from_slice(bytes)?;
    tip.validate()?;
    Ok(tip)
}

fn require_32_byte_hex(name: &str, value: &str) -> Result<()> {
    let decoded = hex::decode(value).map_err(|_| anyhow::anyhow!("{name} must be hex"))?;
    if decoded.len() != 32 {
        bail!("{name} must be 32 bytes");
    }
    Ok(())
}
