use anyhow::{Context, Result};
use serde::Deserialize;
use std::{collections::BTreeSet, fs, path::Path, time::Duration};

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct RetentionPolicy {
    pub rolling: Rolling,
    pub monthly: Monthly,
    pub yearly: Yearly,
    pub gc: GcPolicy,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Rolling {
    pub keep_latest: bool,
    pub keep_previous: bool,
    pub keep_daily: usize,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Monthly {
    pub keep_months: usize,
    pub selection: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Yearly {
    pub keep_years: usize,
    pub selection: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct GcPolicy {
    pub delete_grace_period: String,
    pub dry_run_default: bool,
}

impl RetentionPolicy {
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        Ok(toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?)
    }

    pub fn grace_period(&self) -> Result<Duration> {
        parse_duration(&self.gc.delete_grace_period)
    }
}

pub fn parse_duration(input: &str) -> Result<Duration> {
    let input = input.trim();
    let (num, unit) = input.split_at(
        input
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(input.len()),
    );
    let n: u64 = num.parse()?;
    let seconds = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 60 * 60,
        "d" => n * 24 * 60 * 60,
        _ => anyhow::bail!("unsupported duration unit {unit}"),
    };
    Ok(Duration::from_secs(seconds))
}

#[allow(dead_code)]
pub fn retain_last_dated(mut names: Vec<String>, keep: usize) -> BTreeSet<String> {
    names.sort();
    names.into_iter().rev().take(keep).collect()
}
