use crate::signing::TrustKey;
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::{collections::HashMap, fs, path::Path};

#[derive(Debug, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub trust: HashMap<String, TrustKey>,
    #[serde(default)]
    pub source: HashMap<String, Endpoint>,
    #[serde(default)]
    pub target: HashMap<String, Endpoint>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Endpoint {
    File {
        path: String,
        #[serde(default)]
        trusted_keys: Vec<String>,
        signing_key: Option<String>,
        signing_key_id: Option<String>,
    },
    Https {
        base_url: String,
        #[serde(default)]
        trusted_keys: Vec<String>,
    },
    #[allow(dead_code)]
    S3 {
        endpoint: String,
        bucket: String,
        #[serde(default)]
        prefix: String,
        #[serde(default = "default_s3_region")]
        region: String,
        access_key: String,
        secret_key: String,
        #[serde(default)]
        trusted_keys: Vec<String>,
        signing_key: Option<String>,
        signing_key_id: Option<String>,
        /// Object size at or above which uploads use multipart. Defaults to 64 MiB.
        #[serde(default)]
        multipart_threshold: Option<u64>,
        /// Part size for multipart uploads. Defaults to 16 MiB. Must be >= 5 MiB
        /// (S3 minimum) for all parts except the last.
        #[serde(default)]
        multipart_part_size: Option<u64>,
    },
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        Ok(toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?)
    }

    pub fn target(&self, name: &str) -> Result<&Endpoint> {
        self.target
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("target {name} not found in config"))
    }

    pub fn source(&self, name: &str) -> Result<&Endpoint> {
        self.source
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("source {name} not found in config"))
    }

    pub fn trusted_for_endpoint(&self, endpoint: &Endpoint) -> Result<HashMap<String, TrustKey>> {
        let ids = endpoint.trusted_keys();
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let mut keys = HashMap::new();
        for id in ids {
            let key = self
                .trust
                .get(id)
                .ok_or_else(|| anyhow::anyhow!("trusted key {id} not defined"))?;
            keys.insert(id.clone(), key.clone());
        }
        Ok(keys)
    }
}

impl Endpoint {
    pub fn trusted_keys(&self) -> &Vec<String> {
        match self {
            Endpoint::File { trusted_keys, .. }
            | Endpoint::Https { trusted_keys, .. }
            | Endpoint::S3 { trusted_keys, .. } => trusted_keys,
        }
    }

    pub fn signing_key(&self) -> Result<&str> {
        match self {
            Endpoint::File { signing_key, .. } | Endpoint::S3 { signing_key, .. } => signing_key
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("target has no signing_key configured")),
            Endpoint::Https { .. } => bail!("https endpoint cannot be a signing target"),
        }
    }

    pub fn signing_key_id(&self) -> Result<&str> {
        match self {
            Endpoint::File { signing_key_id, .. } | Endpoint::S3 { signing_key_id, .. } => {
                signing_key_id
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("target has no signing_key_id configured"))
            }
            Endpoint::Https { .. } => bail!("https endpoint cannot be a signing target"),
        }
    }
}

fn default_s3_region() -> String {
    "us-east-1".to_string()
}
