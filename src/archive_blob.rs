use crate::{
    config::ArchiveBlobConfig,
    hashing::{self, Hashes},
    manifest::{Artifact, SignedManifest, MANIFEST_FORMAT},
    object_store::ObjectStore,
    safe_extract, signing,
    signing::{SignatureBlock, TrustKey},
};
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fs::{self, File},
    io::Write,
    path::{Component, Path, PathBuf},
};
use tar::Builder;
use walkdir::WalkDir;

pub const BLOB_RANGE_FORMAT: &str = "rusk-blob-range/v1";
pub const BLOB_COVERAGE_FORMAT: &str = "rusk-blob-coverage/v1";
pub const ARCHIVE_MANIFEST_FORMAT: &str = "rusk-archive-snapshot/v1";
pub const ARCHIVE_POINTER_FORMAT: &str = "rusk-archive-pointer/v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlobObjectRef {
    pub hash: String,
    pub sha256: String,
    pub size: u64,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlobBlockEntry {
    pub height: u64,
    pub block_hash: String,
    pub blobs: Vec<BlobObjectRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmptyBlockEntry {
    pub height: u64,
    pub block_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlobRangeBody {
    pub format: String,
    pub network: String,
    pub from_height: u64,
    pub to_height: u64,
    pub from_block_hash: String,
    pub to_block_hash: String,
    pub entries: Vec<BlobBlockEntry>,
    pub empty_blocks: Vec<EmptyBlockEntry>,
    pub previous_range_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedBlobRange {
    #[serde(flatten)]
    pub body: BlobRangeBody,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureBlock>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlobCoverageRangeRef {
    pub path: String,
    pub sha256: String,
    pub from_height: u64,
    pub to_height: u64,
    pub from_block_hash: String,
    pub to_block_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlobCoverageBody {
    pub format: String,
    pub network: String,
    pub from_height: u64,
    pub to_height: u64,
    pub to_block_hash: String,
    pub ranges: Vec<BlobCoverageRangeRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedBlobCoverage {
    #[serde(flatten)]
    pub body: BlobCoverageBody,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureBlock>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveStateSnapshotRef {
    pub manifest_path: String,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveBlobCoverageRef {
    pub from_height: u64,
    pub to_height: u64,
    pub to_block_hash: String,
    pub coverage_manifest_path: String,
    pub coverage_manifest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveArtifact {
    pub name: String,
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub blake3: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveManifestBody {
    pub format: String,
    pub network: String,
    pub kind: String,
    pub height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub block_timestamp: String,
    pub state_snapshot: ArchiveStateSnapshotRef,
    pub blob_coverage: ArchiveBlobCoverageRef,
    pub artifacts: Vec<ArchiveArtifact>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedArchiveManifest {
    #[serde(flatten)]
    pub body: ArchiveManifestBody,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureBlock>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchivePointerBody {
    pub format: String,
    pub network: String,
    pub label: String,
    pub manifest_path: String,
    pub manifest_sha256: String,
    pub height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedArchivePointer {
    #[serde(flatten)]
    pub body: ArchivePointerBody,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureBlock>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainBlockDescriptor {
    pub height: u64,
    pub block_hash: String,
    #[serde(default)]
    pub blobs: Vec<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct GraphQlResponse<T> {
    data: Option<T>,
    #[serde(default)]
    errors: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct BlockQueryData {
    block: Option<BlockQueryBlock>,
}

#[derive(Debug, Deserialize)]
struct BlockQueryBlock {
    header: BlockQueryHeader,
    #[serde(default)]
    transactions: Vec<BlockQueryTransaction>,
}

#[derive(Debug, Deserialize)]
struct BlockQueryHeader {
    height: u64,
    hash: String,
}

#[derive(Debug, Deserialize)]
struct BlockQueryTransaction {
    tx: Option<BlockQueryTx>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BlockQueryTx {
    #[serde(default)]
    blob_hashes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PackBlobRangeOptions {
    pub network: String,
    pub from_height: u64,
    pub to_height: u64,
    pub chain_db_dir: PathBuf,
    pub out: PathBuf,
    pub previous_range_sha256: Option<String>,
    pub signing_key: Option<String>,
    pub key_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ExportBlobRangeOptions {
    pub network: String,
    pub rusk_url: String,
    pub from_height: u64,
    pub to_height: u64,
    pub out: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ArchivePackOptions {
    pub network: String,
    pub archive_dir: PathBuf,
    pub height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub block_timestamp: String,
    pub state_manifest_path: String,
    pub state_manifest_sha256: String,
    pub blob_coverage_path: String,
    pub blob_coverage_sha256: String,
    pub blob_coverage_from_height: u64,
    pub blob_coverage_to_height: u64,
    pub blob_coverage_to_block_hash: String,
    pub out: PathBuf,
    pub signing_key: Option<String>,
    pub key_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ArchiveBlobVerifyOptions {
    pub require_signed_blob_ranges: bool,
    pub require_signed_blob_coverage: bool,
    pub require_signed_archive: bool,
    pub require_signed_archive_pointers: bool,
}

impl From<&ArchiveBlobConfig> for ArchiveBlobVerifyOptions {
    fn from(config: &ArchiveBlobConfig) -> Self {
        Self {
            require_signed_blob_ranges: config.require_signed_blob_ranges,
            require_signed_blob_coverage: config.require_signed_blob_coverage,
            require_signed_archive: config.require_signed_archive,
            require_signed_archive_pointers: config.require_signed_archive_pointers,
        }
    }
}

pub struct RestoreArchiveOptions<'a> {
    pub archive_manifest_path: &'a str,
    pub target_height: u64,
    pub trust: &'a HashMap<String, TrustKey>,
    pub verify: ArchiveBlobVerifyOptions,
    pub destination_profile: &'a Path,
    pub archive_dir: &'a Path,
    pub replace: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveCompleteness {
    pub archive_manifest_path: String,
    pub archive_height: u64,
    pub target_height: u64,
    pub state_manifest_path: String,
    pub blob_coverage_path: String,
    pub blob_objects: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageProof {
    pub blob_objects: usize,
    pub block_hashes: BTreeMap<u64, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveRestoreProof {
    pub completeness: ArchiveCompleteness,
    pub destination_profile: String,
    pub archive_dir: String,
    pub restored_state_manifest_path: String,
    pub restored_archive_manifest_path: String,
}

impl SignedBlobRange {
    pub fn validate_schema(&self) -> Result<()> {
        let body = &self.body;
        if body.format != BLOB_RANGE_FORMAT {
            bail!("unsupported blob range format {}", body.format);
        }
        if body.from_height > body.to_height {
            bail!("blob range from_height is greater than to_height");
        }
        require_hex("from_block_hash", &body.from_block_hash, 32)?;
        require_hex("to_block_hash", &body.to_block_hash, 32)?;
        if let Some(prev) = &body.previous_range_sha256 {
            require_hex("previous_range_sha256", prev, 32)?;
        }
        let mut represented = BTreeMap::new();
        for entry in &body.entries {
            require_height_in_range(entry.height, body.from_height, body.to_height)?;
            require_hex("entry block_hash", &entry.block_hash, 32)?;
            if entry.blobs.is_empty() {
                bail!("blob entry at height {} has no blobs", entry.height);
            }
            insert_height(&mut represented, entry.height, &entry.block_hash)?;
            for blob in &entry.blobs {
                validate_blob_ref(blob)?;
            }
        }
        for empty in &body.empty_blocks {
            require_height_in_range(empty.height, body.from_height, body.to_height)?;
            require_hex("empty block_hash", &empty.block_hash, 32)?;
            insert_height(&mut represented, empty.height, &empty.block_hash)?;
        }
        for height in body.from_height..=body.to_height {
            if !represented.contains_key(&height) {
                bail!("blob range missing height {height}");
            }
        }
        if represented.get(&body.from_height) != Some(&body.from_block_hash) {
            bail!("from_block_hash does not match represented first height");
        }
        if represented.get(&body.to_height) != Some(&body.to_block_hash) {
            bail!("to_block_hash does not match represented last height");
        }
        Ok(())
    }

    pub fn verify_signature(&self, trusted: &HashMap<String, TrustKey>) -> Result<()> {
        verify_optional_signature(&self.body, &self.signature, trusted, "blob range")
    }
}

impl SignedBlobCoverage {
    pub fn validate_schema(&self) -> Result<()> {
        let body = &self.body;
        if body.format != BLOB_COVERAGE_FORMAT {
            bail!("unsupported blob coverage format {}", body.format);
        }
        if body.from_height > body.to_height {
            bail!("blob coverage from_height is greater than to_height");
        }
        require_hex("coverage to_block_hash", &body.to_block_hash, 32)?;
        let mut expected = body.from_height;
        let mut previous_to = None;
        for range in &body.ranges {
            validate_object_path(&range.path)?;
            if !range.path.starts_with("v1/blobs/ranges/")
                || !range.path.ends_with("/blob-range.json")
            {
                bail!(
                    "coverage range path is not a blob range manifest: {}",
                    range.path
                );
            }
            require_hex("coverage range sha256", &range.sha256, 32)?;
            require_hex("coverage range from_block_hash", &range.from_block_hash, 32)?;
            require_hex("coverage range to_block_hash", &range.to_block_hash, 32)?;
            if range.from_height != expected {
                bail!(
                    "coverage range gap or overlap: expected from_height {expected}, got {}",
                    range.from_height
                );
            }
            if range.from_height > range.to_height {
                bail!("coverage range from_height is greater than to_height");
            }
            expected = range.to_height.saturating_add(1);
            previous_to = Some(range.to_height);
        }
        if body.ranges.is_empty() {
            bail!("blob coverage must contain at least one range");
        }
        if previous_to != Some(body.to_height) {
            bail!("blob coverage does not end at to_height");
        }
        if body.ranges.last().map(|r| &r.to_block_hash) != Some(&body.to_block_hash) {
            bail!("blob coverage to_block_hash does not match last range");
        }
        Ok(())
    }

    pub fn verify_signature(&self, trusted: &HashMap<String, TrustKey>) -> Result<()> {
        verify_optional_signature(&self.body, &self.signature, trusted, "blob coverage")
    }
}

impl SignedArchiveManifest {
    pub fn validate_schema(&self) -> Result<()> {
        let body = &self.body;
        if body.format != ARCHIVE_MANIFEST_FORMAT {
            bail!("unsupported archive manifest format {}", body.format);
        }
        if body.kind != "archive-full" {
            bail!("unsupported archive manifest kind {}", body.kind);
        }
        require_hex("archive block_hash", &body.block_hash, 32)?;
        require_hex("archive state_root", &body.state_root, 32)?;
        validate_object_path(&body.state_snapshot.manifest_path)?;
        require_hex(
            "state manifest sha256",
            &body.state_snapshot.manifest_sha256,
            32,
        )?;
        validate_object_path(&body.blob_coverage.coverage_manifest_path)?;
        require_hex(
            "blob coverage sha256",
            &body.blob_coverage.coverage_manifest_sha256,
            32,
        )?;
        require_hex(
            "blob coverage to_block_hash",
            &body.blob_coverage.to_block_hash,
            32,
        )?;
        if body.blob_coverage.from_height > body.blob_coverage.to_height {
            bail!("archive blob coverage from_height is greater than to_height");
        }
        if body.artifacts.len() != 1 {
            bail!("archive manifest must contain exactly one artifact");
        }
        let artifact = &body.artifacts[0];
        if artifact.name != "archive-db" {
            bail!("archive artifact name must be archive-db");
        }
        if artifact.path != "archive.tar.zst" {
            bail!("archive artifact path must be archive.tar.zst");
        }
        require_hex("archive artifact sha256", &artifact.sha256, 32)?;
        require_hex("archive artifact blake3", &artifact.blake3, 32)?;
        Ok(())
    }

    pub fn verify_signature(&self, trusted: &HashMap<String, TrustKey>) -> Result<()> {
        verify_optional_signature(&self.body, &self.signature, trusted, "archive manifest")
    }
}

impl SignedArchivePointer {
    pub fn validate_schema(&self) -> Result<()> {
        let body = &self.body;
        if body.format != ARCHIVE_POINTER_FORMAT {
            bail!("unsupported archive pointer format {}", body.format);
        }
        validate_object_path(&body.manifest_path)?;
        if !body.manifest_path.starts_with("v1/archive/checkpoints/")
            || !body.manifest_path.ends_with("/archive-manifest.json")
        {
            bail!("archive pointer manifest path must reference immutable archive checkpoint manifest");
        }
        require_hex("archive pointer manifest sha256", &body.manifest_sha256, 32)?;
        require_hex("archive pointer block_hash", &body.block_hash, 32)?;
        require_hex("archive pointer state_root", &body.state_root, 32)?;
        archive_pointer_path(&body.label)?;
        Ok(())
    }
}

fn require_present_signature(signature: &Option<SignatureBlock>, name: &str) -> Result<()> {
    if signature.is_none() {
        bail!("{name} is unsigned");
    }
    Ok(())
}

pub fn blob_object_path(blake3_hex: &str) -> Result<String> {
    require_hex("blob blake3", blake3_hex, 32)?;
    Ok(format!(
        "v1/blobs/objects/{}/{}/{}",
        &blake3_hex[0..2],
        &blake3_hex[2..4],
        blake3_hex
    ))
}

pub fn blob_range_path(from_height: u64, to_height: u64) -> String {
    format!("v1/blobs/ranges/h{from_height:09}-h{to_height:09}/blob-range.json")
}

pub fn blob_coverage_path(to_height: u64, to_block_hash: &str) -> String {
    let prefix = &to_block_hash[..to_block_hash.len().min(8)];
    format!("v1/blobs/coverage/h{to_height:09}-b_{prefix}.json")
}

pub fn archive_manifest_path(height: u64, block_hash: &str) -> String {
    let prefix = &block_hash[..block_hash.len().min(8)];
    format!("v1/archive/checkpoints/h{height:09}-b_{prefix}/archive-manifest.json")
}

pub fn archive_pointer_path(label: &str) -> Result<String> {
    if label == "latest" {
        Ok("v1/archive/pointers/latest.json".to_string())
    } else if let Some(pin) = label.strip_prefix("pin:") {
        validate_path_component(pin)?;
        Ok(format!("v1/archive/pins/{pin}.json"))
    } else {
        bail!("unsupported archive pointer label {label}; use latest or pin:<name>");
    }
}

pub async fn export_blob_range(opts: ExportBlobRangeOptions) -> Result<PathBuf> {
    if opts.from_height > opts.to_height {
        bail!("from-height must be <= to-height");
    }
    if opts.network.trim().is_empty() {
        bail!("network must not be empty");
    }
    let base = opts.rusk_url.trim_end_matches('/').to_string();
    let client = reqwest::Client::new();
    let descriptor_root = opts.out.join("blob-blocks");
    let blob_root = opts.out.join("blobs");
    fs::create_dir_all(&descriptor_root)?;
    fs::create_dir_all(&blob_root)?;

    for height in opts.from_height..=opts.to_height {
        let block = fetch_block_for_blobs(&client, &base, height).await?;
        if block.header.height != height {
            bail!(
                "GraphQL returned block height {}, expected {height}",
                block.header.height
            );
        }
        require_hex("block hash", &block.header.hash, 32)?;
        let mut blob_hashes = BTreeSet::new();
        for tx in block.transactions {
            if let Some(tx) = tx.tx {
                for blob_hash in tx.blob_hashes {
                    require_hex("blob hash", &blob_hash, 32)?;
                    blob_hashes.insert(blob_hash);
                }
            }
        }

        let mut blob_paths = Vec::new();
        for blob_hash in blob_hashes {
            let rel = PathBuf::from("blobs").join(format!("{blob_hash}.sidecar"));
            let local = opts.out.join(&rel);
            let bytes = fetch_blob_sidecar(&client, &base, &blob_hash).await?;
            if bytes.is_empty() {
                bail!("blob sidecar {blob_hash} was empty");
            }
            fs::write(&local, bytes)?;
            blob_paths.push(rel);
        }

        let descriptor = ChainBlockDescriptor {
            height,
            block_hash: block.header.hash,
            blobs: blob_paths,
        };
        atomic_write_json(
            &descriptor_root.join(format!("h{height:09}.json")),
            &descriptor,
        )?;
    }

    Ok(opts.out)
}

async fn fetch_block_for_blobs(
    client: &reqwest::Client,
    base: &str,
    height: u64,
) -> Result<BlockQueryBlock> {
    let query = format!(
        "{{ block(height: {height}) {{ header {{ height hash }} transactions {{ tx {{ id blobHashes }} }} }} }}"
    );
    let response: GraphQlResponse<BlockQueryData> = client
        .post(format!("{base}/graphql"))
        .json(&serde_json::json!({ "query": query }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    if !response.errors.is_empty() {
        bail!(
            "GraphQL returned errors for block {height}: {:?}",
            response.errors
        );
    }
    response
        .data
        .and_then(|data| data.block)
        .ok_or_else(|| anyhow::anyhow!("GraphQL returned no block at height {height}"))
}

async fn fetch_blob_sidecar(
    client: &reqwest::Client,
    base: &str,
    blob_hash: &str,
) -> Result<Vec<u8>> {
    Ok(client
        .post(format!("{base}/on/blobs:{blob_hash}/hash"))
        .header("accept", "application/octet-stream")
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?
        .to_vec())
}

pub fn pack_blob_range(opts: PackBlobRangeOptions) -> Result<PathBuf> {
    if opts.from_height > opts.to_height {
        bail!("from-height must be <= to-height");
    }
    let mut entries = Vec::new();
    let mut empty_blocks = Vec::new();
    let object_root = opts.out.join("v1/blobs/objects");
    fs::create_dir_all(&object_root)?;

    for height in opts.from_height..=opts.to_height {
        let desc = read_block_descriptor(&opts.chain_db_dir, height)?;
        if desc.height != height {
            bail!(
                "block descriptor height mismatch: expected {height}, got {}",
                desc.height
            );
        }
        require_hex("block_hash", &desc.block_hash, 32)?;
        if desc.blobs.is_empty() {
            empty_blocks.push(EmptyBlockEntry {
                height,
                block_hash: desc.block_hash,
            });
            continue;
        }

        let mut blobs = Vec::new();
        for blob_path in desc.blobs {
            let full = if blob_path.is_absolute() {
                blob_path
            } else {
                opts.chain_db_dir.join(blob_path)
            };
            let hashes = hashing::hash_file(&full)?;
            let object_path = blob_object_path(&hashes.blake3)?;
            let local_object = opts.out.join(&object_path);
            if !local_object.exists() {
                if let Some(parent) = local_object.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::copy(&full, &local_object)
                    .with_context(|| format!("copy blob object {}", full.display()))?;
            }
            blobs.push(BlobObjectRef {
                hash: format!("blake3:{}", hashes.blake3),
                sha256: hashes.sha256,
                size: hashes.size,
                path: object_path,
            });
        }
        entries.push(BlobBlockEntry {
            height,
            block_hash: desc.block_hash,
            blobs,
        });
    }

    let represented: BTreeMap<u64, String> = entries
        .iter()
        .map(|e| (e.height, e.block_hash.clone()))
        .chain(
            empty_blocks
                .iter()
                .map(|e| (e.height, e.block_hash.clone())),
        )
        .collect();
    let body = BlobRangeBody {
        format: BLOB_RANGE_FORMAT.to_string(),
        network: opts.network,
        from_height: opts.from_height,
        to_height: opts.to_height,
        from_block_hash: represented
            .get(&opts.from_height)
            .cloned()
            .context("missing first represented block")?,
        to_block_hash: represented
            .get(&opts.to_height)
            .cloned()
            .context("missing last represented block")?,
        entries,
        empty_blocks,
        previous_range_sha256: opts.previous_range_sha256,
    };
    let signature = sign_if_requested(&body, opts.signing_key.as_deref(), opts.key_id.as_deref())?;
    let range = SignedBlobRange { body, signature };
    range.validate_schema()?;

    let manifest_path = opts
        .out
        .join(blob_range_path(opts.from_height, opts.to_height));
    atomic_write_json(&manifest_path, &range)?;
    Ok(manifest_path)
}

pub fn write_blob_coverage(
    out: &Path,
    network: &str,
    range_manifests: &[PathBuf],
    signing_key: Option<&str>,
    key_id: Option<&str>,
) -> Result<PathBuf> {
    if range_manifests.is_empty() {
        bail!("at least one blob range manifest is required");
    }
    let mut ranges = Vec::new();
    let mut previous_sha = None;
    let mut expected_from = None;
    for path in range_manifests {
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let sha = hashing::sha256_bytes(&bytes);
        let range: SignedBlobRange = serde_json::from_slice(&bytes)?;
        range.validate_schema()?;
        if range.body.network != network {
            bail!("range network mismatch");
        }
        if range.body.previous_range_sha256 != previous_sha {
            bail!("range previous_range_sha256 does not match prior range manifest hash");
        }
        if let Some(expected) = expected_from {
            if range.body.from_height != expected {
                bail!("coverage range gap or overlap");
            }
        }
        expected_from = Some(range.body.to_height + 1);
        previous_sha = Some(sha.clone());
        ranges.push(BlobCoverageRangeRef {
            path: blob_range_path(range.body.from_height, range.body.to_height),
            sha256: sha,
            from_height: range.body.from_height,
            to_height: range.body.to_height,
            from_block_hash: range.body.from_block_hash,
            to_block_hash: range.body.to_block_hash,
        });
    }
    let first = ranges.first().unwrap();
    let last = ranges.last().unwrap();
    let body = BlobCoverageBody {
        format: BLOB_COVERAGE_FORMAT.to_string(),
        network: network.to_string(),
        from_height: first.from_height,
        to_height: last.to_height,
        to_block_hash: last.to_block_hash.clone(),
        ranges,
    };
    let signature = sign_if_requested(&body, signing_key, key_id)?;
    let coverage = SignedBlobCoverage { body, signature };
    coverage.validate_schema()?;
    let path = out.join(blob_coverage_path(
        coverage.body.to_height,
        &coverage.body.to_block_hash,
    ));
    atomic_write_json(&path, &coverage)?;
    Ok(path)
}

pub fn pack_archive(opts: ArchivePackOptions) -> Result<PathBuf> {
    require_hex("archive block_hash", &opts.block_hash, 32)?;
    require_hex("archive state_root", &opts.state_root, 32)?;
    require_hex("state manifest sha256", &opts.state_manifest_sha256, 32)?;
    require_hex("blob coverage sha256", &opts.blob_coverage_sha256, 32)?;
    require_hex(
        "blob coverage to_block_hash",
        &opts.blob_coverage_to_block_hash,
        32,
    )?;

    let manifest_remote = archive_manifest_path(opts.height, &opts.block_hash);
    let manifest_local = opts.out.join(&manifest_remote);
    let checkpoint_dir = manifest_local
        .parent()
        .context("archive manifest has no parent")?;
    fs::create_dir_all(checkpoint_dir)?;
    let archive_path = checkpoint_dir.join("archive.tar.zst");
    create_archive_artifact(&opts.archive_dir, &archive_path)?;
    let hashes = hashing::hash_file(&archive_path)?;
    let body = ArchiveManifestBody {
        format: ARCHIVE_MANIFEST_FORMAT.to_string(),
        network: opts.network,
        kind: "archive-full".to_string(),
        height: opts.height,
        block_hash: opts.block_hash,
        state_root: opts.state_root,
        block_timestamp: opts.block_timestamp,
        state_snapshot: ArchiveStateSnapshotRef {
            manifest_path: opts.state_manifest_path,
            manifest_sha256: opts.state_manifest_sha256,
        },
        blob_coverage: ArchiveBlobCoverageRef {
            from_height: opts.blob_coverage_from_height,
            to_height: opts.blob_coverage_to_height,
            to_block_hash: opts.blob_coverage_to_block_hash,
            coverage_manifest_path: opts.blob_coverage_path,
            coverage_manifest_sha256: opts.blob_coverage_sha256,
        },
        artifacts: vec![ArchiveArtifact {
            name: "archive-db".to_string(),
            path: "archive.tar.zst".to_string(),
            size: hashes.size,
            sha256: hashes.sha256,
            blake3: hashes.blake3,
        }],
        created_at: Utc::now(),
    };
    let signature = sign_if_requested(&body, opts.signing_key.as_deref(), opts.key_id.as_deref())?;
    let manifest = SignedArchiveManifest { body, signature };
    manifest.validate_schema()?;
    atomic_write_json(&manifest_local, &manifest)?;
    Ok(manifest_local)
}

pub async fn publish_blob_range(
    store: &dyn ObjectStore,
    local_range_manifest: &Path,
) -> Result<String> {
    let root = local_artifact_root(local_range_manifest)?;
    let bytes = fs::read(local_range_manifest)
        .with_context(|| format!("read {}", local_range_manifest.display()))?;
    let range: SignedBlobRange = serde_json::from_slice(&bytes)?;
    range.validate_schema()?;
    for blob in range.body.entries.iter().flat_map(|entry| &entry.blobs) {
        let local = root.join(&blob.path);
        verify_local_blob(&local, blob)?;
        put_immutable_or_same(store, &blob.path, &fs::read(&local)?).await?;
    }
    let remote = blob_range_path(range.body.from_height, range.body.to_height);
    put_immutable_or_same(store, &remote, &bytes).await?;
    Ok(remote)
}

#[allow(dead_code)]
pub async fn publish_blob_coverage(
    store: &dyn ObjectStore,
    local_coverage_manifest: &Path,
) -> Result<String> {
    publish_blob_coverage_with_options(
        store,
        local_coverage_manifest,
        &HashMap::new(),
        ArchiveBlobVerifyOptions::default(),
    )
    .await
}

pub async fn publish_blob_coverage_with_options(
    store: &dyn ObjectStore,
    local_coverage_manifest: &Path,
    trust: &HashMap<String, TrustKey>,
    verify: ArchiveBlobVerifyOptions,
) -> Result<String> {
    let bytes = fs::read(local_coverage_manifest)
        .with_context(|| format!("read {}", local_coverage_manifest.display()))?;
    let coverage: SignedBlobCoverage = serde_json::from_slice(&bytes)?;
    coverage.validate_schema()?;
    if verify.require_signed_blob_coverage {
        require_present_signature(&coverage.signature, "blob coverage")?;
        coverage.verify_signature(trust)?;
    }
    verify_coverage_ranges_inner(
        store,
        &coverage,
        if verify.require_signed_blob_ranges {
            Some(trust)
        } else {
            None
        },
    )
    .await?;
    let remote = blob_coverage_path(coverage.body.to_height, &coverage.body.to_block_hash);
    put_immutable_or_same(store, &remote, &bytes).await?;
    Ok(remote)
}

#[allow(dead_code)]
pub async fn publish_archive(
    store: &dyn ObjectStore,
    local_archive_manifest: &Path,
) -> Result<String> {
    publish_archive_with_options(
        store,
        local_archive_manifest,
        &HashMap::new(),
        ArchiveBlobVerifyOptions::default(),
    )
    .await
}

pub async fn publish_archive_with_options(
    store: &dyn ObjectStore,
    local_archive_manifest: &Path,
    trust: &HashMap<String, TrustKey>,
    verify: ArchiveBlobVerifyOptions,
) -> Result<String> {
    let root = local_artifact_root(local_archive_manifest)?;
    let bytes = fs::read(local_archive_manifest)
        .with_context(|| format!("read {}", local_archive_manifest.display()))?;
    let archive: SignedArchiveManifest = serde_json::from_slice(&bytes)?;
    archive.validate_schema()?;
    if verify.require_signed_archive {
        require_present_signature(&archive.signature, "archive manifest")?;
        archive.verify_signature(trust)?;
    }
    let remote = archive_manifest_path(archive.body.height, &archive.body.block_hash);
    let local_remote = local_archive_manifest
        .strip_prefix(&root)
        .with_context(|| {
            format!(
                "{} is not under {}",
                local_archive_manifest.display(),
                root.display()
            )
        })?
        .to_string_lossy()
        .replace('\\', "/");
    if local_remote != remote {
        bail!("archive manifest path does not match checkpoint path");
    }
    let archive_dir = remote
        .rsplit_once('/')
        .map(|(dir, _)| dir)
        .context("archive manifest path has no parent")?;
    for artifact in &archive.body.artifacts {
        let remote_artifact = format!("{archive_dir}/{}", artifact.path);
        let local_artifact = root.join(&remote_artifact);
        verify_local_archive_artifact(&local_artifact, artifact)?;
        put_immutable_or_same(store, &remote_artifact, &fs::read(&local_artifact)?).await?;
    }
    put_immutable_or_same(store, &remote, &bytes).await?;
    Ok(remote)
}

#[allow(dead_code)]
pub async fn promote_archive_manifest(
    store: &dyn ObjectStore,
    manifest_path: &str,
    label: &str,
    signing_key: &str,
    key_id: &str,
    trust: &HashMap<String, TrustKey>,
) -> Result<String> {
    promote_archive_manifest_with_options(
        store,
        manifest_path,
        label,
        signing_key,
        key_id,
        trust,
        ArchiveBlobVerifyOptions::default(),
    )
    .await
}

pub async fn promote_archive_manifest_with_options(
    store: &dyn ObjectStore,
    manifest_path: &str,
    label: &str,
    signing_key: &str,
    key_id: &str,
    trust: &HashMap<String, TrustKey>,
    verify: ArchiveBlobVerifyOptions,
) -> Result<String> {
    validate_object_path(manifest_path)?;
    let bytes = store.get(manifest_path).await?;
    let archive: SignedArchiveManifest = serde_json::from_slice(&bytes)?;
    archive.validate_schema()?;
    if verify.require_signed_archive {
        require_present_signature(&archive.signature, "archive manifest")?;
        archive.verify_signature(trust)?;
    } else if archive.signature.is_some() || !trust.is_empty() {
        archive.verify_signature(trust)?;
    }
    let manifest_sha256 = hashing::sha256_bytes(&bytes);
    let archive_dir = manifest_path
        .rsplit_once('/')
        .map(|(dir, _)| dir)
        .context("archive manifest path has no parent")?;
    for artifact in &archive.body.artifacts {
        let artifact_path = format!("{archive_dir}/{}", artifact.path);
        verify_remote_file_hashes(store, &artifact_path, artifact).await?;
    }

    let body = ArchivePointerBody {
        format: ARCHIVE_POINTER_FORMAT.to_string(),
        network: archive.body.network,
        label: label.to_string(),
        manifest_path: manifest_path.to_string(),
        manifest_sha256,
        height: archive.body.height,
        block_hash: archive.body.block_hash,
        state_root: archive.body.state_root,
        updated_at: Utc::now(),
    };
    let signature = sign_if_requested(&body, Some(signing_key), Some(key_id))?;
    let pointer = SignedArchivePointer { body, signature };
    pointer.validate_schema()?;
    if verify.require_signed_archive_pointers {
        require_present_signature(&pointer.signature, "archive pointer")?;
    }
    let path = archive_pointer_path(label)?;
    store
        .put(&path, &serde_json::to_vec_pretty(&pointer)?)
        .await?;
    Ok(path)
}

#[cfg(test)]
pub async fn publish_local_object_tree(store: &dyn ObjectStore, root: &Path) -> Result<()> {
    let root = root.canonicalize()?;
    for entry in WalkDir::new(&root).follow_links(false) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(&root)?
            .to_string_lossy()
            .replace('\\', "/");
        if !rel.starts_with("v1/") {
            continue;
        }
        put_immutable_or_same(store, &rel, &fs::read(entry.path())?).await?;
    }
    Ok(())
}

#[allow(dead_code)]
pub async fn verify_blob_coverage(
    store: &dyn ObjectStore,
    coverage_path: &str,
    from_height: u64,
    to_height: u64,
    trust: &HashMap<String, TrustKey>,
) -> Result<usize> {
    verify_blob_coverage_with_options(
        store,
        coverage_path,
        from_height,
        to_height,
        trust,
        ArchiveBlobVerifyOptions::default(),
    )
    .await
}

pub async fn verify_blob_coverage_with_options(
    store: &dyn ObjectStore,
    coverage_path: &str,
    from_height: u64,
    to_height: u64,
    trust: &HashMap<String, TrustKey>,
    verify: ArchiveBlobVerifyOptions,
) -> Result<usize> {
    validate_object_path(coverage_path)?;
    let coverage_bytes = store.get(coverage_path).await?;
    let coverage: SignedBlobCoverage = serde_json::from_slice(&coverage_bytes)?;
    coverage.validate_schema()?;
    if verify.require_signed_blob_coverage {
        require_present_signature(&coverage.signature, "blob coverage")?;
    }
    coverage.verify_signature(trust)?;
    if coverage.body.from_height != from_height {
        bail!(
            "coverage starts at {}, expected {from_height}",
            coverage.body.from_height
        );
    }
    if coverage.body.to_height < to_height {
        bail!(
            "coverage ends at {}, expected at least {to_height}",
            coverage.body.to_height
        );
    }
    Ok(verify_coverage_ranges(store, &coverage, trust, verify)
        .await?
        .blob_objects)
}

#[allow(dead_code)]
pub async fn verify_archive_complete(
    store: &dyn ObjectStore,
    archive_manifest_path: &str,
    target_height: u64,
    trust: &HashMap<String, TrustKey>,
) -> Result<ArchiveCompleteness> {
    verify_archive_complete_with_options(
        store,
        archive_manifest_path,
        target_height,
        trust,
        ArchiveBlobVerifyOptions::default(),
    )
    .await
}

pub async fn verify_archive_complete_with_options(
    store: &dyn ObjectStore,
    archive_manifest_path: &str,
    target_height: u64,
    trust: &HashMap<String, TrustKey>,
    verify: ArchiveBlobVerifyOptions,
) -> Result<ArchiveCompleteness> {
    validate_object_path(archive_manifest_path)?;
    let archive_bytes = store.get(archive_manifest_path).await?;
    let archive: SignedArchiveManifest = serde_json::from_slice(&archive_bytes)?;
    archive.validate_schema()?;
    if verify.require_signed_archive {
        require_present_signature(&archive.signature, "archive manifest")?;
    }
    archive.verify_signature(trust)?;
    let archive_dir = archive_manifest_path
        .rsplit_once('/')
        .map(|(dir, _)| dir)
        .context("archive manifest path has no parent")?;
    let archive_artifact = &archive.body.artifacts[0];
    let archive_artifact_path = format!("{archive_dir}/{}", archive_artifact.path);
    verify_remote_file_hashes(store, &archive_artifact_path, archive_artifact).await?;
    let tmp = tempfile::tempdir()?;
    let local_archive = tmp.path().join("archive.tar.zst");
    store
        .get_to_file(&archive_artifact_path, &local_archive)
        .await?;
    safe_extract::validate_archive_safe(&local_archive)?;

    let state_bytes = store
        .get(&archive.body.state_snapshot.manifest_path)
        .await?;
    let state_hash = hashing::sha256_bytes(&state_bytes);
    if state_hash != archive.body.state_snapshot.manifest_sha256 {
        bail!("state manifest sha256 does not match archive manifest reference");
    }
    let state_manifest: SignedManifest = serde_json::from_slice(&state_bytes)?;
    state_manifest.validate_schema()?;
    if state_manifest.body.format != MANIFEST_FORMAT
        || state_manifest.body.network != archive.body.network
        || state_manifest.body.height != archive.body.height
        || state_manifest.body.block_hash != archive.body.block_hash
        || state_manifest.body.state_root != archive.body.state_root
    {
        bail!("state snapshot checkpoint does not match archive checkpoint");
    }

    let coverage_bytes = store
        .get(&archive.body.blob_coverage.coverage_manifest_path)
        .await?;
    let coverage_hash = hashing::sha256_bytes(&coverage_bytes);
    if coverage_hash != archive.body.blob_coverage.coverage_manifest_sha256 {
        bail!("blob coverage manifest sha256 does not match archive manifest reference");
    }
    let coverage: SignedBlobCoverage = serde_json::from_slice(&coverage_bytes)?;
    coverage.validate_schema()?;
    if verify.require_signed_blob_coverage {
        require_present_signature(&coverage.signature, "blob coverage")?;
    }
    coverage.verify_signature(trust)?;
    if coverage.body.network != archive.body.network {
        bail!("blob coverage network does not match archive network");
    }
    if coverage.body.from_height != archive.body.blob_coverage.from_height
        || coverage.body.to_height != archive.body.blob_coverage.to_height
        || coverage.body.to_block_hash != archive.body.blob_coverage.to_block_hash
    {
        bail!("blob coverage metadata does not match archive reference");
    }
    if coverage.body.to_height < target_height || target_height < archive.body.height {
        bail!("blob coverage does not reach requested target height");
    }
    let proof = verify_coverage_ranges(store, &coverage, trust, verify).await?;
    if proof.block_hashes.get(&archive.body.height) != Some(&archive.body.block_hash) {
        bail!("blob coverage block hash at archive height does not match archive checkpoint");
    }
    Ok(ArchiveCompleteness {
        archive_manifest_path: archive_manifest_path.to_string(),
        archive_height: archive.body.height,
        target_height,
        state_manifest_path: archive.body.state_snapshot.manifest_path,
        blob_coverage_path: archive.body.blob_coverage.coverage_manifest_path,
        blob_objects: proof.blob_objects,
    })
}

#[allow(dead_code)]
pub async fn restore_archive_complete(
    store: &dyn ObjectStore,
    archive_manifest_path: &str,
    target_height: u64,
    trust: &HashMap<String, TrustKey>,
    destination_profile: &Path,
    archive_dir: &Path,
    replace: bool,
) -> Result<ArchiveRestoreProof> {
    restore_archive_complete_with_options(
        store,
        RestoreArchiveOptions {
            archive_manifest_path,
            target_height,
            trust,
            verify: ArchiveBlobVerifyOptions::default(),
            destination_profile,
            archive_dir,
            replace,
        },
    )
    .await
}

pub async fn restore_archive_complete_with_options(
    store: &dyn ObjectStore,
    opts: RestoreArchiveOptions<'_>,
) -> Result<ArchiveRestoreProof> {
    let completeness = verify_archive_complete_with_options(
        store,
        opts.archive_manifest_path,
        opts.target_height,
        opts.trust,
        opts.verify,
    )
    .await?;
    let archive_bytes = store.get(opts.archive_manifest_path).await?;
    let archive: SignedArchiveManifest = serde_json::from_slice(&archive_bytes)?;
    let state_bytes = store
        .get(&archive.body.state_snapshot.manifest_path)
        .await?;
    let state_manifest: SignedManifest = serde_json::from_slice(&state_bytes)?;

    let temp_parent = opts
        .destination_profile
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(&temp_parent)?;
    let tmp = tempfile::tempdir_in(&temp_parent)?;

    let state_extract = tmp.path().join("state-snapshot");
    restore_state_snapshot_to_temp(
        store,
        &archive.body.state_snapshot.manifest_path,
        &state_manifest,
        &state_extract,
    )
    .await?;

    let archive_extract = tmp.path().join("archive-snapshot");
    restore_archive_snapshot_to_temp(
        store,
        opts.archive_manifest_path,
        &archive,
        &archive_extract,
    )
    .await?;

    install_restored_archive_profile(
        &state_extract,
        &archive_extract,
        opts.destination_profile,
        opts.archive_dir,
        opts.replace,
    )?;

    Ok(ArchiveRestoreProof {
        completeness,
        destination_profile: opts.destination_profile.display().to_string(),
        archive_dir: opts.archive_dir.display().to_string(),
        restored_state_manifest_path: archive.body.state_snapshot.manifest_path,
        restored_archive_manifest_path: opts.archive_manifest_path.to_string(),
    })
}

async fn restore_state_snapshot_to_temp(
    store: &dyn ObjectStore,
    state_manifest_path: &str,
    state_manifest: &SignedManifest,
    extract_dir: &Path,
) -> Result<()> {
    let state_dir = state_manifest_path
        .rsplit_once('/')
        .map(|(dir, _)| dir)
        .context("state manifest path has no parent")?;
    let artifact = &state_manifest.body.artifacts[0];
    let artifact_path = format!("{state_dir}/{}", artifact.path);
    let archive_path = extract_dir.with_extension("tar.zst");
    store.get_to_file(&artifact_path, &archive_path).await?;
    verify_local_state_artifact(&archive_path, artifact)?;
    safe_extract::extract_zstd_tar_safe(&archive_path, extract_dir)?;
    let state_id = fs::read(extract_dir.join("state/state.id"))?;
    if hex::encode(state_id) != state_manifest.body.state_id {
        bail!("restored state.id does not match state manifest");
    }
    Ok(())
}

async fn restore_archive_snapshot_to_temp(
    store: &dyn ObjectStore,
    archive_manifest_path: &str,
    archive: &SignedArchiveManifest,
    extract_dir: &Path,
) -> Result<()> {
    let archive_dir = archive_manifest_path
        .rsplit_once('/')
        .map(|(dir, _)| dir)
        .context("archive manifest path has no parent")?;
    let artifact = &archive.body.artifacts[0];
    let artifact_path = format!("{archive_dir}/{}", artifact.path);
    let archive_path = extract_dir.with_extension("tar.zst");
    store.get_to_file(&artifact_path, &archive_path).await?;
    verify_local_archive_artifact(&archive_path, artifact)?;
    safe_extract::extract_zstd_tar_safe(&archive_path, extract_dir)?;
    if !extract_dir.join("archive").is_dir() {
        bail!("archive artifact did not contain archive/ directory");
    }
    Ok(())
}

pub async fn mark_archive_blob_reachable(
    store: &dyn ObjectStore,
    marked: &mut HashSet<String>,
) -> Result<()> {
    for prefix in ["v1/archive/pointers", "v1/archive/pins"] {
        for meta in store.list_prefix(prefix).await? {
            if !meta.path.ends_with(".json") {
                continue;
            }
            marked.insert(meta.path.clone());
            let Ok(bytes) = store.get(&meta.path).await else {
                continue;
            };
            let Ok(pointer) = serde_json::from_slice::<SignedArchivePointer>(&bytes) else {
                continue;
            };
            if pointer.validate_schema().is_err() {
                continue;
            }
            mark_archive_manifest_reachable(store, marked, &pointer.body.manifest_path).await?;
        }
    }
    Ok(())
}

async fn mark_archive_manifest_reachable(
    store: &dyn ObjectStore,
    marked: &mut HashSet<String>,
    manifest_path: &str,
) -> Result<()> {
    marked.insert(manifest_path.to_string());
    let Ok(bytes) = store.get(manifest_path).await else {
        return Ok(());
    };
    let Ok(archive) = serde_json::from_slice::<SignedArchiveManifest>(&bytes) else {
        return Ok(());
    };
    let Some((archive_dir, _)) = manifest_path.rsplit_once('/') else {
        return Ok(());
    };
    for artifact in &archive.body.artifacts {
        marked.insert(format!("{archive_dir}/{}", artifact.path));
    }
    marked.insert(archive.body.state_snapshot.manifest_path.clone());
    if let Ok(state_bytes) = store.get(&archive.body.state_snapshot.manifest_path).await {
        if let Ok(state) = serde_json::from_slice::<SignedManifest>(&state_bytes) {
            if let Some((state_dir, _)) = archive.body.state_snapshot.manifest_path.rsplit_once('/')
            {
                for artifact in state.body.artifacts {
                    marked.insert(format!("{state_dir}/{}", artifact.path));
                }
            }
        }
    }
    Ok(())
}

async fn verify_coverage_ranges(
    store: &dyn ObjectStore,
    coverage: &SignedBlobCoverage,
    trust: &HashMap<String, TrustKey>,
    verify: ArchiveBlobVerifyOptions,
) -> Result<CoverageProof> {
    verify_coverage_ranges_inner(
        store,
        coverage,
        if verify.require_signed_blob_ranges {
            Some(trust)
        } else {
            None
        },
    )
    .await
}

async fn verify_coverage_ranges_inner(
    store: &dyn ObjectStore,
    coverage: &SignedBlobCoverage,
    trust: Option<&HashMap<String, TrustKey>>,
) -> Result<CoverageProof> {
    let mut previous_sha = None;
    let mut expected_from = coverage.body.from_height;
    let mut seen_objects = BTreeSet::new();
    let mut block_hashes = BTreeMap::new();
    for range_ref in &coverage.body.ranges {
        if range_ref.from_height != expected_from {
            bail!("coverage range gap or overlap");
        }
        let bytes = store.get(&range_ref.path).await?;
        let actual_sha = hashing::sha256_bytes(&bytes);
        if actual_sha != range_ref.sha256 {
            bail!(
                "coverage range manifest sha256 mismatch for {}",
                range_ref.path
            );
        }
        let range: SignedBlobRange = serde_json::from_slice(&bytes)?;
        range.validate_schema()?;
        if let Some(trust) = trust {
            range.verify_signature(trust)?;
        }
        if range.body.network != coverage.body.network {
            bail!("range network does not match coverage network");
        }
        if range.body.previous_range_sha256 != previous_sha {
            bail!("range previous_range_sha256 chain is broken");
        }
        if range.body.from_height != range_ref.from_height
            || range.body.to_height != range_ref.to_height
            || range.body.from_block_hash != range_ref.from_block_hash
            || range.body.to_block_hash != range_ref.to_block_hash
        {
            bail!("coverage range metadata does not match range manifest");
        }
        let represented = represented_range_blocks(&range)?;
        for height in range.body.from_height..=range.body.to_height {
            let Some(block_hash) = represented.get(&height) else {
                bail!("range missing represented height {height}");
            };
            block_hashes.insert(height, block_hash.clone());
        }
        for blob in range.body.entries.iter().flat_map(|entry| &entry.blobs) {
            verify_remote_blob(store, blob).await?;
            seen_objects.insert(blob.path.clone());
        }
        expected_from = range.body.to_height + 1;
        previous_sha = Some(actual_sha);
    }
    Ok(CoverageProof {
        blob_objects: seen_objects.len(),
        block_hashes,
    })
}

fn represented_range_blocks(range: &SignedBlobRange) -> Result<BTreeMap<u64, String>> {
    let mut represented = BTreeMap::new();
    for entry in &range.body.entries {
        insert_height(&mut represented, entry.height, &entry.block_hash)?;
    }
    for empty in &range.body.empty_blocks {
        insert_height(&mut represented, empty.height, &empty.block_hash)?;
    }
    Ok(represented)
}

fn read_block_descriptor(chain_db_dir: &Path, height: u64) -> Result<ChainBlockDescriptor> {
    let path = chain_db_dir
        .join("blob-blocks")
        .join(format!("h{height:09}.json"));
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

fn create_archive_artifact(archive_dir: &Path, out: &Path) -> Result<()> {
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = File::create(out).with_context(|| format!("create {}", out.display()))?;
    let encoder = zstd::Encoder::new(file, 3)?;
    let mut tar = Builder::new(encoder);
    let source = archive_dir.canonicalize()?;
    let mut entries: Vec<PathBuf> = WalkDir::new(&source)
        .follow_links(false)
        .into_iter()
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .map(|e| e.path().to_path_buf())
        .collect();
    entries.sort();
    for path in entries {
        let rel = path.strip_prefix(&source)?;
        if rel.as_os_str().is_empty() || is_forbidden_archive_input(rel) {
            continue;
        }
        let meta = fs::symlink_metadata(&path)?;
        let archive_path = Path::new("archive").join(rel);
        if meta.is_dir() {
            tar.append_dir(&archive_path, &path)?;
        } else if meta.is_file() {
            tar.append_path_with_name(&path, &archive_path)?;
        } else if meta.file_type().is_symlink() {
            bail!(
                "archive pack refuses symlinks in archive input: {}",
                path.display()
            );
        }
    }
    let encoder = tar.into_inner()?;
    encoder.finish()?;
    Ok(())
}

fn is_forbidden_archive_input(path: &Path) -> bool {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    lower.contains("secret")
        || lower.contains("credential")
        || lower.contains("wallet")
        || lower.contains("signing")
        || lower.ends_with(".log")
        || lower.starts_with("logs/")
        || lower.contains("/logs/")
}

fn validate_blob_ref(blob: &BlobObjectRef) -> Result<()> {
    let hash = blob
        .hash
        .strip_prefix("blake3:")
        .context("blob hash must be blake3:<hex>")?;
    require_hex("blob blake3", hash, 32)?;
    require_hex("blob sha256", &blob.sha256, 32)?;
    validate_object_path(&blob.path)?;
    let expected_path = blob_object_path(hash)?;
    if blob.path != expected_path {
        bail!("blob path does not match content hash");
    }
    Ok(())
}

fn validate_object_path(path: &str) -> Result<()> {
    let rel = Path::new(path);
    if rel.is_absolute()
        || rel
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
    {
        bail!("unsafe object path {path}");
    }
    Ok(())
}

fn validate_path_component(value: &str) -> Result<()> {
    if value.is_empty()
        || value.contains('/')
        || value.contains('\\')
        || value == "."
        || value == ".."
    {
        bail!("unsafe path component {value}");
    }
    Ok(())
}

fn verify_local_blob(path: &Path, blob: &BlobObjectRef) -> Result<()> {
    let hashes = hashing::hash_file(path)?;
    verify_hashes(&hashes, blob.size, &blob.sha256, &blob.hash)
}

async fn verify_remote_blob(store: &dyn ObjectStore, blob: &BlobObjectRef) -> Result<()> {
    let bytes = store.get(&blob.path).await?;
    let sha = hashing::sha256_bytes(&bytes);
    let b3 = blake3::hash(&bytes).to_hex().to_string();
    verify_hashes(
        &Hashes {
            size: bytes.len() as u64,
            sha256: sha,
            blake3: b3.clone(),
        },
        blob.size,
        &blob.sha256,
        &blob.hash,
    )
}

async fn verify_remote_file_hashes(
    store: &dyn ObjectStore,
    path: &str,
    artifact: &ArchiveArtifact,
) -> Result<()> {
    let bytes = store.get(path).await?;
    let sha = hashing::sha256_bytes(&bytes);
    let b3 = blake3::hash(&bytes).to_hex().to_string();
    verify_hashes(
        &Hashes {
            size: bytes.len() as u64,
            sha256: sha,
            blake3: b3.clone(),
        },
        artifact.size,
        &artifact.sha256,
        &format!("blake3:{}", artifact.blake3),
    )
}

fn verify_local_state_artifact(path: &Path, artifact: &Artifact) -> Result<()> {
    let hashes = hashing::hash_file(path)?;
    verify_hashes(
        &hashes,
        artifact.size,
        &artifact.sha256,
        &format!("blake3:{}", artifact.blake3),
    )
}

fn verify_local_archive_artifact(path: &Path, artifact: &ArchiveArtifact) -> Result<()> {
    let hashes = hashing::hash_file(path)?;
    verify_hashes(
        &hashes,
        artifact.size,
        &artifact.sha256,
        &format!("blake3:{}", artifact.blake3),
    )
}

fn install_restored_archive_profile(
    state_extract: &Path,
    archive_extract: &Path,
    destination_profile: &Path,
    archive_dir: &Path,
    replace: bool,
) -> Result<()> {
    let sources = [
        (
            "state",
            state_extract.join("state"),
            destination_profile.join("state"),
        ),
        (
            "chain.db",
            state_extract.join("chain.db"),
            destination_profile.join("chain.db"),
        ),
        (
            "archive",
            archive_extract.join("archive"),
            archive_dir.to_path_buf(),
        ),
    ];
    for (name, source, _) in &sources {
        if !source.is_dir() {
            bail!("restored {name} source directory is missing");
        }
    }
    for (name, _, target) in &sources {
        if target.exists() && !replace {
            bail!(
                "destination {name} already exists at {}; pass --replace to overwrite",
                target.display()
            );
        }
    }

    fs::create_dir_all(destination_profile)?;
    if let Some(parent) = archive_dir.parent() {
        fs::create_dir_all(parent)?;
    }
    let backup = destination_profile.join("backups").join(format!(
        "archive-restore-{}",
        Utc::now().format("%Y%m%dT%H%M%SZ")
    ));
    let mut moved = Vec::new();
    if replace {
        fs::create_dir_all(&backup)?;
        for (name, _, target) in &sources {
            if target.exists() {
                let saved = backup.join(name);
                if let Err(err) = fs::rename(target, &saved) {
                    rollback_restore(&moved);
                    return Err(err)
                        .with_context(|| format!("backup existing {}", target.display()));
                }
                moved.push((saved, target.clone()));
            }
        }
    }

    let mut installed = Vec::new();
    for (_, source, target) in &sources {
        if let Err(err) = copy_dir_all(source, target) {
            for path in &installed {
                let _ = fs::remove_dir_all(path);
            }
            rollback_restore(&moved);
            return Err(err).with_context(|| format!("install {}", target.display()));
        }
        installed.push(target.clone());
    }
    Ok(())
}

fn rollback_restore(moved: &[(PathBuf, PathBuf)]) {
    for (saved, target) in moved.iter().rev() {
        if saved.exists() {
            let _ = fs::remove_dir_all(target);
            let _ = fs::rename(saved, target);
        }
    }
}

fn copy_dir_all(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir_all(target)?;
    for entry in WalkDir::new(source).follow_links(false) {
        let entry = entry?;
        let rel = entry.path().strip_prefix(source)?;
        if rel.as_os_str().is_empty() {
            continue;
        }
        let dest = target.join(rel);
        let meta = fs::symlink_metadata(entry.path())?;
        if meta.is_dir() {
            fs::create_dir_all(&dest)?;
        } else if meta.is_file() {
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(entry.path(), &dest)?;
        } else {
            bail!(
                "refusing to install non-file archive entry {}",
                entry.path().display()
            );
        }
    }
    Ok(())
}

fn verify_hashes(hashes: &Hashes, size: u64, sha256: &str, blake3_hash: &str) -> Result<()> {
    if hashes.size != size {
        bail!("object size mismatch");
    }
    if hashes.sha256 != sha256 {
        bail!("object sha256 mismatch");
    }
    let expected_b3 = blake3_hash.strip_prefix("blake3:").unwrap_or(blake3_hash);
    if hashes.blake3 != expected_b3 {
        bail!("object blake3 mismatch");
    }
    Ok(())
}

fn insert_height(map: &mut BTreeMap<u64, String>, height: u64, block_hash: &str) -> Result<()> {
    if let Some(previous) = map.insert(height, block_hash.to_string()) {
        if previous != block_hash {
            bail!("height {height} represented with conflicting block hashes");
        }
        bail!("height {height} represented more than once");
    }
    Ok(())
}

fn require_height_in_range(height: u64, from: u64, to: u64) -> Result<()> {
    if height < from || height > to {
        bail!("height {height} outside range {from}..={to}");
    }
    Ok(())
}

fn require_hex(name: &str, value: &str, bytes: usize) -> Result<()> {
    let decoded = hex::decode(value).map_err(|_| anyhow::anyhow!("{name} must be hex"))?;
    if decoded.len() != bytes {
        bail!("{name} must be {bytes} bytes");
    }
    Ok(())
}

fn sign_if_requested<T: Serialize>(
    body: &T,
    signing_key: Option<&str>,
    key_id: Option<&str>,
) -> Result<Option<SignatureBlock>> {
    match (signing_key, key_id) {
        (Some(key), Some(id)) => Ok(Some(signing::sign_body(body, id, key)?)),
        (None, None) => Ok(None),
        _ => bail!("signing key and key id must be provided together"),
    }
}

fn verify_optional_signature<T: Serialize>(
    body: &T,
    signature: &Option<SignatureBlock>,
    trusted: &HashMap<String, TrustKey>,
    name: &str,
) -> Result<()> {
    if trusted.is_empty() && signature.is_none() {
        return Ok(());
    }
    let sig = signature
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("{name} is unsigned"))?;
    let key = trusted
        .get(&sig.key_id)
        .ok_or_else(|| anyhow::anyhow!("untrusted {name} key id {}", sig.key_id))?;
    signing::verify_body(body, sig, &key.public_key)
}

fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    let mut file = File::create(&tmp)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.sync_all().ok();
    fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        File::open(parent).and_then(|f| f.sync_all()).ok();
    }
    Ok(())
}

async fn put_immutable_or_same(store: &dyn ObjectStore, path: &str, bytes: &[u8]) -> Result<()> {
    validate_object_path(path)?;
    if store.exists(path).await? {
        let existing = store.get(path).await?;
        if existing != bytes {
            bail!("immutable object already exists with different bytes: {path}");
        }
        return Ok(());
    }
    store.put(path, bytes).await
}

fn local_artifact_root(path: &Path) -> Result<PathBuf> {
    let mut cursor = path.parent().context("path has no parent")?;
    loop {
        if cursor.join("v1").is_dir() {
            return Ok(cursor.to_path_buf());
        }
        cursor = cursor
            .parent()
            .ok_or_else(|| anyhow::anyhow!("could not find local artifact root containing v1/"))?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        archive,
        manifest::{Artifact, ComponentEntry, Components, ManifestBody, Publisher},
        object_store::{file::FileStore, ObjectStore},
        signing::TrustKey,
    };
    use std::path::Path;

    const SEED1: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const SEED2: &str = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
    const NETWORK: &str = "localnet";
    const STATE_ROOT: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const STATE_ID: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    struct Fixture {
        tmp: tempfile::TempDir,
        local_root: PathBuf,
        store: FileStore,
        store_root: PathBuf,
        coverage_path: String,
        archive_manifest_path: String,
        trust: HashMap<String, TrustKey>,
        state_manifest_path: String,
        blob_object_path: String,
    }

    #[tokio::test]
    async fn archive_complete_accepts_aligned_state_archive_and_blob_coverage() {
        let fx = build_fixture().await;
        let proof = verify_archive_complete(&fx.store, &fx.archive_manifest_path, 4, &fx.trust)
            .await
            .unwrap();
        assert_eq!(proof.archive_height, 4);
        assert_eq!(proof.target_height, 4);
        assert_eq!(proof.state_manifest_path, fx.state_manifest_path);
        assert_eq!(proof.blob_coverage_path, fx.coverage_path);
        assert_eq!(proof.blob_objects, 3);
    }

    #[tokio::test]
    async fn archive_complete_checks_checkpoint_hash_inside_extended_coverage() {
        let fx = build_fixture().await;
        extend_coverage_past_archive_with_wrong_checkpoint_hash(&fx);
        assert!(
            verify_archive_complete(&fx.store, &fx.archive_manifest_path, 5, &fx.trust)
                .await
                .unwrap_err()
                .to_string()
                .contains("archive height")
        );
    }

    #[tokio::test]
    async fn archive_restore_installs_matching_state_archive_and_refuses_bad_inputs() {
        let fx = build_fixture().await;
        let destination = fx.tmp.path().join("restored-profile");
        let archive_dir = fx.tmp.path().join("restored-archive");
        let proof = restore_archive_complete(
            &fx.store,
            &fx.archive_manifest_path,
            4,
            &fx.trust,
            &destination,
            &archive_dir,
            false,
        )
        .await
        .unwrap();
        assert_eq!(proof.completeness.archive_height, 4);
        assert_eq!(
            fs::read(destination.join("state/state.txt")).unwrap(),
            b"state"
        );
        assert_eq!(
            fs::read(destination.join("chain.db/chain.txt")).unwrap(),
            b"chain"
        );
        assert_eq!(
            fs::read(archive_dir.join("archive.data")).unwrap(),
            b"archive rows"
        );

        assert!(restore_archive_complete(
            &fx.store,
            &fx.archive_manifest_path,
            4,
            &fx.trust,
            &destination,
            &archive_dir,
            false,
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("already exists"));

        fs::write(destination.join("state/old.txt"), b"old").unwrap();
        restore_archive_complete(
            &fx.store,
            &fx.archive_manifest_path,
            4,
            &fx.trust,
            &destination,
            &archive_dir,
            true,
        )
        .await
        .unwrap();
        assert!(!destination.join("state/old.txt").exists());

        let bad = build_fixture().await;
        bad.store.delete(&bad.blob_object_path).await.unwrap();
        assert!(
            verify_archive_complete(&bad.store, &bad.archive_manifest_path, 4, &bad.trust)
                .await
                .unwrap_err()
                .to_string()
                .contains("read object")
        );
        assert!(restore_archive_complete(
            &bad.store,
            &bad.archive_manifest_path,
            4,
            &bad.trust,
            &bad.tmp.path().join("restore"),
            &bad.tmp.path().join("restore-archive"),
            false,
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("read object"));
    }

    #[tokio::test]
    async fn blob_coverage_rejects_missing_corrupt_gapped_and_mismatched_ranges() {
        let fx = build_fixture().await;
        verify_blob_coverage(&fx.store, &fx.coverage_path, 0, 4, &fx.trust)
            .await
            .unwrap();

        let missing = build_fixture().await;
        missing
            .store
            .delete(&missing.blob_object_path)
            .await
            .unwrap();
        assert!(
            verify_blob_coverage(&missing.store, &missing.coverage_path, 0, 4, &missing.trust)
                .await
                .unwrap_err()
                .to_string()
                .contains("read object")
        );

        let corrupt = build_fixture().await;
        corrupt
            .store
            .put(&corrupt.blob_object_path, b"corrupted")
            .await
            .unwrap();
        assert!(
            verify_blob_coverage(&corrupt.store, &corrupt.coverage_path, 0, 4, &corrupt.trust)
                .await
                .unwrap_err()
                .to_string()
                .contains("mismatch")
        );

        let gapped = build_fixture().await;
        mutate_coverage(&gapped.store_root, &gapped.coverage_path, |coverage| {
            coverage.body.ranges[1].from_height = 4;
        });
        assert!(
            verify_blob_coverage(&gapped.store, &gapped.coverage_path, 0, 4, &gapped.trust)
                .await
                .unwrap_err()
                .to_string()
                .contains("gap")
        );

        let wrong_prev = build_fixture().await;
        let range_path = blob_range_path(3, 4);
        mutate_range(&wrong_prev.store_root, &range_path, |range| {
            range.body.previous_range_sha256 = Some(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            );
        });
        assert!(verify_blob_coverage(
            &wrong_prev.store,
            &wrong_prev.coverage_path,
            0,
            4,
            &wrong_prev.trust
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("sha256"));

        let wrong_block = build_fixture().await;
        mutate_coverage(
            &wrong_block.store_root,
            &wrong_block.coverage_path,
            |coverage| {
                coverage.body.ranges[1].to_block_hash =
                    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
                resign_coverage(coverage);
            },
        );
        assert!(verify_blob_coverage(
            &wrong_block.store,
            &wrong_block.coverage_path,
            0,
            4,
            &wrong_block.trust
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn coverage_publish_writes_manifest_only_after_remote_dependencies_verify() {
        let tmp = tempfile::tempdir().unwrap();
        let local_root = tmp.path().join("local");
        let store_root = tmp.path().join("store");
        let chain = tmp.path().join("chain.db");
        fs::create_dir_all(chain.join("blob-blocks")).unwrap();
        fs::create_dir_all(chain.join("blobs")).unwrap();
        let blob = chain.join("blobs/blob-0.bin");
        fs::write(&blob, b"real blob").unwrap();
        write_descriptor(
            &chain,
            0,
            &[blob.strip_prefix(&chain).unwrap().to_path_buf()],
        );
        write_descriptor(&chain, 1, &[]);

        let range = pack_blob_range(PackBlobRangeOptions {
            network: NETWORK.to_string(),
            from_height: 0,
            to_height: 1,
            chain_db_dir: chain,
            out: local_root.clone(),
            previous_range_sha256: None,
            signing_key: None,
            key_id: None,
        })
        .unwrap();
        let coverage = write_blob_coverage(
            &local_root,
            NETWORK,
            std::slice::from_ref(&range),
            None,
            None,
        )
        .unwrap();
        let store = FileStore::new(&store_root);
        assert!(publish_blob_coverage(&store, &coverage)
            .await
            .unwrap_err()
            .to_string()
            .contains("read object"));

        publish_blob_range(&store, &range).await.unwrap();
        let remote = publish_blob_coverage(&store, &coverage).await.unwrap();
        assert!(remote.starts_with("v1/blobs/coverage/"));
        assert!(store.exists(&remote).await.unwrap());
    }

    #[tokio::test]
    async fn archive_publish_uploads_artifact_before_manifest_and_promote_hashes_artifact() {
        let fx = build_fixture().await;
        let publish_root = fx.tmp.path().join("archive-publish-store");
        let store = FileStore::new(&publish_root);
        let remote = publish_archive(&store, &fx.local_root.join(&fx.archive_manifest_path))
            .await
            .unwrap();
        assert_eq!(remote, fx.archive_manifest_path);
        let artifact_path = remote
            .rsplit_once('/')
            .map(|(dir, _)| format!("{dir}/archive.tar.zst"))
            .unwrap();
        assert!(store.exists(&remote).await.unwrap());
        assert!(store.exists(&artifact_path).await.unwrap());

        let artifact = store.get(&artifact_path).await.unwrap();
        store
            .put(&artifact_path, &vec![0u8; artifact.len()])
            .await
            .unwrap();
        assert!(
            promote_archive_manifest(&store, &remote, "latest", SEED1, "k1", &fx.trust)
                .await
                .unwrap_err()
                .to_string()
                .contains("mismatch")
        );
    }

    #[tokio::test]
    async fn archive_complete_rejects_checkpoint_drift_and_incomplete_coverage() {
        let state_drift = build_fixture().await;
        mutate_archive(
            &state_drift.store_root,
            &state_drift.archive_manifest_path,
            |archive| {
                archive.body.height = 3;
                resign_archive(archive);
            },
        );
        assert!(verify_archive_complete(
            &state_drift.store,
            &state_drift.archive_manifest_path,
            4,
            &state_drift.trust
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("checkpoint"));

        let coverage_short = build_fixture().await;
        mutate_archive(
            &coverage_short.store_root,
            &coverage_short.archive_manifest_path,
            |archive| {
                archive.body.blob_coverage.to_height = 3;
                resign_archive(archive);
            },
        );
        assert!(verify_archive_complete(
            &coverage_short.store,
            &coverage_short.archive_manifest_path,
            4,
            &coverage_short.trust
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("metadata"));

        let wrong_end_hash = build_fixture().await;
        mutate_archive(
            &wrong_end_hash.store_root,
            &wrong_end_hash.archive_manifest_path,
            |archive| {
                archive.body.blob_coverage.to_block_hash =
                    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string();
                resign_archive(archive);
            },
        );
        assert!(verify_archive_complete(
            &wrong_end_hash.store,
            &wrong_end_hash.archive_manifest_path,
            4,
            &wrong_end_hash.trust
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("metadata"));
    }

    #[tokio::test]
    async fn archive_artifact_rejects_corruption_and_unsafe_paths() {
        let corrupt = build_fixture().await;
        let artifact = corrupt
            .archive_manifest_path
            .rsplit_once('/')
            .map(|(dir, _)| format!("{dir}/archive.tar.zst"))
            .unwrap();
        corrupt
            .store
            .put(&artifact, b"not a zstd tar")
            .await
            .unwrap();
        assert!(verify_archive_complete(
            &corrupt.store,
            &corrupt.archive_manifest_path,
            4,
            &corrupt.trust
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("mismatch"));

        let unsafe_fx = build_fixture().await;
        write_unsafe_archive(&unsafe_fx.store_root.join(&artifact));
        mutate_archive(
            &unsafe_fx.store_root,
            &unsafe_fx.archive_manifest_path,
            |archive| {
                let hashes = hashing::hash_file(&unsafe_fx.store_root.join(&artifact)).unwrap();
                archive.body.artifacts[0].size = hashes.size;
                archive.body.artifacts[0].sha256 = hashes.sha256;
                archive.body.artifacts[0].blake3 = hashes.blake3;
                resign_archive(archive);
            },
        );
        assert!(verify_archive_complete(
            &unsafe_fx.store,
            &unsafe_fx.archive_manifest_path,
            4,
            &unsafe_fx.trust
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("unsafe archive path"));
    }

    #[tokio::test]
    async fn tampered_or_wrong_key_manifests_fail_verification() {
        let tampered = build_fixture().await;
        mutate_coverage(&tampered.store_root, &tampered.coverage_path, |coverage| {
            coverage.body.network = "othernet".to_string();
        });
        assert!(verify_blob_coverage(
            &tampered.store,
            &tampered.coverage_path,
            0,
            4,
            &tampered.trust
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("signature"));

        let wrong_key = build_fixture().await;
        let mut trust = HashMap::new();
        trust.insert(
            "k1".to_string(),
            TrustKey {
                scheme: "ed25519".to_string(),
                public_key: signing::public_key_from_secret_spec(SEED2).unwrap(),
            },
        );
        assert!(verify_archive_complete(
            &wrong_key.store,
            &wrong_key.archive_manifest_path,
            4,
            &trust
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("signature"));
    }

    #[tokio::test]
    async fn gc_preserves_blob_namespace_and_deletes_unrooted_archive() {
        let fx = build_fixture().await;
        let orphan_blob =
            "v1/blobs/objects/ff/ff/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        fx.store.put(orphan_blob, b"orphan").await.unwrap();
        let range_path = blob_range_path(0, 2);
        let archive_artifact = fx
            .archive_manifest_path
            .rsplit_once('/')
            .map(|(dir, _)| format!("{dir}/archive.tar.zst"))
            .unwrap();

        run_test_gc(&fx).await;

        assert!(fx.store.exists(orphan_blob).await.unwrap());
        assert!(fx.store.exists(&fx.blob_object_path).await.unwrap());
        assert!(fx.store.exists(&range_path).await.unwrap());
        assert!(fx.store.exists(&fx.coverage_path).await.unwrap());
        assert!(!fx.store.exists(&fx.archive_manifest_path).await.unwrap());
        assert!(!fx.store.exists(&archive_artifact).await.unwrap());
    }

    #[tokio::test]
    async fn gc_keeps_archive_rooted_state_snapshot() {
        let fx = build_fixture().await;
        promote_archive_manifest(
            &fx.store,
            &fx.archive_manifest_path,
            "latest",
            SEED1,
            "k1",
            &fx.trust,
        )
        .await
        .unwrap();
        let state_artifact = fx
            .state_manifest_path
            .rsplit_once('/')
            .map(|(dir, _)| format!("{dir}/snapshot.tar.zst"))
            .unwrap();

        run_test_gc(&fx).await;

        assert!(fx.store.exists(&fx.archive_manifest_path).await.unwrap());
        assert!(fx
            .store
            .exists("v1/archive/pointers/latest.json")
            .await
            .unwrap());
        assert!(fx.store.exists(&fx.state_manifest_path).await.unwrap());
        assert!(fx.store.exists(&state_artifact).await.unwrap());
        assert!(fx.store.exists(&fx.coverage_path).await.unwrap());
        assert!(fx.store.exists(&fx.blob_object_path).await.unwrap());
    }

    #[test]
    fn blob_range_schema_rejects_missing_heights_duplicates_and_unsafe_paths() {
        let mut range = valid_range(0, 1);
        range.body.empty_blocks.clear();
        assert!(range
            .validate_schema()
            .unwrap_err()
            .to_string()
            .contains("missing height"));

        let mut range = valid_range(0, 1);
        range.body.entries[0].height = 1;
        range.body.entries[0].block_hash = block_hash(1);
        assert!(range
            .validate_schema()
            .unwrap_err()
            .to_string()
            .contains("more than once"));

        let mut range = valid_range(0, 1);
        range.body.entries[0].blobs[0].path = "../x".to_string();
        assert!(range
            .validate_schema()
            .unwrap_err()
            .to_string()
            .contains("unsafe"));
    }

    async fn build_fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let local_root = tmp.path().join("local");
        let store_root = tmp.path().join("store");
        let chain = tmp.path().join("chain.db");
        let archive_dir = tmp.path().join("archive-db");
        fs::create_dir_all(chain.join("blob-blocks")).unwrap();
        fs::create_dir_all(chain.join("blobs")).unwrap();
        fs::create_dir_all(&archive_dir).unwrap();
        fs::write(archive_dir.join("archive.data"), b"archive rows").unwrap();

        for height in 0..=4 {
            let mut blobs = Vec::<PathBuf>::new();
            if matches!(height, 1 | 3 | 4) {
                let blob = chain.join("blobs").join(format!("blob-{height}.bin"));
                fs::write(&blob, format!("real blob payload {height}")).unwrap();
                blobs.push(blob.strip_prefix(&chain).unwrap().to_path_buf());
            }
            write_descriptor(&chain, height, &blobs);
        }

        let range1 = pack_blob_range(PackBlobRangeOptions {
            network: NETWORK.to_string(),
            from_height: 0,
            to_height: 2,
            chain_db_dir: chain.clone(),
            out: local_root.clone(),
            previous_range_sha256: None,
            signing_key: Some(SEED1.to_string()),
            key_id: Some("k1".to_string()),
        })
        .unwrap();
        let range1_sha = hashing::sha256_bytes(&fs::read(&range1).unwrap());
        let range2 = pack_blob_range(PackBlobRangeOptions {
            network: NETWORK.to_string(),
            from_height: 3,
            to_height: 4,
            chain_db_dir: chain.clone(),
            out: local_root.clone(),
            previous_range_sha256: Some(range1_sha),
            signing_key: Some(SEED1.to_string()),
            key_id: Some("k1".to_string()),
        })
        .unwrap();
        let coverage = write_blob_coverage(
            &local_root,
            NETWORK,
            &[range1.clone(), range2.clone()],
            Some(SEED1),
            Some("k1"),
        )
        .unwrap();
        let coverage_path = coverage
            .strip_prefix(&local_root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let coverage_hash = hashing::sha256_bytes(&fs::read(&coverage).unwrap());
        let coverage_manifest: SignedBlobCoverage =
            serde_json::from_slice(&fs::read(&coverage).unwrap()).unwrap();

        let state_manifest_path = write_state_snapshot(&local_root).unwrap();
        let state_manifest_hash =
            hashing::sha256_bytes(&fs::read(local_root.join(&state_manifest_path)).unwrap());
        let archive_manifest = pack_archive(ArchivePackOptions {
            network: NETWORK.to_string(),
            archive_dir,
            height: 4,
            block_hash: block_hash(4),
            state_root: STATE_ROOT.to_string(),
            block_timestamp: "2026-05-11T00:00:00Z".to_string(),
            state_manifest_path: state_manifest_path.clone(),
            state_manifest_sha256: state_manifest_hash,
            blob_coverage_path: coverage_path.clone(),
            blob_coverage_sha256: coverage_hash,
            blob_coverage_from_height: coverage_manifest.body.from_height,
            blob_coverage_to_height: coverage_manifest.body.to_height,
            blob_coverage_to_block_hash: coverage_manifest.body.to_block_hash,
            out: local_root.clone(),
            signing_key: Some(SEED1.to_string()),
            key_id: Some("k1".to_string()),
        })
        .unwrap();
        let archive_manifest_path = archive_manifest
            .strip_prefix(&local_root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");

        let store = FileStore::new(&store_root);
        publish_local_object_tree(&store, &local_root)
            .await
            .unwrap();
        let first_range: SignedBlobRange =
            serde_json::from_slice(&fs::read(range1).unwrap()).unwrap();
        let blob_object_path = first_range.body.entries[0].blobs[0].path.clone();
        let mut trust = HashMap::new();
        trust.insert(
            "k1".to_string(),
            TrustKey {
                scheme: "ed25519".to_string(),
                public_key: signing::public_key_from_secret_spec(SEED1).unwrap(),
            },
        );
        Fixture {
            tmp,
            local_root,
            store,
            store_root,
            coverage_path,
            archive_manifest_path,
            trust,
            state_manifest_path,
            blob_object_path,
        }
    }

    async fn run_test_gc(fx: &Fixture) {
        let policy = fx.tmp.path().join("retention.toml");
        fs::write(
            &policy,
            "[rolling]\nkeep_latest=false\nkeep_previous=false\nkeep_daily=0\n[monthly]\nkeep_months=0\nselection='last-good-daily-of-month'\n[yearly]\nkeep_years=0\nselection='december-monthly'\n[gc]\ndelete_grace_period='0s'\ndry_run_default=true\n",
        )
        .unwrap();
        let cfg = fx.tmp.path().join("config.toml");
        fs::write(
            &cfg,
            format!(
                "[target.local]\nkind='file'\npath='{}'\n",
                fx.store_root.display()
            ),
        )
        .unwrap();
        crate::commands::gc::run(crate::cli::GcArgs {
            target: "local".to_string(),
            config: cfg,
            policy,
            dry_run: false,
            delete: true,
        })
        .await
        .unwrap();
    }

    fn write_descriptor(chain: &Path, height: u64, blobs: &[PathBuf]) {
        let desc = ChainBlockDescriptor {
            height,
            block_hash: block_hash(height),
            blobs: blobs.to_vec(),
        };
        fs::write(
            chain.join("blob-blocks").join(format!("h{height:09}.json")),
            serde_json::to_vec_pretty(&desc).unwrap(),
        )
        .unwrap();
    }

    fn write_state_snapshot(root: &Path) -> Result<String> {
        let dir = root.join("v1/snapshots/full/h000000004-sr_11111111");
        let state_dir = root.join("state-input");
        let chain_dir = root.join("chain-input");
        fs::create_dir_all(&state_dir)?;
        fs::create_dir_all(&chain_dir)?;
        fs::write(state_dir.join("state.id"), hex::decode(STATE_ID)?)?;
        fs::write(state_dir.join("state.txt"), b"state")?;
        fs::write(chain_dir.join("chain.txt"), b"chain")?;
        archive::create_snapshot_archive(&state_dir, &chain_dir, &dir.join("snapshot.tar.zst"))?;
        let hashes = hashing::hash_file(&dir.join("snapshot.tar.zst"))?;
        let body = ManifestBody {
            format: MANIFEST_FORMAT.to_string(),
            network: NETWORK.to_string(),
            role: "provisioner".to_string(),
            kind: "full".to_string(),
            height: 4,
            block_hash: block_hash(4),
            block_timestamp: "2026-05-11T00:00:00Z".to_string(),
            state_root: STATE_ROOT.to_string(),
            state_id: STATE_ID.to_string(),
            rusk_version: "test".to_string(),
            created_at: Utc::now(),
            artifacts: vec![Artifact {
                name: "snapshot".to_string(),
                path: "snapshot.tar.zst".to_string(),
                size: hashes.size,
                sha256: hashes.sha256,
                blake3: hashes.blake3,
            }],
            components: Components {
                state: ComponentEntry {
                    included: true,
                    path: Some("state".to_string()),
                },
                chain_db: ComponentEntry {
                    included: true,
                    path: Some("chain.db".to_string()),
                },
                archive: ComponentEntry {
                    included: false,
                    path: None,
                },
            },
            publisher: Some(Publisher {
                name: "test".to_string(),
                key_id: "k1".to_string(),
            }),
        };
        let manifest = SignedManifest {
            signature: Some(signing::sign_body(&body, "k1", SEED1)?),
            body,
        };
        manifest.validate_schema()?;
        fs::write(
            dir.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest)?,
        )?;
        Ok("v1/snapshots/full/h000000004-sr_11111111/manifest.json".to_string())
    }

    fn mutate_coverage<F: FnOnce(&mut SignedBlobCoverage)>(root: &Path, path: &str, mutate: F) {
        let path = root.join(path);
        let mut coverage: SignedBlobCoverage =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        mutate(&mut coverage);
        fs::write(path, serde_json::to_vec_pretty(&coverage).unwrap()).unwrap();
    }

    fn mutate_range<F: FnOnce(&mut SignedBlobRange)>(root: &Path, path: &str, mutate: F) {
        let path = root.join(path);
        let mut range: SignedBlobRange = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        mutate(&mut range);
        fs::write(path, serde_json::to_vec_pretty(&range).unwrap()).unwrap();
    }

    fn mutate_archive<F: FnOnce(&mut SignedArchiveManifest)>(root: &Path, path: &str, mutate: F) {
        let path = root.join(path);
        let mut archive: SignedArchiveManifest =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        mutate(&mut archive);
        fs::write(path, serde_json::to_vec_pretty(&archive).unwrap()).unwrap();
    }

    fn resign_coverage(coverage: &mut SignedBlobCoverage) {
        coverage.signature = Some(signing::sign_body(&coverage.body, "k1", SEED1).unwrap());
    }

    fn resign_archive(archive: &mut SignedArchiveManifest) {
        archive.signature = Some(signing::sign_body(&archive.body, "k1", SEED1).unwrap());
    }

    fn resign_range(range: &mut SignedBlobRange) {
        range.signature = Some(signing::sign_body(&range.body, "k1", SEED1).unwrap());
    }

    fn extend_coverage_past_archive_with_wrong_checkpoint_hash(fx: &Fixture) {
        let coverage_bytes = fs::read(fx.store_root.join(&fx.coverage_path)).unwrap();
        let mut coverage: SignedBlobCoverage = serde_json::from_slice(&coverage_bytes).unwrap();
        let range2_ref = coverage.body.ranges[1].clone();
        let range2_path = fx.store_root.join(&range2_ref.path);
        let mut range2: SignedBlobRange =
            serde_json::from_slice(&fs::read(&range2_path).unwrap()).unwrap();
        let wrong_hash = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        range2.body.entries[1].block_hash = wrong_hash.to_string();
        range2.body.to_block_hash = wrong_hash.to_string();
        resign_range(&mut range2);
        fs::write(&range2_path, serde_json::to_vec_pretty(&range2).unwrap()).unwrap();
        let range2_sha = hashing::sha256_bytes(&fs::read(&range2_path).unwrap());

        let mut range3 = SignedBlobRange {
            body: BlobRangeBody {
                format: BLOB_RANGE_FORMAT.to_string(),
                network: NETWORK.to_string(),
                from_height: 5,
                to_height: 5,
                from_block_hash: block_hash(5),
                to_block_hash: block_hash(5),
                entries: vec![],
                empty_blocks: vec![EmptyBlockEntry {
                    height: 5,
                    block_hash: block_hash(5),
                }],
                previous_range_sha256: Some(range2_sha.clone()),
            },
            signature: None,
        };
        resign_range(&mut range3);
        let range3_path = blob_range_path(5, 5);
        let range3_full = fx.store_root.join(&range3_path);
        fs::create_dir_all(range3_full.parent().unwrap()).unwrap();
        fs::write(&range3_full, serde_json::to_vec_pretty(&range3).unwrap()).unwrap();
        let range3_sha = hashing::sha256_bytes(&fs::read(&range3_full).unwrap());

        coverage.body.ranges[1].sha256 = range2_sha;
        coverage.body.ranges[1].to_block_hash = wrong_hash.to_string();
        coverage.body.ranges.push(BlobCoverageRangeRef {
            path: range3_path,
            sha256: range3_sha,
            from_height: 5,
            to_height: 5,
            from_block_hash: block_hash(5),
            to_block_hash: block_hash(5),
        });
        coverage.body.to_height = 5;
        coverage.body.to_block_hash = block_hash(5);
        resign_coverage(&mut coverage);
        let new_coverage_path = blob_coverage_path(5, &block_hash(5));
        fs::write(
            fx.store_root.join(&new_coverage_path),
            serde_json::to_vec_pretty(&coverage).unwrap(),
        )
        .unwrap();
        let new_coverage_sha =
            hashing::sha256_bytes(&fs::read(fx.store_root.join(&new_coverage_path)).unwrap());

        mutate_archive(&fx.store_root, &fx.archive_manifest_path, |archive| {
            archive.body.blob_coverage.coverage_manifest_path = new_coverage_path;
            archive.body.blob_coverage.coverage_manifest_sha256 = new_coverage_sha;
            archive.body.blob_coverage.to_height = 5;
            archive.body.blob_coverage.to_block_hash = block_hash(5);
            resign_archive(archive);
        });
    }

    fn write_unsafe_archive(path: &Path) {
        let file = File::create(path).unwrap();
        let mut encoder = zstd::Encoder::new(file, 3).unwrap();
        encoder.write_all(&unsafe_tar_bytes()).unwrap();
        encoder.finish().unwrap();
    }

    fn unsafe_tar_bytes() -> Vec<u8> {
        let mut header = [0u8; 512];
        header[..9].copy_from_slice(b"../escape");
        header[100..108].copy_from_slice(b"0000644\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        header[124..136].copy_from_slice(b"00000000004\0");
        header[136..148].copy_from_slice(b"00000000000\0");
        for byte in &mut header[148..156] {
            *byte = b' ';
        }
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum: u32 = header.iter().map(|b| *b as u32).sum();
        let checksum = format!("{checksum:06o}\0 ");
        header[148..156].copy_from_slice(checksum.as_bytes());
        let mut out = Vec::new();
        out.extend_from_slice(&header);
        out.extend_from_slice(b"evil");
        out.resize(1024, 0);
        out.extend_from_slice(&[0u8; 1024]);
        out
    }

    fn valid_range(from: u64, to: u64) -> SignedBlobRange {
        let bytes = b"blob";
        let b3 = blake3::hash(bytes).to_hex().to_string();
        SignedBlobRange {
            body: BlobRangeBody {
                format: BLOB_RANGE_FORMAT.to_string(),
                network: NETWORK.to_string(),
                from_height: from,
                to_height: to,
                from_block_hash: block_hash(from),
                to_block_hash: block_hash(to),
                entries: vec![BlobBlockEntry {
                    height: from,
                    block_hash: block_hash(from),
                    blobs: vec![BlobObjectRef {
                        hash: format!("blake3:{b3}"),
                        sha256: hashing::sha256_bytes(bytes),
                        size: bytes.len() as u64,
                        path: blob_object_path(&b3).unwrap(),
                    }],
                }],
                empty_blocks: ((from + 1)..=to)
                    .map(|height| EmptyBlockEntry {
                        height,
                        block_hash: block_hash(height),
                    })
                    .collect(),
                previous_range_sha256: None,
            },
            signature: None,
        }
    }

    fn block_hash(height: u64) -> String {
        format!("{height:064x}")
    }
}
