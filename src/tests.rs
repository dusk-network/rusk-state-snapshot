use crate::{
    archive,
    cli::{GcArgs, PackArgs, PromoteArgs, PublishArgs, RebuildIndexArgs, RestoreArgs, VerifyArgs},
    commands,
    config::Endpoint,
    hashing,
    journal::WatchJournal,
    manifest::{
        Artifact, ComponentEntry, Components, ManifestBody, SignedManifest, MANIFEST_FORMAT,
    },
    object_store::{
        file::FileStore,
        http,
        s3::{self, S3Store, UploadPlan},
        ObjectStore,
    },
    planner::{self, Target, TargetKind},
    pointer::{PointerBody, SignedPointer, POINTER_FORMAT},
    retention, safe_extract, signing,
    tip::{self, Tip},
};
use chrono::{DateTime, Utc};
use std::{fs, path::Path};
use tempfile::TempDir;

const SEED1: &str = "0101010101010101010101010101010101010101010101010101010101010101";
const SEED2: &str = "0202020202020202020202020202020202020202020202020202020202020202";
const HASH1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const HASH2: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn body() -> ManifestBody {
    ManifestBody {
        format: MANIFEST_FORMAT.to_string(),
        network: "mainnet".to_string(),
        role: "provisioner".to_string(),
        kind: "full".to_string(),
        height: 1,
        block_hash: HASH1.to_string(),
        block_timestamp: "2026-05-04T00:00:00Z".to_string(),
        state_root: HASH2.to_string(),
        state_id: HASH1.to_string(),
        rusk_version: "1.6.0".to_string(),
        created_at: Utc::now(),
        artifacts: vec![Artifact {
            name: "state-chain".to_string(),
            path: "snapshot.tar.zst".to_string(),
            size: 1,
            sha256: HASH1.to_string(),
            blake3: HASH2.to_string(),
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
        publisher: None,
    }
}

fn pointer_body() -> PointerBody {
    PointerBody {
        format: POINTER_FORMAT.to_string(),
        network: "mainnet".to_string(),
        role: "provisioner".to_string(),
        label: "latest".to_string(),
        snapshot_id: "h000000001-sr_22222222".to_string(),
        manifest_path: "v1/snapshots/full/h000000001-sr_22222222/manifest.json".to_string(),
        manifest_sha256: HASH1.to_string(),
        height: 1,
        state_root: HASH2.to_string(),
        block_hash: HASH1.to_string(),
        updated_at: Utc::now(),
    }
}

fn trust(seed: &str) -> std::collections::HashMap<String, signing::TrustKey> {
    let mut map = std::collections::HashMap::new();
    map.insert(
        "k1".to_string(),
        signing::TrustKey {
            scheme: "ed25519".to_string(),
            public_key: signing::public_key_from_secret_spec(seed).unwrap(),
        },
    );
    map
}

fn dt(input: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(input)
        .unwrap()
        .with_timezone(&Utc)
}

fn test_tip(timestamp: &str) -> Tip {
    Tip {
        height: 1,
        block_hash: HASH1.to_string(),
        state_root: HASH2.to_string(),
        block_timestamp: dt(timestamp),
    }
}

fn target(label: &str, kind: TargetKind, period: &str, cutoff: &str) -> Target {
    Target {
        label: label.to_string(),
        kind,
        period: period.to_string(),
        cutoff: dt(cutoff),
    }
}

fn make_profile(root: &Path) {
    fs::create_dir_all(root.join("state")).unwrap();
    fs::create_dir_all(root.join("chain.db")).unwrap();
    fs::write(root.join("state/state.id"), [7u8; 32]).unwrap();
    fs::write(root.join("state/value"), b"state").unwrap();
    fs::write(root.join("state/debug.log"), b"app log").unwrap();
    fs::write(root.join("chain.db/value"), b"chain").unwrap();
    fs::write(root.join("chain.db/000001.log"), b"rocksdb wal").unwrap();
}

async fn pack_candidate(tmp: &TempDir, signed: bool) -> std::path::PathBuf {
    let state = tmp.path().join("input-state");
    let chain = tmp.path().join("input-chain.db");
    make_profile(tmp.path());
    fs::rename(tmp.path().join("state"), &state).unwrap();
    fs::rename(tmp.path().join("chain.db"), &chain).unwrap();
    commands::pack::run(PackArgs {
        network: "mainnet".to_string(),
        role: "provisioner".to_string(),
        state_dir: state,
        chain_db_dir: chain,
        height: 1,
        block_hash: HASH1.to_string(),
        state_root: HASH2.to_string(),
        block_timestamp: "2026-05-04T00:00:00Z".to_string(),
        rusk_version: "1.6.0".to_string(),
        out: tmp.path().join("candidates"),
        signing_key: signed.then(|| SEED1.to_string()),
        key_id: Some("k1".to_string()),
        publisher_name: Some("Test".to_string()),
    })
    .await
    .unwrap();
    tmp.path()
        .join("candidates")
        .join("h000000001-sr_22222222")
        .join("manifest.json")
}

#[test]
fn manifest_signature_verifies_and_rejects_tamper_and_wrong_key() {
    let mut body = body();
    let sig = signing::sign_body(&body, "k1", SEED1).unwrap();
    let manifest = SignedManifest {
        body: body.clone(),
        signature: Some(sig),
    };
    manifest.verify_signature(&trust(SEED1)).unwrap();
    let stable_a = signing::canonical_json(&body).unwrap();
    let stable_b = signing::canonical_json(&body).unwrap();
    assert_eq!(stable_a, stable_b);

    body.height = 2;
    let tampered = SignedManifest {
        body,
        signature: manifest.signature.clone(),
    };
    assert!(tampered.verify_signature(&trust(SEED1)).is_err());
    assert!(manifest.verify_signature(&trust(SEED2)).is_err());
}

#[test]
fn pointer_signature_verifies_and_rejects_tamper() {
    let body = pointer_body();
    let pointer = SignedPointer {
        signature: signing::sign_body(&body, "k1", SEED1).unwrap(),
        body,
    };
    pointer.verify_signature(&trust(SEED1)).unwrap();
    let mut tampered = pointer.clone();
    tampered.body.height = 9;
    assert!(tampered.verify_signature(&trust(SEED1)).is_err());
}

#[tokio::test]
async fn pack_creates_manifest_archive_and_validates_state_id() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest_path = pack_candidate(&tmp, false).await;
    let manifest: SignedManifest =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    let artifact_path = manifest_path.parent().unwrap().join("snapshot.tar.zst");
    let hashes = hashing::hash_file(&artifact_path).unwrap();
    assert_eq!(manifest.body.artifacts[0].sha256, hashes.sha256);
    assert_eq!(manifest.body.artifacts[0].blake3, hashes.blake3);
    commands::verify::run(VerifyArgs {
        manifest: manifest_path.to_string_lossy().to_string(),
        config: None,
        trusted_key: vec![],
        require_signature: false,
        network: Some("mainnet".to_string()),
        role: Some("provisioner".to_string()),
    })
    .await
    .unwrap();

    let extract = tempfile::tempdir().unwrap();
    safe_extract::extract_zstd_tar_safe(&artifact_path, extract.path()).unwrap();
    assert!(extract.path().join("chain.db/000001.log").exists());
    assert!(!extract.path().join("state/debug.log").exists());

    let bad = tempfile::tempdir().unwrap();
    fs::create_dir_all(bad.path().join("state")).unwrap();
    fs::create_dir_all(bad.path().join("chain.db")).unwrap();
    assert!(archive::read_state_id(&bad.path().join("state")).is_err());
    fs::write(bad.path().join("state/state.id"), [1u8; 31]).unwrap();
    assert!(archive::read_state_id(&bad.path().join("state")).is_err());
}

#[test]
fn safe_extract_rejects_unsafe_paths_and_symlink_escape() {
    fn make_tar(path: &Path, name: &str, symlink: Option<&str>) {
        let file = fs::File::create(path).unwrap();
        let encoder = zstd::Encoder::new(file, 0).unwrap();
        let mut tar = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        if let Some(target) = symlink {
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_cksum();
            tar.append_link(&mut header, name, target).unwrap();
        } else {
            let bytes = b"x";
            header.set_size(bytes.len() as u64);
            header.set_cksum();
            tar.append_data(&mut header, name, &bytes[..]).unwrap();
        }
        let encoder = tar.into_inner().unwrap();
        encoder.finish().unwrap();
    }

    let tmp = tempfile::tempdir().unwrap();
    assert!(safe_extract::validate_archive_path(Path::new("../x")).is_err());
    assert!(safe_extract::validate_archive_path(Path::new("/x")).is_err());

    let sym = tmp.path().join("sym.tar.zst");
    make_tar(&sym, "state/escape", Some("../../outside"));
    assert!(safe_extract::validate_archive_safe(&sym).is_err());
}

#[tokio::test]
async fn local_object_store_and_publish_idempotency_conflict() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FileStore::new(tmp.path().join("store"));
    store.put("v1/a.txt", b"a").await.unwrap();
    assert_eq!(store.get("v1/a.txt").await.unwrap(), b"a");
    assert!(store.exists("v1/a.txt").await.unwrap());
    assert_eq!(store.list_prefix("v1").await.unwrap().len(), 1);
    store.delete("v1/a.txt").await.unwrap();
    assert!(!store.exists("v1/a.txt").await.unwrap());

    let manifest_path = pack_candidate(&tmp, true).await;
    let cfg = tmp.path().join("config.toml");
    fs::write(
        &cfg,
        format!(
            "[target.local]\nkind='file'\npath='{}'\nsigning_key='{}'\nsigning_key_id='target-k1'\n",
            tmp.path().join("target").display(),
            SEED1
        ),
    )
    .unwrap();
    let args = PublishArgs {
        target: "local".to_string(),
        config: cfg.clone(),
        manifest: manifest_path.clone(),
    };
    commands::publish::run(args).await.unwrap();
    commands::publish::run(PublishArgs {
        target: "local".to_string(),
        config: cfg.clone(),
        manifest: manifest_path.clone(),
    })
    .await
    .unwrap();
    let final_manifest = tmp
        .path()
        .join("target/v1/snapshots/full/h000000001-sr_22222222/manifest.json");
    let final_artifact = tmp
        .path()
        .join("target/v1/snapshots/full/h000000001-sr_22222222/snapshot.tar.zst");
    let manifest_mtime = fs::metadata(&final_manifest).unwrap().modified().unwrap();
    let artifact_mtime = fs::metadata(&final_artifact).unwrap().modified().unwrap();
    assert!(manifest_mtime >= artifact_mtime);
    fs::write(&final_manifest, b"different").unwrap();
    assert!(commands::publish::run(PublishArgs {
        target: "local".to_string(),
        config: cfg,
        manifest: manifest_path,
    })
    .await
    .is_err());
}

#[tokio::test]
async fn restore_verifies_before_replacing_and_keeps_backup() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest_path = pack_candidate(&tmp, true).await;
    let pub_cfg = tmp.path().join("config.toml");
    let public = signing::public_key_from_secret_spec(SEED1).unwrap();
    fs::write(
        &pub_cfg,
        format!(
            "[trust.k1]\nscheme='ed25519'\npublic_key='{public}'\n[trust.target-k1]\nscheme='ed25519'\npublic_key='{public}'\n[source.local]\nkind='file'\npath='{}'\ntrusted_keys=['k1', 'target-k1']\n[target.local]\nkind='file'\npath='{}'\nsigning_key='{}'\nsigning_key_id='target-k1'\n",
            tmp.path().join("target").display(),
            tmp.path().join("target").display(),
            SEED1
        ),
    )
    .unwrap();
    commands::publish::run(PublishArgs {
        target: "local".to_string(),
        config: pub_cfg.clone(),
        manifest: manifest_path,
    })
    .await
    .unwrap();
    commands::promote::run(PromoteArgs {
        target: "local".to_string(),
        config: pub_cfg.clone(),
        manifest_path: "v1/snapshots/full/h000000001-sr_22222222/manifest.json".to_string(),
        label: "latest".to_string(),
        update_previous: true,
        require_signed_manifest: false,
    })
    .await
    .unwrap();
    let pointer_path = tmp.path().join("target/v1/pointers/latest.json");
    let pointer: SignedPointer = serde_json::from_slice(&fs::read(&pointer_path).unwrap()).unwrap();
    assert_eq!(pointer.signature.key_id, "target-k1");

    let dest = tmp.path().join("dest");
    make_profile(&dest);
    fs::write(dest.join("state/old"), b"old").unwrap();
    commands::restore::run(RestoreArgs {
        source: "local".to_string(),
        config: pub_cfg.clone(),
        latest: true,
        monthly: None,
        daily: None,
        yearly: None,
        pin: None,
        manifest_path: None,
        destination_profile: dest.clone(),
        manage_service: None,
        owner: None,
    })
    .await
    .unwrap();
    assert!(dest.join("state/value").exists());
    assert!(dest.join("chain.db/value").exists());
    assert!(dest.join("backups").read_dir().unwrap().next().is_some());

    let mut tampered = pointer;
    tampered.body.manifest_sha256 = HASH2.to_string();
    tampered.signature = signing::sign_body(&tampered.body, "target-k1", SEED1).unwrap();
    fs::write(&pointer_path, serde_json::to_vec_pretty(&tampered).unwrap()).unwrap();
    let before = fs::read(dest.join("state/state.id")).unwrap();
    assert!(commands::restore::run(RestoreArgs {
        source: "local".to_string(),
        config: pub_cfg,
        latest: true,
        monthly: None,
        daily: None,
        yearly: None,
        pin: None,
        manifest_path: None,
        destination_profile: dest.clone(),
        manage_service: None,
        owner: None,
    })
    .await
    .is_err());
    assert_eq!(fs::read(dest.join("state/state.id")).unwrap(), before);
}

#[tokio::test]
async fn gc_dry_run_and_delete_unreferenced_objects() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest_path = pack_candidate(&tmp, true).await;
    let cfg = tmp.path().join("config.toml");
    let target = tmp.path().join("target");
    fs::write(
        &cfg,
        format!(
            "[target.local]\nkind='file'\npath='{}'\nsigning_key='{}'\nsigning_key_id='target-k1'\n",
            target.display(),
            SEED1
        ),
    )
    .unwrap();
    commands::publish::run(PublishArgs {
        target: "local".to_string(),
        config: cfg.clone(),
        manifest: manifest_path,
    })
    .await
    .unwrap();
    fs::create_dir_all(target.join("v1/snapshots/full/old")).unwrap();
    fs::write(
        target.join("v1/snapshots/full/old/snapshot.tar.zst"),
        b"old",
    )
    .unwrap();
    let policy = tmp.path().join("retention.toml");
    fs::write(
        &policy,
        "[rolling]\nkeep_latest=true\nkeep_previous=true\nkeep_daily=5\n[monthly]\nkeep_months=12\nselection='last-good-daily-of-month'\n[yearly]\nkeep_years=0\nselection='december-monthly'\n[gc]\ndelete_grace_period='0s'\ndry_run_default=true\n",
    )
    .unwrap();
    commands::gc::run(GcArgs {
        target: "local".to_string(),
        config: cfg.clone(),
        policy: policy.clone(),
        dry_run: true,
        delete: false,
    })
    .await
    .unwrap();
    assert!(target
        .join("v1/snapshots/full/old/snapshot.tar.zst")
        .exists());
    commands::gc::run(GcArgs {
        target: "local".to_string(),
        config: cfg,
        policy,
        dry_run: false,
        delete: true,
    })
    .await
    .unwrap();
    assert!(!target
        .join("v1/snapshots/full/old/snapshot.tar.zst")
        .exists());
}

#[tokio::test]
async fn file_store_streaming_helpers_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FileStore::new(tmp.path().join("store"));
    let source = tmp.path().join("large.bin");
    fs::write(&source, vec![42u8; 1024 * 64]).unwrap();
    store.put_file("v1/large.bin", &source).await.unwrap();
    assert_eq!(
        store.stat("v1/large.bin").await.unwrap().unwrap().size,
        65536
    );
    let dest = tmp.path().join("out.bin");
    store.get_to_file("v1/large.bin", &dest).await.unwrap();
    assert_eq!(
        hashing::hash_file(&source).unwrap(),
        hashing::hash_file(&dest).unwrap()
    );
}

#[test]
fn s3_backend_builds_keys_under_custom_endpoint_prefix() {
    let s3 = S3Store::new(Endpoint::S3 {
        endpoint: "https://hel1.your-objectstorage.com".to_string(),
        bucket: "operator-bucket".to_string(),
        prefix: "v1".to_string(),
        region: "hel1".to_string(),
        access_key: "access".to_string(),
        secret_key: "secret".to_string(),
        trusted_keys: vec![],
        signing_key: None,
        signing_key_id: None,
        multipart_threshold: None,
        multipart_part_size: None,
    })
    .unwrap();
    assert_eq!(
        s3.object_key("v1/snapshots/full/h000000001-sr_11111111/manifest.json")
            .unwrap(),
        "v1/snapshots/full/h000000001-sr_11111111/manifest.json"
    );
}

#[test]
fn http_index_lists_prefix_without_store_listing() {
    let index = br#"{
      "format": "rusk-state-snapshot-index/v1",
      "objects": [
        {"path":"v1/pointers/latest.json","size":10},
        {"path":"v1/calendar/monthly/2026-05.json","size":20},
        {"path":"v1/snapshots/full/h000000001-sr_11111111/manifest.json","size":30}
      ]
    }"#;
    let monthly = http::list_from_index_bytes("v1/calendar/monthly", index).unwrap();
    assert_eq!(monthly.len(), 1);
    assert_eq!(monthly[0].path, "v1/calendar/monthly/2026-05.json");
}

#[tokio::test]
async fn gc_prunes_calendar_pointers_before_reachability() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("target");
    let cfg = tmp.path().join("config.toml");
    fs::write(
        &cfg,
        format!(
            "[target.local]\nkind='file'\npath='{}'\nsigning_key='{}'\nsigning_key_id='target-k1'\n",
            target.display(),
            SEED1
        ),
    )
    .unwrap();
    for day in 1..=6 {
        let path = target.join(format!("v1/calendar/daily/2026-05-0{day}.json"));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"{}").unwrap();
    }
    for month in 1..=13 {
        let path = target.join(format!("v1/calendar/monthly/2026-{month:02}.json"));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"{}").unwrap();
    }
    for year in 2024..=2026 {
        let path = target.join(format!("v1/calendar/yearly/{year}.json"));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"{}").unwrap();
    }
    let policy = tmp.path().join("retention.toml");
    fs::write(
        &policy,
        "[rolling]\nkeep_latest=true\nkeep_previous=true\nkeep_daily=5\n[monthly]\nkeep_months=12\nselection='last-good-daily-of-month'\n[yearly]\nkeep_years=1\nselection='december-monthly'\n[gc]\ndelete_grace_period='0s'\ndry_run_default=true\n",
    )
    .unwrap();
    commands::gc::run(GcArgs {
        target: "local".to_string(),
        config: cfg,
        policy,
        dry_run: false,
        delete: true,
    })
    .await
    .unwrap();
    assert!(!target.join("v1/calendar/daily/2026-05-01.json").exists());
    assert!(target.join("v1/calendar/daily/2026-05-06.json").exists());
    assert!(!target.join("v1/calendar/monthly/2026-01.json").exists());
    assert!(target.join("v1/calendar/monthly/2026-13.json").exists());
    assert!(!target.join("v1/calendar/yearly/2024.json").exists());
    assert!(target.join("v1/calendar/yearly/2026.json").exists());
}

#[test]
fn retention_duration_parses() {
    assert_eq!(retention::parse_duration("7d").unwrap().as_secs(), 604800);
    let kept = retention::retain_last_dated(
        vec![
            "2026-05-01".to_string(),
            "2026-05-04".to_string(),
            "2026-05-02".to_string(),
            "2026-05-03".to_string(),
        ],
        2,
    );
    assert!(kept.contains("2026-05-04"));
    assert!(kept.contains("2026-05-03"));
}

#[test]
fn planner_builds_desired_completed_calendar_targets() {
    let now = dt("2026-05-08T14:57:00Z");
    let daily = planner::desired_daily_targets(now, 5);
    assert_eq!(
        daily.iter().map(|t| t.period.as_str()).collect::<Vec<_>>(),
        vec![
            "2026-05-03",
            "2026-05-04",
            "2026-05-05",
            "2026-05-06",
            "2026-05-07"
        ]
    );
    assert_eq!(daily.last().unwrap().cutoff, dt("2026-05-08T00:00:00Z"));

    let monthly = planner::desired_monthly_targets(now, 12);
    assert_eq!(monthly.first().unwrap().label, "monthly:2025-05");
    assert_eq!(monthly.last().unwrap().label, "monthly:2026-04");
    assert_eq!(monthly.first().unwrap().cutoff, dt("2025-06-01T00:00:00Z"));
    assert_eq!(monthly.last().unwrap().cutoff, dt("2026-05-01T00:00:00Z"));

    let yearly = planner::desired_yearly_targets(now, 0, Some(dt("2025-01-01T00:00:00Z")));
    assert_eq!(yearly.len(), 1);
    assert_eq!(yearly[0].label, "yearly:2025");
    assert_eq!(yearly[0].cutoff, dt("2026-01-01T00:00:00Z"));
}

#[test]
fn planner_handles_leap_year_and_month_boundaries() {
    let daily = planner::desired_daily_targets(dt("2024-03-01T12:00:00Z"), 1);
    assert_eq!(daily[0].label, "daily:2024-02-29");
    assert_eq!(daily[0].cutoff, dt("2024-03-01T00:00:00Z"));

    let monthly = planner::desired_monthly_targets(dt("2026-01-15T00:00:00Z"), 1);
    assert_eq!(monthly[0].label, "monthly:2025-12");
    assert_eq!(monthly[0].cutoff, dt("2026-01-01T00:00:00Z"));

    let yearly = planner::desired_yearly_targets(dt("2027-01-01T00:00:00Z"), 1, None);
    assert_eq!(yearly[0].label, "yearly:2026");
    assert_eq!(yearly[0].cutoff, dt("2027-01-01T00:00:00Z"));
}

#[test]
fn watch_startup_marks_already_passed_missing_cutoffs_as_missed() {
    let now = dt("2026-05-08T14:57:00Z");
    let desired = planner::desired_monthly_targets(now, 12);
    let mut journal = WatchJournal::new("mainnet".to_string(), now);
    let existing = std::collections::BTreeSet::new();
    commands::watch::classify_startup(
        &mut journal,
        &desired,
        &existing,
        &test_tip("2025-10-08T00:00:00Z"),
        now,
    );
    let missed: Vec<String> = journal.missed.iter().map(|m| m.label.clone()).collect();
    assert_eq!(
        missed,
        vec![
            "monthly:2025-05",
            "monthly:2025-06",
            "monthly:2025-07",
            "monthly:2025-08",
            "monthly:2025-09"
        ]
    );
    assert!(!journal.has_missed_label("monthly:2025-10"));
}

#[test]
fn watch_crossing_groups_same_cutoff_and_marks_late_crossings_missed() {
    let now = dt("2026-01-01T00:30:00Z");
    let desired = vec![
        target(
            "monthly:2025-12",
            TargetKind::Monthly,
            "2025-12",
            "2026-01-01T00:00:00Z",
        ),
        target(
            "yearly:2025",
            TargetKind::Yearly,
            "2025",
            "2026-01-01T00:00:00Z",
        ),
    ];
    let mut journal = WatchJournal::new("mainnet".to_string(), now);
    let existing = std::collections::BTreeSet::new();
    let grouped = commands::watch::classify_crossings(
        &mut journal,
        &desired,
        &existing,
        &test_tip("2025-12-31T23:59:00Z"),
        &test_tip("2026-01-01T00:30:00Z"),
        std::time::Duration::from_secs(3600),
        now,
    );
    assert_eq!(grouped.len(), 1);
    let labels: Vec<String> = grouped
        .values()
        .next()
        .unwrap()
        .iter()
        .map(|t| t.label.clone())
        .collect();
    assert_eq!(labels, vec!["monthly:2025-12", "yearly:2025"]);

    let mut late_journal = WatchJournal::new("mainnet".to_string(), now);
    let late = commands::watch::classify_crossings(
        &mut late_journal,
        &desired[..1],
        &existing,
        &test_tip("2025-12-31T23:59:00Z"),
        &test_tip("2026-01-01T02:00:01Z"),
        std::time::Duration::from_secs(3600),
        now,
    );
    assert!(late.is_empty());
    assert!(late_journal.has_missed_label("monthly:2025-12"));
}

#[test]
fn latest_freshness_and_min_interval_are_enforced() {
    let reference = dt("2026-05-08T14:57:00Z");
    assert!(commands::watch::latest_is_fresh(
        dt("2026-05-07T15:57:00Z"),
        reference,
        std::time::Duration::from_secs(24 * 3600)
    ));
    assert!(!commands::watch::latest_is_fresh(
        dt("2026-05-07T13:57:00Z"),
        reference,
        std::time::Duration::from_secs(24 * 3600)
    ));

    let mut journal = WatchJournal::new("mainnet".to_string(), reference);
    assert!(commands::watch::latest_interval_elapsed(
        &journal,
        std::time::Duration::from_secs(24 * 3600),
        reference
    ));
    journal.latest = Some(crate::journal::LatestEntry {
        last_promoted_at: dt("2026-05-08T00:00:00Z"),
        last_snapshot_id: "h000000001-sr_22222222".to_string(),
    });
    assert!(!commands::watch::latest_interval_elapsed(
        &journal,
        std::time::Duration::from_secs(24 * 3600),
        reference
    ));
}

#[test]
fn journal_atomic_save_and_load_preserves_state() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("watch.json");
    let now = dt("2026-05-08T14:57:00Z");
    let mut journal = WatchJournal::new("mainnet".to_string(), now);
    journal.record_missed(
        "monthly:2025-05".to_string(),
        dt("2025-06-01T00:00:00Z"),
        "test",
        now,
    );
    crate::journal::save_atomic(&path, &mut journal, now).unwrap();
    let loaded = crate::journal::load_or_create(&path, "mainnet", now).unwrap();
    assert!(loaded.has_missed_label("monthly:2025-05"));
}

#[tokio::test]
async fn tip_sources_parse_valid_json_and_reject_invalid_values() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("tip.json");
    fs::write(
        &path,
        format!(
            r#"{{
              "height": 123,
              "block_hash": "{HASH1}",
              "state_root": "{HASH2}",
              "block_timestamp": "2026-05-08T00:00:00Z"
            }}"#
        ),
    )
    .unwrap();
    let parsed = tip::read_tip_file(&path).unwrap();
    assert_eq!(parsed.height, 123);
    assert_eq!(parsed.block_timestamp, dt("2026-05-08T00:00:00Z"));

    fs::write(
        &path,
        format!(
            r#"{{
              "height": 123,
              "block_hash": "abcd",
              "state_root": "{HASH2}",
              "block_timestamp": "2026-05-08T00:00:00Z"
            }}"#
        ),
    )
    .unwrap();
    assert!(tip::read_tip_file(&path).is_err());
    assert!(tip::read_tip_command("false").await.is_err());
}

#[test]
fn capture_refuses_calendar_labels_outside_lag_unless_overridden() {
    let labels = vec!["monthly:2025-12".to_string(), "yearly:2025".to_string()];
    assert!(commands::capture::validate_tip_for_labels(
        &test_tip("2026-01-01T00:30:00Z"),
        &labels,
        Some(dt("2026-01-01T00:00:00Z")),
        std::time::Duration::from_secs(3600),
        false,
    )
    .is_ok());
    assert!(commands::capture::validate_tip_for_labels(
        &test_tip("2026-01-01T02:00:00Z"),
        &labels,
        Some(dt("2026-01-01T00:00:00Z")),
        std::time::Duration::from_secs(3600),
        false,
    )
    .is_err());
    assert!(commands::capture::validate_tip_for_labels(
        &test_tip("2026-01-01T02:00:00Z"),
        &labels,
        Some(dt("2026-01-01T00:00:00Z")),
        std::time::Duration::from_secs(3600),
        true,
    )
    .is_ok());
}

// ---------------------------------------------------------------------------
// Multipart decision logic
// ---------------------------------------------------------------------------

fn test_s3(threshold: Option<u64>, part_size: Option<u64>) -> S3Store {
    S3Store::new(Endpoint::S3 {
        endpoint: "https://hel1.your-objectstorage.com".to_string(),
        bucket: "operator-bucket".to_string(),
        prefix: "v1".to_string(),
        region: "hel1".to_string(),
        access_key: "access".to_string(),
        secret_key: "secret".to_string(),
        trusted_keys: vec![],
        signing_key: None,
        signing_key_id: None,
        multipart_threshold: threshold,
        multipart_part_size: part_size,
    })
    .unwrap()
}

#[test]
fn s3_upload_plan_below_threshold_is_single_put() {
    let store = test_s3(Some(64 * 1024 * 1024), Some(16 * 1024 * 1024));
    assert_eq!(
        store.upload_plan(10 * 1024 * 1024),
        UploadPlan::Single {
            size: 10 * 1024 * 1024
        }
    );
}

#[test]
fn s3_upload_plan_above_threshold_is_multipart_with_correct_parts() {
    let store = test_s3(Some(64 * 1024 * 1024), Some(16 * 1024 * 1024));
    // 100 MiB with 16 MiB parts: ceil(100/16) = 7 parts.
    let plan = store.upload_plan(100 * 1024 * 1024);
    match plan {
        UploadPlan::Multipart {
            size,
            part_size,
            parts,
        } => {
            assert_eq!(size, 100 * 1024 * 1024);
            assert_eq!(part_size, 16 * 1024 * 1024);
            assert_eq!(parts, 7);
        }
        other => panic!("expected multipart, got {other:?}"),
    }
}

#[test]
fn s3_upload_plan_grows_part_size_when_part_count_would_exceed_10000() {
    // Force tiny part size that would otherwise produce far too many parts.
    let store = test_s3(Some(5 * 1024 * 1024), Some(s3::S3_MIN_PART_SIZE));
    // 200 GiB at 5 MiB parts is ~40,960 parts; planner must enlarge parts.
    let size = 200u64 * 1024 * 1024 * 1024;
    let plan = store.upload_plan(size);
    match plan {
        UploadPlan::Multipart {
            size: planned_size,
            part_size,
            parts,
        } => {
            assert_eq!(planned_size, size);
            assert!(parts <= s3::S3_MAX_PARTS, "got {parts} parts");
            assert!(part_size >= s3::S3_MIN_PART_SIZE);
            assert!(part_size * parts >= size);
        }
        other => panic!("expected multipart, got {other:?}"),
    }
}

#[test]
fn s3_construction_rejects_part_size_below_5_mib() {
    let err = S3Store::new(Endpoint::S3 {
        endpoint: "https://example.invalid".to_string(),
        bucket: "b".to_string(),
        prefix: String::new(),
        region: "r".to_string(),
        access_key: "a".to_string(),
        secret_key: "s".to_string(),
        trusted_keys: vec![],
        signing_key: None,
        signing_key_id: None,
        multipart_threshold: None,
        multipart_part_size: Some(1024 * 1024),
    })
    .err()
    .expect("must reject sub-5MiB part size");
    assert!(err.to_string().contains("multipart_part_size"), "{err}");
}

// ---------------------------------------------------------------------------
// S3 ListObjectsV2 pagination parsing
// ---------------------------------------------------------------------------

#[test]
fn s3_list_pagination_parses_truncated_and_final_pages() {
    let truncated = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>opaque-token-1</NextContinuationToken>
  <Contents><Key>v1/snapshots/full/a/manifest.json</Key><Size>10</Size></Contents>
  <Contents><Key>v1/snapshots/full/a/snapshot.tar.zst</Key><Size>20</Size></Contents>
</ListBucketResult>"#;
    let (entries, next) = s3::parse_list_page(truncated);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].0, "v1/snapshots/full/a/manifest.json");
    assert_eq!(entries[0].1, 10);
    assert_eq!(next.as_deref(), Some("opaque-token-1"));

    let final_page = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <IsTruncated>false</IsTruncated>
  <Contents><Key>v1/snapshots/full/b/manifest.json</Key><Size>30</Size></Contents>
</ListBucketResult>"#;
    let (entries, next) = s3::parse_list_page(final_page);
    assert_eq!(entries.len(), 1);
    assert!(next.is_none());
}

// ---------------------------------------------------------------------------
// GC dry-run pointer prune simulation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn gc_dry_run_excludes_simulated_pruned_pointers_from_reachability() {
    // If retention would prune a daily pointer, dry-run must NOT keep that
    // pointer's manifest/artifact alive in the report. Otherwise operators
    // would think the artifact was protected when in fact a real run would
    // delete it next.
    let tmp = tempfile::tempdir().unwrap();
    let manifest_path = pack_candidate(&tmp, true).await;
    let cfg = tmp.path().join("config.toml");
    let target = tmp.path().join("target");
    fs::write(
        &cfg,
        format!(
            "[target.local]\nkind='file'\npath='{}'\nsigning_key='{}'\nsigning_key_id='target-k1'\n",
            target.display(),
            SEED1
        ),
    )
    .unwrap();
    commands::publish::run(PublishArgs {
        target: "local".to_string(),
        config: cfg.clone(),
        manifest: manifest_path,
    })
    .await
    .unwrap();
    // Promote latest so the snapshot becomes reachable via a real pointer.
    commands::promote::run(PromoteArgs {
        target: "local".to_string(),
        config: cfg.clone(),
        manifest_path: "v1/snapshots/full/h000000001-sr_22222222/manifest.json".to_string(),
        label: "latest".to_string(),
        update_previous: false,
        require_signed_manifest: false,
    })
    .await
    .unwrap();
    // Create extra daily calendar pointers older than what retention keeps.
    for day in 1..=4 {
        let path = target.join(format!("v1/calendar/daily/2026-05-0{day}.json"));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"{}").unwrap();
    }
    // Policy keeps only 2 dailies: the older 2 should appear as prunable.
    let policy = tmp.path().join("retention.toml");
    fs::write(
        &policy,
        "[rolling]\nkeep_latest=true\nkeep_previous=true\nkeep_daily=2\n[monthly]\nkeep_months=12\nselection='last-good-daily-of-month'\n[yearly]\nkeep_years=0\nselection='december-monthly'\n[gc]\ndelete_grace_period='0s'\ndry_run_default=true\n",
    )
    .unwrap();
    commands::gc::run(GcArgs {
        target: "local".to_string(),
        config: cfg.clone(),
        policy: policy.clone(),
        dry_run: true,
        delete: false,
    })
    .await
    .unwrap();

    // Find the dry-run report and confirm the pruned dailies appear in
    // prunable_pointers and are NOT present in marked.
    let mut report_path = None;
    for entry in fs::read_dir(target.join("v1/gc/reports")).unwrap() {
        let entry = entry.unwrap();
        if entry.path().extension().and_then(|s| s.to_str()) == Some("json") {
            report_path = Some(entry.path());
        }
    }
    let report_path = report_path.expect("gc report must be written");
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(&report_path).unwrap()).unwrap();
    assert_eq!(report["dry_run"], serde_json::Value::Bool(true));
    let prunable: Vec<String> = report["prunable_pointers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    let marked: Vec<String> = report["marked"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(prunable
        .iter()
        .any(|p| p == "v1/calendar/daily/2026-05-01.json"));
    for pruned in &prunable {
        assert!(
            !marked.contains(pruned),
            "marked must not include simulated-pruned pointer {pruned}"
        );
    }
}

// ---------------------------------------------------------------------------
// Index rebuild
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rebuild_index_lists_all_v1_objects_and_excludes_self() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest_path = pack_candidate(&tmp, true).await;
    let cfg = tmp.path().join("config.toml");
    let target = tmp.path().join("target");
    fs::write(
        &cfg,
        format!(
            "[target.local]\nkind='file'\npath='{}'\nsigning_key='{}'\nsigning_key_id='target-k1'\n",
            target.display(),
            SEED1
        ),
    )
    .unwrap();
    commands::publish::run(PublishArgs {
        target: "local".to_string(),
        config: cfg.clone(),
        manifest: manifest_path,
    })
    .await
    .unwrap();
    commands::promote::run(PromoteArgs {
        target: "local".to_string(),
        config: cfg.clone(),
        manifest_path: "v1/snapshots/full/h000000001-sr_22222222/manifest.json".to_string(),
        label: "latest".to_string(),
        update_previous: false,
        require_signed_manifest: false,
    })
    .await
    .unwrap();
    commands::index::run(RebuildIndexArgs {
        target: "local".to_string(),
        config: cfg.clone(),
    })
    .await
    .unwrap();
    let index_bytes = fs::read(target.join("v1/index.json")).unwrap();
    let index: serde_json::Value = serde_json::from_slice(&index_bytes).unwrap();
    assert_eq!(index["format"], "rusk-state-snapshot-index/v1");
    let paths: Vec<String> = index["objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["path"].as_str().unwrap().to_string())
        .collect();
    assert!(paths.contains(&"v1/pointers/latest.json".to_string()));
    assert!(paths.contains(&"v1/snapshots/full/h000000001-sr_22222222/manifest.json".to_string()));
    assert!(
        paths.contains(&"v1/snapshots/full/h000000001-sr_22222222/snapshot.tar.zst".to_string())
    );
    // The index never describes itself.
    assert!(!paths.contains(&"v1/index.json".to_string()));
    // Sizes are recorded.
    let manifest_entry = index["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["path"] == "v1/pointers/latest.json")
        .unwrap();
    assert!(manifest_entry["size"].as_u64().unwrap() > 0);
}

// ---------------------------------------------------------------------------
// Promote artifact validation + signed-manifest requirement
// ---------------------------------------------------------------------------

#[tokio::test]
async fn promote_requires_signed_manifest_and_artifact_existence() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest_path = pack_candidate(&tmp, true).await;
    let cfg = tmp.path().join("config.toml");
    let target = tmp.path().join("target");
    let public = signing::public_key_from_secret_spec(SEED1).unwrap();
    fs::write(
        &cfg,
        format!(
            "[trust.k1]\nscheme='ed25519'\npublic_key='{public}'\n[target.local]\nkind='file'\npath='{}'\nsigning_key='{}'\nsigning_key_id='target-k1'\ntrusted_keys=['k1']\n",
            target.display(),
            SEED1
        ),
    )
    .unwrap();
    commands::publish::run(PublishArgs {
        target: "local".to_string(),
        config: cfg.clone(),
        manifest: manifest_path,
    })
    .await
    .unwrap();
    // Happy path: signed manifest, artifact exists at correct size.
    commands::promote::run(PromoteArgs {
        target: "local".to_string(),
        config: cfg.clone(),
        manifest_path: "v1/snapshots/full/h000000001-sr_22222222/manifest.json".to_string(),
        label: "latest".to_string(),
        update_previous: false,
        require_signed_manifest: true,
    })
    .await
    .unwrap();

    // Tamper: shrink the artifact so its size no longer matches the manifest.
    let artifact = target.join("v1/snapshots/full/h000000001-sr_22222222/snapshot.tar.zst");
    fs::write(&artifact, b"truncated").unwrap();
    let err = commands::promote::run(PromoteArgs {
        target: "local".to_string(),
        config: cfg.clone(),
        manifest_path: "v1/snapshots/full/h000000001-sr_22222222/manifest.json".to_string(),
        label: "latest".to_string(),
        update_previous: false,
        require_signed_manifest: true,
    })
    .await
    .expect_err("must reject promotion when artifact size differs from manifest");
    assert!(err.to_string().contains("size mismatch"), "{err}");

    // Remove the artifact entirely.
    fs::remove_file(&artifact).unwrap();
    let err = commands::promote::run(PromoteArgs {
        target: "local".to_string(),
        config: cfg.clone(),
        manifest_path: "v1/snapshots/full/h000000001-sr_22222222/manifest.json".to_string(),
        label: "latest".to_string(),
        update_previous: false,
        require_signed_manifest: true,
    })
    .await
    .expect_err("must reject promotion when artifact is missing");
    assert!(err.to_string().contains("missing"), "{err}");
}

#[tokio::test]
async fn promote_rejects_unsigned_manifest_when_required() {
    let tmp = tempfile::tempdir().unwrap();
    // Pack WITHOUT signing.
    let manifest_path = pack_candidate(&tmp, false).await;
    let cfg = tmp.path().join("config.toml");
    let target = tmp.path().join("target");
    let public = signing::public_key_from_secret_spec(SEED1).unwrap();
    fs::write(
        &cfg,
        format!(
            "[trust.k1]\nscheme='ed25519'\npublic_key='{public}'\n[target.local]\nkind='file'\npath='{}'\nsigning_key='{}'\nsigning_key_id='target-k1'\ntrusted_keys=['k1']\n",
            target.display(),
            SEED1
        ),
    )
    .unwrap();
    commands::publish::run(PublishArgs {
        target: "local".to_string(),
        config: cfg.clone(),
        manifest: manifest_path,
    })
    .await
    .unwrap();
    let err = commands::promote::run(PromoteArgs {
        target: "local".to_string(),
        config: cfg,
        manifest_path: "v1/snapshots/full/h000000001-sr_22222222/manifest.json".to_string(),
        label: "latest".to_string(),
        update_previous: false,
        require_signed_manifest: true,
    })
    .await
    .expect_err("unsigned manifest must be rejected when required");
    assert!(err.to_string().contains("unsigned"), "{err}");
}

#[tokio::test]
async fn promote_writes_freshly_signed_previous_pointer_with_correct_label() {
    // The "previous" pointer must not be a byte-for-byte copy of the previous
    // "latest". Its body must say label="previous" and carry a new signature.
    let tmp = tempfile::tempdir().unwrap();
    let manifest_path = pack_candidate(&tmp, true).await;
    let cfg = tmp.path().join("config.toml");
    let target = tmp.path().join("target");
    let public = signing::public_key_from_secret_spec(SEED1).unwrap();
    fs::write(
        &cfg,
        format!(
            "[trust.target-k1]\nscheme='ed25519'\npublic_key='{public}'\n[target.local]\nkind='file'\npath='{}'\nsigning_key='{}'\nsigning_key_id='target-k1'\n",
            target.display(),
            SEED1
        ),
    )
    .unwrap();
    commands::publish::run(PublishArgs {
        target: "local".to_string(),
        config: cfg.clone(),
        manifest: manifest_path,
    })
    .await
    .unwrap();
    commands::promote::run(PromoteArgs {
        target: "local".to_string(),
        config: cfg.clone(),
        manifest_path: "v1/snapshots/full/h000000001-sr_22222222/manifest.json".to_string(),
        label: "latest".to_string(),
        update_previous: true,
        require_signed_manifest: false,
    })
    .await
    .unwrap();
    // First promotion: no prior latest -> no previous file.
    assert!(!target.join("v1/pointers/previous.json").exists());

    // Second promotion: previous.json must now exist as a freshly signed
    // pointer body with label="previous".
    commands::promote::run(PromoteArgs {
        target: "local".to_string(),
        config: cfg,
        manifest_path: "v1/snapshots/full/h000000001-sr_22222222/manifest.json".to_string(),
        label: "latest".to_string(),
        update_previous: true,
        require_signed_manifest: false,
    })
    .await
    .unwrap();
    let previous_bytes = fs::read(target.join("v1/pointers/previous.json")).unwrap();
    let previous: SignedPointer = serde_json::from_slice(&previous_bytes).unwrap();
    assert_eq!(previous.body.label, "previous");
    assert_eq!(previous.signature.key_id, "target-k1");
    let mut trust = std::collections::HashMap::new();
    trust.insert(
        "target-k1".to_string(),
        signing::TrustKey {
            scheme: "ed25519".to_string(),
            public_key: public,
        },
    );
    previous.verify_signature(&trust).unwrap();
}

// ---------------------------------------------------------------------------
// Remote verify streams to disk
// ---------------------------------------------------------------------------

#[tokio::test]
async fn remote_verify_streams_artifact_to_temp_file() {
    use std::net::SocketAddr;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    // Build a manifest for an archive whose hashes we'll serve verbatim. We
    // pack unsigned so verification doesn't require trust setup; the test is
    // about streaming the artifact body to disk, not about signatures.
    let tmp = tempfile::tempdir().unwrap();
    let candidate = pack_candidate(&tmp, false).await;
    let candidate_dir = candidate.parent().unwrap();
    let manifest_bytes = fs::read(&candidate).unwrap();
    let artifact_bytes = fs::read(candidate_dir.join("snapshot.tar.zst")).unwrap();

    // Spin a tiny one-shot HTTP/1.1 server that serves manifest then archive.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let server_manifest = manifest_bytes.clone();
    let server_artifact = artifact_bytes.clone();
    let server = tokio::spawn(async move {
        for body in [server_manifest, server_artifact] {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await.unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            use tokio::io::AsyncWriteExt;
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.write_all(&body).await.unwrap();
            socket.shutdown().await.ok();
        }
    });

    let manifest_url = format!("http://{addr}/manifest.json");
    commands::verify::run(VerifyArgs {
        manifest: manifest_url,
        config: None,
        trusted_key: vec![],
        require_signature: false,
        network: Some("mainnet".to_string()),
        role: Some("provisioner".to_string()),
    })
    .await
    .unwrap();
    server.await.unwrap();
}
