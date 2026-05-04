use crate::{
    archive,
    cli::{GcArgs, PackArgs, PromoteArgs, PublishArgs, RestoreArgs, VerifyArgs},
    commands, hashing,
    manifest::{
        Artifact, ComponentEntry, Components, ManifestBody, SignedManifest, MANIFEST_FORMAT,
    },
    object_store::{file::FileStore, ObjectStore},
    pointer::{PointerBody, SignedPointer, POINTER_FORMAT},
    retention, safe_extract, signing,
};
use chrono::Utc;
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

fn make_profile(root: &Path) {
    fs::create_dir_all(root.join("state")).unwrap();
    fs::create_dir_all(root.join("chain.db")).unwrap();
    fs::write(root.join("state/state.id"), [7u8; 32]).unwrap();
    fs::write(root.join("state/value"), b"state").unwrap();
    fs::write(root.join("chain.db/value"), b"chain").unwrap();
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
            "[target.local]\nkind='file'\npath='{}'\nsigning_key='{}'\n",
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
            "[trust.k1]\nscheme='ed25519'\npublic_key='{public}'\n[source.local]\nkind='file'\npath='{}'\ntrusted_keys=['k1']\n[target.local]\nkind='file'\npath='{}'\nsigning_key='{}'\n",
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
    })
    .await
    .unwrap();
    let dest = tmp.path().join("dest");
    make_profile(&dest);
    fs::write(dest.join("state/old"), b"old").unwrap();
    commands::restore::run(RestoreArgs {
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
    .unwrap();
    assert!(dest.join("state/value").exists());
    assert!(dest.join("chain.db/value").exists());
    assert!(dest.join("backups").read_dir().unwrap().next().is_some());
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
            "[target.local]\nkind='file'\npath='{}'\nsigning_key='{}'\n",
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
