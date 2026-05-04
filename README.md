# rusk-state-snapshot

`rusk-state-snapshot` is a standalone Rust CLI for creating, publishing,
discovering, verifying, restoring, and garbage-collecting Dusk/Rusk state
snapshots. It is not part of the Rusk node runtime and does not import private
Rusk repository code.

The trust model is manifest based:

- Snapshots are immutable artifacts.
- Pointers are mutable retention labels such as `latest`, `daily`, `monthly`,
  `yearly`, and pins.
- Buckets, HTTP endpoints, and local directories are transports, not trust
  roots.
- Clients decide which configured sources and Ed25519 signing keys they trust.
- Official Dusk storage can be configured as a source or target, but no Dusk
  bucket name, endpoint, URL, public key, or signing key is hardcoded.

## Commands

```sh
cargo run -- pack \
  --network mainnet \
  --role provisioner \
  --state-dir ./testdata/state \
  --chain-db-dir ./testdata/chain.db \
  --height 1 \
  --block-hash 0000000000000000000000000000000000000000000000000000000000000001 \
  --state-root 1111111111111111111111111111111111111111111111111111111111111111 \
  --block-timestamp 2026-05-04T00:00:00Z \
  --rusk-version 1.6.0 \
  --out ./target/rusk-state-snapshot-candidates
```

```sh
cargo run -- verify ./target/rusk-state-snapshot-candidates/*/manifest.json
```

```sh
cargo run -- publish \
  --config ./examples/config.example.toml \
  --target local_mainnet \
  ./target/rusk-state-snapshot-candidates/*/manifest.json
```

```sh
cargo run -- promote \
  --config ./examples/config.example.toml \
  --target local_mainnet \
  --manifest-path v1/snapshots/full/h000000001-sr_11111111/manifest.json \
  --label latest
```

```sh
cargo run -- list \
  --config ./examples/config.example.toml \
  --source local_mainnet
```

```sh
cargo run -- restore \
  --config ./examples/config.example.toml \
  --source local_mainnet \
  --latest \
  --destination-profile ./target/restored-profile
```

```sh
cargo run -- gc \
  --config ./examples/config.example.toml \
  --target local_mainnet \
  --policy ./examples/retention.example.toml \
  --dry-run
```

## Scope

Version 0 packs full provisioner snapshots only. The archive includes:

- `state/`
- `chain.db/`

It excludes archive data, logs, wallets, consensus keys, node configuration
secrets, object-store credentials, signing keys, and anything outside the
explicit input roots.

Archives are compressed tar files named `snapshot.tar.zst`; manifests record
SHA-256 and BLAKE3 hashes. Archive extraction rejects absolute paths, `..`
components, and symlinks that escape the extraction root.

## Source vs Target

Sources are read-only discovery locations. Targets are writable publishing
locations. Both are configured in TOML. The local filesystem backend is fully
implemented and tested. HTTP sources support direct object fetches and public
listing through an `index.json` file. The S3 backend uses AWS Signature V4
against configurable S3-compatible endpoints, buckets, prefixes, and regions,
including Hetzner-style object storage.

Targets that promote pointers must configure both `signing_key` and
`signing_key_id`. Pointer signatures use the target key id, not the manifest
publisher key id, so operators can publish manifests and retention labels with
separate keys.

HTTP sources that do not allow bucket listing can publish an index at
`<base_url>/index.json`:

```json
{
  "format": "rusk-state-snapshot-index/v1",
  "objects": [
    {
      "path": "v1/pointers/latest.json",
      "size": 767
    },
    {
      "path": "v1/snapshots/full/h000000001-sr_11111111/manifest.json",
      "size": 989
    }
  ]
}
```

## Restore Safety

Restore downloads and verifies the pointer, pointer-to-manifest hash and
metadata, manifest signature, artifact hashes, archive paths, and
`state/state.id` before touching the destination profile. Artifact downloads use
file-based object-store operations so large archives are not buffered in memory.
It moves existing `state` and `chain.db` into a timestamped backup directory,
then moves the verified replacement into place. It never deletes live node state
before verification.

## GC Safety

`gc` is snapshot-object eviction only. It first prunes daily/monthly/yearly
pointer labels according to the retention policy, then loads remaining pointers,
marks reachable manifests and artifacts, reports unreferenced snapshot/staging
objects older than the grace period, and deletes them only with `--delete`. It
never touches local node state.

## No Runtime Integration

This tool does not integrate with a running Rusk process and does not add any
automatic publishing behavior to Rusk. Service stop/start during restore is
explicit and opt-in via `--manage-service`.
