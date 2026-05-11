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

Plan the currently desired calendar labels from UTC wall-clock time:

```sh
cargo run -- plan \
  --network mainnet \
  --policy ./examples/retention.example.toml \
  --now 2026-05-08T14:57:00Z \
  --genesis-time 2025-01-01T00:00:00Z
```

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

```sh
cargo run -- rebuild-index \
  --config ./examples/config.example.toml \
  --target local_mainnet
```

The primitive publishing flow is:

```text
pack -> publish -> promote -> rebuild-index -> gc
```

For long-running syncs, the orchestrated flow is:

```text
plan -> watch -> capture
```

`watch` computes desired labels repeatedly, polls an external tip source, marks
labels missed when their cutoffs were already passed without observation, and
calls `capture` only when the local node crosses a cutoff inside the configured
capture lag window.

```sh
cargo run -- watch \
  --network mainnet \
  --policy ./examples/retention.example.toml \
  --config ./examples/config.example.toml \
  --source local_mainnet \
  --target local_mainnet \
  --state-dir ./testdata/state \
  --chain-db-dir ./testdata/chain.db \
  --tip-file ./testdata/tip.json \
  --journal ./target/watch-mainnet.json \
  --spool-dir ./target/mainnet-snapshot-spool \
  --poll-interval 1s \
  --max-capture-lag 1h \
  --latest-freshness-window 24h \
  --latest-min-interval 24h
```

`capture` stops Rusk only long enough to write a local immutable candidate and
run light structural verification. Once `snapshot.tar.zst`, `manifest.json`,
and `candidate.json` are complete in the spool directory, Rusk is started
again. Full candidate verification, including artifact hashing and archive
safety validation, happens after restart and reads only those candidate files,
never the live `state/` or `chain.db/` paths. Upload, promotion, and index
rebuild also run after restart. All provided labels are promoted to the same
immutable manifest:

```sh
cargo run -- capture \
  --network mainnet \
  --labels monthly:2025-12,yearly:2025 \
  --cutoff 2026-01-01T00:00:00Z \
  --config ./examples/config.example.toml \
  --target local_mainnet \
  --state-dir ./testdata/state \
  --chain-db-dir ./testdata/chain.db \
  --spool-dir ./target/mainnet-snapshot-spool \
  --tip-file ./testdata/tip.json \
  --manage-service rusk \
  --manifest-signing-key file:/etc/rusk-state-snapshot/mainnet-manifest-key \
  --manifest-key-id dusk-mainnet-2026 \
  --publisher-name "Dusk Network" \
  --require-signed-manifest \
  --rebuild-index
```

For calendar labels, direct `capture` validates that the label matches the
cutoff. For example, `monthly:2025-12` and `yearly:2025` both require
`--cutoff 2026-01-01T00:00:00Z`; `monthly:2025-05` would require
`--cutoff 2025-06-01T00:00:00Z`. If the stopped-tip read fails, `capture`
fails by default; use `--allow-prestop-tip` only when falling back to pre-stop
metadata is intentional.

The candidate spool layout is:

```text
<spool-dir>/
  candidates/
    h001234567-sr_abcd1234/
      snapshot.tar.zst
      manifest.json
      candidate.json
```

`candidate.json` is the publishable marker. Watch scans the spool for valid
candidate markers before classifying cutoffs, so a crash after packing but
before the journal update can still recover the candidate instead of marking the
label missed. Watch records packed candidates as pending in its journal before
publishing; if publish or promotion fails after Rusk has restarted, the next
watch iteration retries from the same candidate without stopping Rusk or
repacking. During retry, labels whose pointers already reference the candidate
manifest are skipped; this is especially important for `latest`, because
rewriting an already-promoted `latest` would also rewrite `previous`.

Watch deletes candidate directories after successful publication by default.
Manual `capture` keeps the candidate unless `--delete-candidate-after-publish`
is provided.

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
including Hetzner-style object storage. Uploads larger than
`multipart_threshold` (default 64 MiB) are sent as multipart uploads with
configurable `multipart_part_size` (default 16 MiB, S3 minimum 5 MiB) and
fall back to AbortMultipartUpload on error. `ListObjectsV2` pagination uses
continuation tokens so listings are not silently truncated at 1 000 keys.

Publishes upload the snapshot artifact directly to its final immutable key and
write the manifest last. This avoids server-side single-PUT copy (capped at
5 GiB on AWS S3 and many providers) and guarantees that no manifest ever
references a partial or missing artifact. Promotions verify the referenced
manifest's signature against the target's `trusted_keys` (mandatorily, with
`--require-signed-manifest`) and confirm the referenced artifact exists at the
expected size before any pointer is written. The `previous` pointer is
regenerated as a freshly signed pointer with `label = "previous"` rather than
byte-copied from `latest.json`.

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
never touches local node state. It prunes stale pointers and unreferenced
artifacts; it does not create daily, monthly, yearly, or latest labels.

On the experimental `poc/archive-blob-retention` branch, `gc` also understands
archive/blob reachability. A retained archive manifest pins its archive artifact,
the matching state snapshot manifest and artifact, the blob coverage manifest,
the signed blob range manifests, and every referenced content-addressed blob
object. This is branch-local POC behavior and does not make archive/blob capture
part of the default provisioner snapshot path.

## Experimental Archive/Blob POC

This branch contains local-only proof plumbing for archive/blob retention. State
snapshots remain the existing provisioner snapshots. Archive snapshots are
separate checkpoint-aligned artifacts under `v1/archive/checkpoints/...`, and
blob data is stored independently under `v1/blobs/objects/...` by content hash.
Blob completeness is proven by signed contiguous range manifests plus a signed
coverage manifest; archive completeness is true only when the archive artifact,
matching state snapshot, and blob coverage all verify.

The POC commands are intentionally separate:

```sh
cargo run -- blobs-pack-range \
  --network localnet \
  --from-height 0 \
  --to-height 49 \
  --chain-db-dir ./target/poc-chain.db \
  --out ./target/archive-blob-poc

cargo run -- blobs-write-coverage \
  --network localnet \
  --out ./target/archive-blob-poc \
  ./target/archive-blob-poc/v1/blobs/ranges/h000000000-h000000049/blob-range.json

cargo run -- blobs-publish-range \
  --config ./examples/config.example.toml \
  --target local_mainnet \
  ./target/archive-blob-poc/v1/blobs/ranges/h000000000-h000000049/blob-range.json

cargo run -- blobs-verify-coverage \
  --config ./examples/config.example.toml \
  --source local_mainnet \
  --coverage-manifest v1/blobs/coverage/h000000049-b_00000000.json \
  --from-height 0 \
  --to-height 49

cargo run -- archive-pack \
  --network localnet \
  --archive-dir ./target/archive-node/archive \
  --height 49 \
  --block-hash 0000000000000000000000000000000000000000000000000000000000000031 \
  --state-root 1111111111111111111111111111111111111111111111111111111111111111 \
  --block-timestamp 2026-05-11T00:00:00Z \
  --state-manifest-path v1/snapshots/full/h000000049-sr_11111111/manifest.json \
  --state-manifest-sha256 ... \
  --blob-coverage-path v1/blobs/coverage/h000000049-b_00000000.json \
  --blob-coverage-sha256 ... \
  --blob-coverage-from-height 0 \
  --blob-coverage-to-height 49 \
  --blob-coverage-to-block-hash 0000000000000000000000000000000000000000000000000000000000000031 \
  --out ./target/archive-blob-poc

cargo run -- verify-archive-complete \
  --config ./examples/config.example.toml \
  --source local_mainnet \
  --archive-manifest v1/archive/checkpoints/h000000049-b_00000000/archive-manifest.json \
  --target-height 49

cargo run -- archive-restore-complete \
  --config ./examples/config.example.toml \
  --source local_mainnet \
  --archive-manifest v1/archive/checkpoints/h000000049-b_00000000/archive-manifest.json \
  --target-height 49 \
  --destination-profile ./target/restored-profile \
  --archive-dir ./target/restored-profile/archive
```

For the local invariant tests, `blobs-pack-range` reads deterministic POC block
descriptors from `CHAIN_DB_DIR/blob-blocks/h#########.json`; each descriptor
contains a height, block hash, and paths to real local blob bytes. Empty blocks
are represented explicitly. This proves the archive/blob object and manifest
rules locally, but it is not yet a production Rusk archive-node integration.

The branch also includes `scripts/local-archive-blob-poc.sh`, a proof harness
for a running local Rusk archive node. It uses `rusk-wallet blob` to submit real
blob transactions, queries local GraphQL for block hashes and transaction blob
hashes, downloads sidecar bytes through `/on/blobs:<hash>/hash`, exports the
POC descriptors, and then runs state snapshot, blob range/coverage, archive
pack, archive completeness verification, and manifest-driven restore of the
matching state/archive artifacts against a local file store. It is intended for
local proof runs only; it does not start or manage production services.

The invariant suite covers checkpoint drift, incomplete coverage, missing or
corrupted blob objects, range gaps, broken previous-range hashes, tampered
signatures, unsafe archive paths, archive artifact corruption, and GC
reachability across state/archive/blob artifacts.

## Calendar Orchestration

Calendar retention labels are generated from UTC wall-clock time, not from the
historical sync stream:

- `daily` means the last N completed UTC days.
- `monthly` means the last N completed UTC months.
- `yearly` means completed UTC years. With `keep_years = 0`, planning uses
  `--genesis-time` as the first possible year; without `--genesis-time`, it
  defaults to the previous completed year.

A calendar label is only honest if the watcher observes the local tip crossing
that label's cutoff:

```text
previous_local_tip_time < cutoff <= current_local_tip_time
```

The capture is allowed only when the current local tip is within
`--max-capture-lag` of the cutoff. If the watcher starts from an already
partially synced node, or if it was not running when a cutoff was crossed, the
missing label is recorded as missed in the local journal. Missed labels are not
published as remote pointers. Producing a complete historical set requires
syncing from scratch or from a state before the missing cutoffs.

`latest` has a separate freshness policy. `watch` promotes `latest` only when
the local tip is within `--latest-freshness-window` of a trusted network tip
source, or of wall-clock time when no network tip source is configured. A node
that is months behind may still capture honest historical calendar labels as it
crosses their cutoffs, but it will not update `latest`.

Tip metadata is supplied by a standalone JSON command or file. The tool does
not import Rusk code:

```json
{
  "height": 1234567,
  "block_hash": "0000000000000000000000000000000000000000000000000000000000000001",
  "state_root": "1111111111111111111111111111111111111111111111111111111111111111",
  "block_timestamp": "2026-05-08T00:00:00Z"
}
```

For official publishing, run `watch` from scratch for complete historical
labels, publish testnet before mainnet, and use a tip command that can read
consistent stopped-state metadata. `capture` requires `--manage-service`; the
state and chain database are packed while Rusk is stopped, then the service is
restarted before remote publication begins.

## No Runtime Integration

This tool does not import a running Rusk process and does not add any automatic
publishing behavior to Rusk itself. Service stop/start during restore and
capture is explicit via `--manage-service`.
