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
run light structural verification. Once `snapshot.tar.gz`, `manifest.json`,
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
      snapshot.tar.gz
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

## Provisioner Snapshots

Version 0 packs full provisioner snapshots only. The archive includes:

- `state/`
- `chain.db/`

It excludes archive data, logs, wallets, consensus keys, node configuration
secrets, object-store credentials, signing keys, and anything outside the
explicit input roots.

Archives are compressed tar files named `snapshot.tar.gz` by default; pass
`--compression zstd` to `pack`, `capture`, or `watch` to produce
`snapshot.tar.zst` instead. Manifests record the actual artifact path plus
SHA-256 and BLAKE3 hashes, so restore and verification remain format-aware.
Archive extraction rejects absolute paths, `..` components, and symlinks that
escape the extraction root.

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

## Retention and GC

`gc` is snapshot-object eviction only. It first prunes daily/monthly/yearly
pointer labels according to the retention policy, then loads remaining pointers,
marks reachable manifests and artifacts, reports unreferenced snapshot/staging
objects older than the grace period, and deletes them only with `--delete`. It
never touches local node state. It prunes stale pointers and unreferenced
artifacts; it does not create daily, monthly, yearly, or latest labels.

Archive/blob support is opt-in and remains separate from the default
provisioner snapshot path. When archive roots are present, `gc` also follows
archive/state reachability: a rooted archive manifest pins its archive artifact
and the matching state snapshot manifest and artifact.

Archive manifests are not GC roots by filename alone. Archive checkpoints are
retained through explicit roots under `v1/archive/pointers/...` or
`v1/archive/pins/...`; unrooted archive checkpoints are eligible for deletion
after the configured grace period.

Blob storage is WORM-like. Normal retention GC intentionally does not delete
`v1/blobs/**`, including blob objects, range manifests, or coverage manifests.
Operators must also avoid object-store lifecycle policies that expire
`v1/blobs/**`. Any future blob cleanup must be a separate explicit
administrative flow, such as `blob-audit` or `blob-prune`, with stronger
safeguards than snapshot GC.

Normal GC deletion prefixes are:

```text
v1/snapshots/
v1/staging/
v1/archive/
```

`v1/blobs/**` is intentionally absent from that list.

## Archive Snapshots

Archive snapshots are separate checkpoint-aligned artifacts under
`v1/archive/checkpoints/...`. They reference an existing state snapshot and blob
coverage for the same checkpoint. A valid archive snapshot must match the
referenced state snapshot on network, height, block hash, and state root.

Archive checkpoints are rooted only by:

```text
v1/archive/pointers/latest.json
v1/archive/pins/<name>.json
```

The archive layout is:

```text
v1/
  archive/
    checkpoints/
      h.../
        archive-manifest.json
        archive.tar.zst
    pointers/
      latest.json
    pins/
      <name>.json
```

Archive completeness verification checks the archive artifact, the referenced
state manifest and artifact, and the referenced blob coverage before restore.
Restore is manifest-driven and verification-first.

## Blob Depot

Blob data is stored independently as content-addressed objects. Blob
completeness is proven by signed contiguous range manifests plus a signed
coverage manifest. Empty blocks are represented explicitly so coverage proves
that every height in the range was inspected.

The blob layout is:

```text
v1/
  blobs/
    objects/
      ab/
        cd/
          <blob_hash>
    ranges/
      h000000000-h000000999/
        blob-range.json
    coverage/
      h000000999-b_<hash>.json
```

`blobs-publish-range` writes blob objects before the range manifest.
`blobs-publish-coverage` verifies every referenced remote range manifest and
blob object before writing the coverage manifest. Coverage manifests are the
final truth objects for contiguous blob ranges.

`blobs-export-range` queries block headers and transaction blob hashes from a
Rusk GraphQL node, downloads each sidecar through `/on/blobs:<hash>/hash`, and
verifies the sidecar commitment derives the chain-reported versioned KZG blob
hash and that the blob data verifies against the commitment/proof before
writing the descriptor. `blobs-pack-range` repeats those descriptor/file/KZG
checks before creating content-addressed blob objects. Each blob range entry
stores both the chain-reported versioned KZG blob hash and the content hashes,
so later coverage verification can prove the full
`block -> chain blob hash -> sidecar commitment/proof/data -> blob object`
link without trusting the original pack step.

## Operational Flows

Provisioner snapshots:

```text
pack -> publish -> promote -> rebuild-index -> gc
```

Archive checkpoints:

```text
state snapshot at H
blob ranges/coverage through H
archive-pack at H
archive-publish
archive-promote
verify-archive-complete
```

Blob depot:

```text
blobs-export-range
blobs-pack-range
blobs-publish-range
blobs-write-coverage
blobs-publish-coverage
blobs-verify-coverage
```

The archive/blob commands are explicit:

```sh
cargo run -- blobs-export-range \
  --network localnet \
  --rusk-url http://127.0.0.1:8080 \
  --from-height 0 \
  --to-height 49 \
  --out ./target/archive-blob-validation/descriptors

cargo run -- blobs-pack-range \
  --network localnet \
  --from-height 0 \
  --to-height 49 \
  --descriptor-dir ./target/archive-blob-validation/descriptors \
  --out ./target/archive-blob-validation

cargo run -- blobs-write-coverage \
  --network localnet \
  --out ./target/archive-blob-validation \
  ./target/archive-blob-validation/v1/blobs/ranges/h000000000-h000000049/blob-range.json

cargo run -- blobs-publish-range \
  --config ./examples/config.example.toml \
  --target local_mainnet \
  ./target/archive-blob-validation/v1/blobs/ranges/h000000000-h000000049/blob-range.json

cargo run -- blobs-publish-coverage \
  --config ./examples/config.example.toml \
  --target local_mainnet \
  ./target/archive-blob-validation/v1/blobs/coverage/h000000049-b_00000000.json

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
  --out ./target/archive-blob-validation

cargo run -- archive-publish \
  --config ./examples/config.example.toml \
  --target local_mainnet \
  ./target/archive-blob-validation/v1/archive/checkpoints/h000000049-b_00000000/archive-manifest.json

cargo run -- archive-promote \
  --config ./examples/config.example.toml \
  --target local_mainnet \
  --archive-manifest v1/archive/checkpoints/h000000049-b_00000000/archive-manifest.json \
  --label latest

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

For official sources, configure signature requirements for archive/blob data:

```toml
[archive_blob]
require_signed_blob_ranges = true
require_signed_blob_coverage = true
require_signed_archive = true
require_signed_archive_pointers = true
```

Unsigned archive/blob data is suitable only for local validation stores.

## Validation Harness

`scripts/local-archive-blob-validation.sh` validates the archive/blob flow
against a running local Rusk archive node. It uses `rusk-wallet blob` to submit
real blob transactions, queries local GraphQL for block hashes and transaction
blob hashes, downloads sidecar bytes through `/on/blobs:<hash>/hash`, exports
range descriptors that bind each sidecar to its chain blob hash, and then runs
state snapshot, blob range/coverage, archive pack/publish, archive completeness
verification, and manifest-driven restore of the matching state/archive
artifacts against a local file store.

The release sign-off mode is:

```sh
RESTORED_NODE_CHECK=1 scripts/local-archive-blob-validation.sh
```

With `RESTORED_NODE_CHECK=1`, the harness also starts a restored archive node,
asserts that the restored H1 block is present, compares restored H1 archive
events byte-for-byte against the original archive node, and waits for the
restored node to advance to H2.

The invariant suite covers checkpoint drift, incomplete coverage, missing or
corrupted blob objects, range gaps, broken previous-range hashes, tampered
signatures, unsafe archive paths, archive artifact corruption, WORM blob
retention, and GC reachability across state/archive artifacts.

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
