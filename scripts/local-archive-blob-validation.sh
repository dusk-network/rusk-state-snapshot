#!/usr/bin/env bash
set -euo pipefail

# Local archive/blob retention validation harness.
#
# It expects a local Rusk
# archive node and wallet to be available, generates real blob transactions
# through rusk-wallet, exports block/blob descriptors from the node HTTP API,
# then runs the archive/blob commands against those real sidecar bytes.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUSK_REPO="${RUSK_REPO:-/home/hein_/projects/rusk-private-rc-pr117-build}"
WORKDIR="${WORKDIR:-$ROOT/target/archive-blob-localnet-validation}"
RUSK_URL="${RUSK_URL:-http://127.0.0.1:8080}"
NETWORK="${NETWORK:-localnet}"
FROM_HEIGHT="${FROM_HEIGHT:-0}"
RANGE_LEN="${RANGE_LEN:-50}"
ARCHIVE_DIR="${ARCHIVE_DIR:-}"
STATE_DIR="${STATE_DIR:-}"
CHAIN_DB_DIR="${CHAIN_DB_DIR:-}"
SIGNING_KEY="${SIGNING_KEY:-}"
KEY_ID="${KEY_ID:-local-validation}"
TRUST_PUBLIC_KEY="${TRUST_PUBLIC_KEY:-}"
WALLET_DIR="${WALLET_DIR:-$WORKDIR/wallet}"
RESTORED_NODE_CHECK="${RESTORED_NODE_CHECK:-0}"
RUSK_BIN="${RUSK_BIN:-$RUSK_REPO/target/release/rusk}"
RESTORE_HTTP_ADDR="${RESTORE_HTTP_ADDR:-127.0.0.1:8091}"
RESTORE_URL="${RESTORE_URL:-http://$RESTORE_HTTP_ADDR}"
RESTORE_KADCAST_ADDR="${RESTORE_KADCAST_ADDR:-127.0.0.1:9111}"
RESTORE_NETWORK_ID="${RESTORE_NETWORK_ID:-239}"
RESTORED_NODE_PID=""

cleanup() {
  if [[ -n "$RESTORED_NODE_PID" ]]; then
    kill "$RESTORED_NODE_PID" >/dev/null 2>&1 || true
    wait "$RESTORED_NODE_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 2
  }
}

graphql() {
  graphql_at "$RUSK_URL" "$1"
}

graphql_at() {
  local url="$1"
  local query="$2"
  curl -fsS \
    -H 'content-type: application/json' \
    -d "$(jq -cn --arg query "$query" '{query:$query}')" \
    "$url/graphql"
}

tip_height() {
  graphql '{ block(height: -1) { header { height } } }' \
    | jq -r '.data.block.header.height'
}

block_query() {
  local height="$1"
  graphql "{ block(height: $height) { header { height hash stateHash timestamp } transactions { tx { id blobHashes } } } }"
}

wait_tip() {
  local target="$1"
  local current
  for _ in $(seq 1 120); do
    current="$(tip_height)"
    if [[ "$current" =~ ^[0-9]+$ ]] && (( current >= target )); then
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for local tip >= $target" >&2
  return 1
}

send_blob_tx() {
  local idx="$1"
  local payload="$WORKDIR/blob-input/blob-$idx.bin"
  local output tx_hash
  mkdir -p "$(dirname "$payload")"
  python3 - "$payload" "$idx" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
idx = int(sys.argv[2])
seed = f"archive-blob-validation-{idx:02d}-".encode()
blob = bytearray()
for field_idx in range(4096):
    chunk = bytearray(32)
    chunk[0] = 0
    chunk[1] = idx & 0xff
    chunk[2] = (field_idx >> 8) & 0xff
    chunk[3] = field_idx & 0xff
    for pos in range(4, 32):
        chunk[pos] = seed[(field_idx + pos) % len(seed)]
    blob.extend(chunk)
path.write_bytes(blob)
PY
  mkdir -p "$WALLET_DIR"
  if [[ ! -f "$WALLET_DIR/wallet.dat" && -f "$RUSK_REPO/examples/wallet.dat" ]]; then
    cp "$RUSK_REPO/examples/wallet.dat" "$WALLET_DIR/wallet.dat"
  fi
  output="$({
    cd "$RUSK_REPO"
    RUSK_WALLET_PWD="${RUSK_WALLET_PWD:-password}" \
      cargo run --release -p rusk-wallet -- \
        --wallet-dir "$WALLET_DIR" \
        --state "$RUSK_URL" \
        --prover "$RUSK_URL" \
        --archiver "$RUSK_URL" \
        blob --blobs "$payload"
  } 2>&1)"
  echo "$output" >&2
  if grep -Eiq 'error|failed|panic' <<<"$output"; then
    echo "blob transaction command reported failure" >&2
    exit 1
  fi
  tx_hash="$(grep -Eo '^[0-9a-f]{64}$' <<<"$output" | tail -1)"
  if [[ -z "$tx_hash" ]]; then
    echo "blob transaction command did not print a transaction hash" >&2
    exit 1
  fi
  printf '%s\n' "$tx_hash"
}

wait_for_tx() {
  local tx_id="$1"
  local from="$2"
  local current height block_json found
  for _ in $(seq 1 180); do
    current="$(tip_height)"
    if [[ "$current" =~ ^[0-9]+$ ]] && (( current >= from )); then
      for height in $(seq "$from" "$current"); do
        block_json="$(block_query "$height")"
        found="$(jq -r --arg tx_id "$tx_id" '.data.block.transactions[]?.tx.id | select(. == $tx_id)' <<<"$block_json" | head -1)"
        if [[ "$found" == "$tx_id" ]]; then
          printf '%s\n' "$height"
          return 0
        fi
      done
    fi
    sleep 1
  done
  echo "timed out waiting for blob tx $tx_id to be included" >&2
  return 1
}

write_config() {
  local store="$1"
  if [[ -n "$TRUST_PUBLIC_KEY" ]]; then
    cat > "$WORKDIR/config.toml" <<EOF
[trust.$KEY_ID]
scheme = "ed25519"
public_key = "$TRUST_PUBLIC_KEY"

[source.local_validation]
kind = "file"
path = "$store"
trusted_keys = ["$KEY_ID"]

[target.local_validation]
kind = "file"
path = "$store"
trusted_keys = ["$KEY_ID"]
signing_key = "$SIGNING_KEY"
signing_key_id = "$KEY_ID"

[archive_blob]
require_signed_blob_ranges = true
require_signed_blob_coverage = true
require_signed_archive = true
require_signed_archive_pointers = true
EOF
  else
    cat > "$WORKDIR/config.toml" <<EOF
[source.local_validation]
kind = "file"
path = "$store"

[target.local_validation]
kind = "file"
path = "$store"
EOF
  fi
}

sign_args() {
  if [[ -n "$SIGNING_KEY" ]]; then
    if [[ -z "$TRUST_PUBLIC_KEY" ]]; then
      echo "SIGNING_KEY requires TRUST_PUBLIC_KEY so verification can trust signed manifests" >&2
      exit 2
    fi
    printf '%s\n' --signing-key "$SIGNING_KEY" --key-id "$KEY_ID"
  fi
}

pack_state_snapshot() {
  local height="$1"
  local block_hash="$2"
  local state_hash="$3"
  local block_ts="$4"
  local pack_dir manifest_rel
  pack_dir="$(cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -- pack \
    --network "$NETWORK" \
    --state-dir "$STATE_DIR" \
    --chain-db-dir "$CHAIN_DB_DIR" \
    --height "$height" \
    --block-hash "$block_hash" \
    --state-root "$state_hash" \
    --block-timestamp "$block_ts" \
    --rusk-version "local-validation" \
    --out "$LOCAL" \
    --publisher-name "local-validation" \
    $(sign_args))"
  manifest_rel="$(cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -- publish \
    --config "$WORKDIR/config.toml" \
    --target local_validation \
    "$pack_dir/manifest.json")"
  sha256sum "$pack_dir/manifest.json" | awk '{print $1}' > "$WORKDIR/state-manifest.sha"
  printf '%s\n' "$manifest_rel"
}

block_field() {
  local height="$1"
  local field="$2"
  block_query "$height" | jq -r ".data.block.header.$field"
}

wait_remote_tip() {
  local url="$1"
  local target="$2"
  local current
  for _ in $(seq 1 120); do
    current="$(graphql_at "$url" '{ block(height: -1) { header { height } } }' 2>/dev/null \
      | jq -r '.data.block.header.height // empty' || true)"
    if [[ "$current" =~ ^[0-9]+$ ]] && (( current >= target )); then
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for restored node tip >= $target" >&2
  return 1
}

check_restored_node() {
  if [[ "$RESTORED_NODE_CHECK" != "1" ]]; then
    return 0
  fi
  if [[ ! -x "$RUSK_BIN" ]]; then
    echo "RESTORED_NODE_CHECK=1 requires executable RUSK_BIN=$RUSK_BIN" >&2
    exit 2
  fi

  echo "starting restored archive node and checking restored archive events"
  RUSK_PROFILE_PATH="$RESTORE_PROFILE" \
  RUSK_STATE_PATH="$RESTORE_PROFILE/state" \
  DUSK_CONSENSUS_KEYS_PASS="${DUSK_CONSENSUS_KEYS_PASS:-password}" \
    "$RUSK_BIN" \
      --log-type plain \
      --log-level info \
      --db-path "$RESTORE_PROFILE" \
      --http-listen-addr "$RESTORE_HTTP_ADDR" \
      --kadcast-public-address "$RESTORE_KADCAST_ADDR" \
      --network-id "$RESTORE_NETWORK_ID" \
      > "$WORKDIR/restored-node.log" 2>&1 &
  RESTORED_NODE_PID="$!"

  wait_remote_tip "$RESTORE_URL" "$H1"
  graphql_at "$RESTORE_URL" "{ checkBlock(height: $H1, hash: \"$H1_BLOCK_HASH\", onlyFinalized: false) }" \
    | jq -e '.data.checkBlock == true' >/dev/null
  graphql_at "$RESTORE_URL" "{ contractEvents(height: $H1) { json } }" \
    | jq -S . > "$WORKDIR/restored-h1-events.json"
  diff -u "$ORIGINAL_H1_EVENTS" "$WORKDIR/restored-h1-events.json"

  wait_remote_tip "$RESTORE_URL" "$H2"
}

need cargo
need curl
need jq
need python3

mkdir -p "$WORKDIR"
STORE="$WORKDIR/store"
LOCAL="$WORKDIR/local-artifacts"
DESCRIPTORS="$WORKDIR/exported-chain.db"
mkdir -p "$STORE" "$LOCAL"
write_config "$STORE"

if [[ -z "$ARCHIVE_DIR" || -z "$STATE_DIR" || -z "$CHAIN_DB_DIR" ]]; then
  cat >&2 <<EOF
ARCHIVE_DIR, STATE_DIR, and CHAIN_DB_DIR must be set.

Expected workflow:
  1. In rusk-private, run:
       make prepare-dev
       RUSK_DEV_ARGS='--http-listen' make run-dev-archive
  2. In another shell, set paths for that local node, for example:
       export STATE_DIR=/tmp/example.state
       export CHAIN_DB_DIR=/tmp/example.chain.db
       export ARCHIVE_DIR=/tmp/example.state/archive
  3. Re-run this script.
EOF
  exit 2
fi

wait_tip 1
START_TIP="$(tip_height)"
MIN_H2="$((START_TIP + RANGE_LEN))"

echo "local tip is $START_TIP; sending real blob transactions"
TX1="$(send_blob_tx 1)"
TX1_HEIGHT="$(wait_for_tx "$TX1" "$START_TIP")"
H1="$TX1_HEIGHT"
echo "first blob tx included at height $H1; checkpointing archive/state at H1"
wait_tip "$H1"

echo "exporting block/blob descriptors for $FROM_HEIGHT..$H1"
cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -- blobs-export-range \
  --network "$NETWORK" \
  --rusk-url "$RUSK_URL" \
  --from-height "$FROM_HEIGHT" \
  --to-height "$H1" \
  --out "$DESCRIPTORS" >/dev/null

echo "packing H1 state snapshot"
H1_STATE_HASH="$(block_field "$H1" stateHash)"
H1_BLOCK_HASH="$(block_field "$H1" hash)"
H1_BLOCK_TS="$(block_field "$H1" timestamp)"
STATE_MANIFEST_REL="$(pack_state_snapshot "$H1" "$H1_BLOCK_HASH" "$H1_STATE_HASH" "$H1_BLOCK_TS")"
STATE_MANIFEST_SHA="$(cat "$WORKDIR/state-manifest.sha")"

echo "packing H1 blob range and coverage"
RANGE1_MANIFEST="$(cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -- blobs-pack-range \
  --network "$NETWORK" \
  --from-height "$FROM_HEIGHT" \
  --to-height "$H1" \
  --descriptor-dir "$DESCRIPTORS" \
  --out "$LOCAL" \
  $(sign_args))"
RANGE1_SHA="$(sha256sum "$RANGE1_MANIFEST" | awk '{print $1}')"
cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -- blobs-publish-range \
  --config "$WORKDIR/config.toml" \
  --target local_validation \
  "$RANGE1_MANIFEST" >/dev/null
COVERAGE_H1_MANIFEST="$(cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -- blobs-write-coverage \
  --network "$NETWORK" \
  --out "$LOCAL" \
  $(sign_args) \
  "$RANGE1_MANIFEST")"
COVERAGE_H1_REL="${COVERAGE_H1_MANIFEST#"$LOCAL/"}"
COVERAGE_H1_SHA="$(sha256sum "$COVERAGE_H1_MANIFEST" | awk '{print $1}')"
cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -- blobs-publish-coverage \
  --config "$WORKDIR/config.toml" \
  --target local_validation \
  "$COVERAGE_H1_MANIFEST" >/dev/null

echo "packing H1 archive checkpoint"
cargo run --manifest-path "$ROOT/Cargo.toml" -- archive-pack \
  --network "$NETWORK" \
  --archive-dir "$ARCHIVE_DIR" \
  --height "$H1" \
  --block-hash "$H1_BLOCK_HASH" \
  --state-root "$H1_STATE_HASH" \
  --block-timestamp "$H1_BLOCK_TS" \
  --state-manifest-path "$STATE_MANIFEST_REL" \
  --state-manifest-sha256 "$STATE_MANIFEST_SHA" \
  --blob-coverage-path "$COVERAGE_H1_REL" \
  --blob-coverage-sha256 "$COVERAGE_H1_SHA" \
  --blob-coverage-from-height "$FROM_HEIGHT" \
  --blob-coverage-to-height "$H1" \
  --blob-coverage-to-block-hash "$H1_BLOCK_HASH" \
  --out "$LOCAL" \
  $(sign_args)

ARCHIVE_MANIFEST="$(find "$LOCAL/v1/archive/checkpoints" -name archive-manifest.json | sort | tail -1)"
ARCHIVE_REL="${ARCHIVE_MANIFEST#"$LOCAL/"}"
cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -- archive-publish \
  --config "$WORKDIR/config.toml" \
  --target local_validation \
  "$ARCHIVE_MANIFEST" >/dev/null
if [[ -n "$SIGNING_KEY" ]]; then
  cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -- archive-promote \
    --config "$WORKDIR/config.toml" \
    --target local_validation \
    --archive-manifest "$ARCHIVE_REL" \
    --label latest >/dev/null
fi
ORIGINAL_H1_EVENTS="$WORKDIR/original-h1-events.json"
graphql "{ contractEvents(height: $H1) { json } }" | jq -S . > "$ORIGINAL_H1_EVENTS"

echo "sending second blob transaction for post-checkpoint coverage"
TX2="$(send_blob_tx 2)"
TX2_HEIGHT="$(wait_for_tx "$TX2" "$START_TIP")"
H2="$MIN_H2"
if (( TX2_HEIGHT > H2 )); then
  H2="$TX2_HEIGHT"
fi
echo "second blob tx included at height $TX2_HEIGHT; proving blob coverage through H2=$H2"
wait_tip "$H2"

NEXT_FROM="$((H1 + 1))"
echo "exporting block/blob descriptors for $NEXT_FROM..$H2"
cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -- blobs-export-range \
  --network "$NETWORK" \
  --rusk-url "$RUSK_URL" \
  --from-height "$NEXT_FROM" \
  --to-height "$H2" \
  --out "$DESCRIPTORS" >/dev/null

echo "packing H1+1..H2 blob range and full coverage"
RANGE2_MANIFEST="$(cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -- blobs-pack-range \
  --network "$NETWORK" \
  --from-height "$NEXT_FROM" \
  --to-height "$H2" \
  --descriptor-dir "$DESCRIPTORS" \
  --out "$LOCAL" \
  --previous-range-sha256 "$RANGE1_SHA" \
  $(sign_args))"
cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -- blobs-publish-range \
  --config "$WORKDIR/config.toml" \
  --target local_validation \
  "$RANGE2_MANIFEST" >/dev/null
COVERAGE_H2_MANIFEST="$(cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -- blobs-write-coverage \
  --network "$NETWORK" \
  --out "$LOCAL" \
  $(sign_args) \
  "$RANGE1_MANIFEST" "$RANGE2_MANIFEST")"
COVERAGE_H2_REL="${COVERAGE_H2_MANIFEST#"$LOCAL/"}"
cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -- blobs-publish-coverage \
  --config "$WORKDIR/config.toml" \
  --target local_validation \
  "$COVERAGE_H2_MANIFEST" >/dev/null

echo "verifying completeness from published manifests"
cargo run --manifest-path "$ROOT/Cargo.toml" -- verify-archive-complete \
  --config "$WORKDIR/config.toml" \
  --source local_validation \
  --archive-manifest "$ARCHIVE_REL" \
  --target-height "$H1"
cargo run --manifest-path "$ROOT/Cargo.toml" -- blobs-verify-coverage \
  --config "$WORKDIR/config.toml" \
  --source local_validation \
  --coverage-manifest "$COVERAGE_H2_REL" \
  --from-height "$FROM_HEIGHT" \
  --to-height "$H2"

echo "restoring state and archive artifacts from manifests"
RESTORE_PROFILE="$WORKDIR/restored-profile"
RESTORE_ARCHIVE="$RESTORE_PROFILE/archive"
rm -rf "$RESTORE_PROFILE" "$RESTORE_ARCHIVE"
cargo run --manifest-path "$ROOT/Cargo.toml" -- archive-restore-complete \
  --config "$WORKDIR/config.toml" \
  --source local_validation \
  --archive-manifest "$ARCHIVE_REL" \
  --target-height "$H1" \
  --destination-profile "$RESTORE_PROFILE" \
  --archive-dir "$RESTORE_ARCHIVE"

check_restored_node

jq -n \
  --arg tx1 "$TX1" \
  --arg tx2 "$TX2" \
  --argjson h1 "$H1" \
  --argjson h2 "$H2" \
  --arg archive_manifest "$ARCHIVE_REL" \
  --arg h2_coverage "$COVERAGE_H2_REL" \
  '{
    tx1: $tx1,
    tx2: $tx2,
    h1: $h1,
    h2: $h2,
    archive_manifest: $archive_manifest,
    h2_coverage_manifest: $h2_coverage
  }' > "$WORKDIR/proof-summary.json"

echo "local archive/blob snapshot validation completed"
