#!/usr/bin/env bash
# Regenerate with the direct upstream native oracle, then compare its committed output.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
output=$(mktemp)
trap 'rm -f "$output"' EXIT
cd "$repo/rust"
cargo run --offline --locked --release -p cgw-verification --bin batched-oracle < "$repo/testdata/parity/batched/input.json" > "$output"
diff -u "$repo/testdata/parity/batched/expected.json" "$output"
cd "$repo"
go test -count=1 -run '^TestBatchedNativeParity$' ./cedar/authorization/batched
