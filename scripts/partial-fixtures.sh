#!/usr/bin/env bash
# Regenerate via direct native Cedar APIs; --check rejects stale expected results.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
output=$(mktemp)
trap 'rm -f "$output"' EXIT
cargo run --offline --locked --release --manifest-path "$repo/rust/Cargo.toml" \
  -p cgw-native-bench --example partial_fixture \
  < "$repo/testdata/parity/partial/input.json" > "$output"
if [[ ${1:-} == --check ]]; then
  diff -u "$repo/testdata/parity/partial/expected.json" "$output"
else
  cp "$output" "$repo/testdata/parity/partial/expected.json"
fi
