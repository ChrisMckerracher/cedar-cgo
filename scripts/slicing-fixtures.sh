#!/usr/bin/env bash
# Regenerate the direct native Cedar oracle, or compare it with the committed results.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
generated=$(mktemp)
trap 'rm -f "$generated"' EXIT
cd "$repo/rust"
cargo run --offline --locked --release -p cgw-native-bench --bin slicing-fixtures -- \
  "$repo/testdata/parity/slicing/cases.json" > "$generated"
if [[ ${1:-} == --check ]]; then
  diff -u "$repo/testdata/parity/slicing/expected.json" "$generated"
else
  cp "$generated" "$repo/testdata/parity/slicing/expected.json"
fi
