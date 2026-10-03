#!/usr/bin/env bash
set -euo pipefail
: "${CVC5:?Set CVC5 to the pinned cvc5 executable}"
repo=$(cd "$(dirname "$0")/.." && pwd)
actual=$(mktemp)
trap 'rm -f "$actual"' EXIT
cargo run --manifest-path "$repo/rust/Cargo.toml" --locked --release -p cgw-analysis --example analysis_queries < "$repo/testdata/parity/analysis-queries/input.json" > "$actual"
case "${1:---check}" in
  --write) cp "$actual" "$repo/testdata/parity/analysis-queries/expected.json" ;;
  --check) diff -u "$repo/testdata/parity/analysis-queries/expected.json" "$actual" ;;
  *) exit 2 ;;
esac
