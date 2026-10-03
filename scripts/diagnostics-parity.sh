#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
actual=$(mktemp)
trap 'rm -f "$actual"' EXIT
cargo run --manifest-path "$repo/rust/Cargo.toml" --locked --release -p cgw-authorizer --example diagnostic_fixtures < "$repo/testdata/parity/diagnostics/input.json" > "$actual"
case "${1:---check}" in
  --write) cp "$actual" "$repo/testdata/parity/diagnostics/expected.json" ;;
  --check) diff -u "$repo/testdata/parity/diagnostics/expected.json" "$actual" ;;
  *) exit 2 ;;
esac
