#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
expected="$repo/testdata/parity/validation-depth/expected.json"
actual=$(mktemp)
trap 'rm -f "$actual"' EXIT
cargo run --manifest-path "$repo/rust/Cargo.toml" --locked --release -p cgw-authorizer --example validation_depth < "$repo/testdata/parity/validation-depth/input.json" > "$actual"
case "${1:---check}" in
  --write) cp "$actual" "$expected" ;;
  --check) diff -u "$expected" "$actual" ;;
  *) exit 2 ;;
esac
