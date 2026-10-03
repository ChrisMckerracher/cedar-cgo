#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
actual=$(mktemp)
trap 'rm -f "$actual"' EXIT
cargo run --manifest-path "$repo/rust/Cargo.toml" --locked --release -p cgw-authorizer --example literal_fixtures < "$repo/testdata/parity/literals/input.json" > "$actual"
case "${1:---check}" in
  --write) cp "$actual" "$repo/testdata/parity/literals/expected.json" ;;
  --check) diff -u "$repo/testdata/parity/literals/expected.json" "$actual" ;;
  *) exit 2 ;;
esac
