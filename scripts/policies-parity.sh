#!/usr/bin/env bash
# Regenerate the fixture from native Cedar, then compare or explicitly update it.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
fixture="$repo/testdata/parity/policies/native.json"
actual=$(mktemp)
trap 'rm -f "$actual"' EXIT
cargo run --manifest-path "$repo/rust/Cargo.toml" --locked --offline --release -p cgw-authorizer --example policies_oracle >"$actual"
case "${1:---check}" in
  --write) cp "$actual" "$fixture" ;;
  --check) diff -u "$fixture" "$actual" ;;
  *) echo 'usage: scripts/policies-parity.sh [--check|--write]' >&2; exit 2 ;;
esac
