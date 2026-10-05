#!/usr/bin/env bash
# Compare two clean native builds without sharing Cargo output directories.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
[[ $# == 1 || $# == 2 ]] || { echo "usage: $0 OUTPUT_DIR [RUST_TARGET]" >&2; exit 1; }
mkdir -p "$1"
output=$(cd "$1" && pwd)
[[ -z "$(ls -A "$output")" ]] || { echo 'output directory must be empty' >&2; exit 1; }
target=${2:-$(rustc -vV | sed -n 's/^host: //p')}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
source_commit=$(git -C "$repo" rev-parse HEAD)
for build in first second; do
 CARGO_TARGET_DIR="$work/$build/target" "$repo/scripts/build-native.sh" "$work/$build/artifact" "$target"
 go run "$repo/cmd/verify-native-artifact" "$work/$build/artifact" "$source_commit" "$target" "$repo/internal/native/include/cedar.h"
done
diff -r "$work/first/artifact" "$work/second/artifact"
cp -R "$work/first/artifact/." "$output/"
echo "Both independent native builds match. Artifact: $output"
