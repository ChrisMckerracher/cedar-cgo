#!/usr/bin/env bash
# Use clean Cargo target directories so cached builds cannot conceal changed output.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
[[ $# == 1 ]] || { echo "usage: $0 OUTPUT_DIR" >&2; exit 1; }
mkdir -p "$1"
output=$(cd "$1" && pwd)
[[ -z "$(ls -A "$output")" ]] || { echo "output directory must be empty" >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
source_commit=$(git -C "$repo" rev-parse HEAD)

for build in first second; do
	CARGO_TARGET_DIR="$work/$build/target" WASM_OUTPUT_DIR="$work/$build/artifact" "$repo/scripts/build-wasm.sh"
	(cd "$repo" && go run ./cmd/verify-wasm-artifact "$work/$build/artifact" "$source_commit")
done
diff -r "$work/first/artifact" "$work/second/artifact"
cp -R "$work/first/artifact/." "$output/"
echo "Both independent Wasm builds match. Artifact: $output"
