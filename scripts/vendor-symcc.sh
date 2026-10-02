#!/usr/bin/env bash
# Rebuilds rust/vendor/cedar-policy-symcc-0.7.0 from the crates.io release
# and rust/patches/cedar-policy-symcc-0.7.0-wasm.patch, and checks that the
# committed copy matches.
#
# The crate archive must match the checksum that crates.io publishes in its
# index, which is also the checksum that cargo verifies.
#
# Usage: scripts/vendor-symcc.sh          # check the committed copy
#        scripts/vendor-symcc.sh --write  # replace the committed copy
set -euo pipefail

name=cedar-policy-symcc
version=0.7.0
sha256=c4a1e6ff21119f50f3114451b9d7ac135690fe18759cc37a59d8aa5b1c797c5b

repo=$(cd "$(dirname "$0")/.." && pwd)
patch_file="$repo/rust/patches/$name-$version-wasm.patch"
vendored="$repo/rust/vendor/$name-$version"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

curl -sSfL -o "$work/crate.tar.gz" "https://static.crates.io/crates/$name/$name-$version.crate"
echo "$sha256  $work/crate.tar.gz" | sha256sum --check --quiet
tar xzf "$work/crate.tar.gz" -C "$work"
git -C "$work/$name-$version" apply -p1 "$patch_file"

if [[ "${1:-}" == "--write" ]]; then
	rm -rf "$vendored"
	cp -a "$work/$name-$version" "$vendored"
	echo "wrote $vendored"
else
	diff -r "$work/$name-$version" "$vendored"
	echo "$vendored matches crates.io $name $version plus the patch"
fi
