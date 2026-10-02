#!/usr/bin/env bash
# Writes THIRD_PARTY_LICENSES.txt: the license of every crate that the
# WebAssembly modules contain, from rust/Cargo.lock, with cargo-about.
#
# Usage: scripts/third-party-licenses.sh
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo/rust"
cargo about generate --workspace --locked --fail --config about.toml about.hbs -o "$repo/THIRD_PARTY_LICENSES.txt"
# Some license texts use CRLF line endings; store the file with LF only.
sed -i 's/\r$//' "$repo/THIRD_PARTY_LICENSES.txt"
