#!/usr/bin/env bash
# Build one pinned native library and bind its metadata to the source commit.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
source_commit=$(python3 "$repo/scripts/native/source.py" "$repo")
snapshot=$(mktemp -d)
trap 'rm -rf "$snapshot"' EXIT
git -C "$repo" archive "$source_commit" | tar -xf - -C "$snapshot"
output=${1:-$repo/internal/native/_artifacts/$(go env GOOS)_$(go env GOARCH)}
target=${2:-$(rustc -vV | sed -n 's/^host: //p')}
toolchain=$(sed -n 's/^channel = "\([^"]*\)"$/\1/p' "$snapshot/rust-toolchain.toml")
cargo_home=$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd)
rustup_home=$(cd "${RUSTUP_HOME:-$HOME/.rustup}" && pwd)
mkdir -p "${CARGO_TARGET_DIR:-$repo/rust/target}" "$output"
export CARGO_TARGET_DIR=$(cd "${CARGO_TARGET_DIR:-$repo/rust/target}" && pwd)
output=$(cd "$output" && pwd)
export RUSTFLAGS="--remap-path-prefix=$snapshot=/cedar-cgo --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$rustup_home=/rustup --remap-path-prefix=$CARGO_TARGET_DIR=/cedar-target"
export CARGO_INCREMENTAL=0
unset CARGO_BUILD_RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
(cd "$snapshot" && cargo +"$toolchain" rustc --manifest-path "$snapshot/rust/Cargo.toml" --locked --profile native --target "$target" -p cgw-native -- --print=native-static-libs) 2> "$output/build.log"
cat "$output/build.log"
cp "$CARGO_TARGET_DIR/$target/native/libcgw_native.a" "$output/libcgw_native.a"
cp "$snapshot/internal/native/include/cedar.h" "$output/cedar.h"
python3 "$snapshot/scripts/native/manifest.py" "$output" "$source_commit" "$target" "$toolchain"
rm "$output/build.log"
if [[ $# == 0 ]]; then
 "$repo/scripts/install-native.sh" "$output" "$source_commit" "$target"
fi
