#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
output=${1:?Provide the measurement output directory}
mkdir -p "$output"
output=$(cd "$output" && pwd)
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
export GOMAXPROCS=2 GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
export CEDAR_BENCH_FIXTURES="$repo/testdata"
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$repo/rust/target}
archive="$repo/internal/native/lib/$(go env GOOS)_$(go env GOARCH)/libcgw_native.a"
artifact=${CEDAR_BENCH_ARTIFACT:-$repo/internal/native/_artifacts/$(go env GOOS)_$(go env GOARCH)}
cmp "$archive" "$artifact/libcgw_native.a"
cp "$artifact/manifest.json" "$output/artifact.json"
archive_hash=$(sha256sum "$archive" | cut -d ' ' -f 1)
source=$(python3 "$repo/scripts/performance/source-hash.py" "$repo" "$output/source.json")
cargo build --manifest-path "$repo/rust/Cargo.toml" --locked --offline --profile native \
    -p cgw-verification --bin native-bench
cp "$CARGO_TARGET_DIR/native/native-bench" "$temporary/rust-native"
go -C "$repo" test -c -o "$temporary/go-cgo.test" ./internal/verification/performance
{
    date -u +'%Y-%m-%dT%H:%M:%SZ'
    uname -a
    lscpu
    go version
    rustc --version
    git -C "$repo" rev-parse HEAD
    git -C "$repo" status --short
    sha256sum "$repo/rust/Cargo.lock" "$repo/internal/native/include/cedar.h"
    sha256sum "$archive" "$temporary/rust-native" "$temporary/go-cgo.test"
    cat "$output/artifact.json"
    printf '%s\n' 'Cargo native profile: opt-level=3, LTO=true, codegen-units=1, panic=unwind.'
    printf '%s\n' 'Fresh process per sample/workload; five samples; Rust/Go order alternates.'
    printf '%s\n' 'GOMAXPROCS=2; Go pool and native call caps=2; all workloads are serial.'
    printf '%s\n' 'Authorization: 20000 operations; load: 500; strict validation: 200.'
    printf '%s\n' 'All setup, input file reads, compilation and static linking are outside measured loops.'
    printf '%s\n' 'Each authorization result must allow with reason policy1 and no errors.'
    printf '%s\n' 'Validation must pass without errors, warnings or schema warnings.'
    printf 'Source digest: %s\n' "$source"
} > "$output/environment.txt"
for sample in 1 2 3 4 5; do
    if (( sample % 2 )); then order=(rust go); else order=(go rust); fi
    for engine in "${order[@]}"; do
        for workload in authorize load validate; do
            case "$workload" in
                authorize) iterations=20000; benchmark=Authorize ;;
                load) iterations=500; benchmark=Load ;;
                validate) iterations=200; benchmark=Validate ;;
            esac
            if [[ "$engine" == rust ]]; then
                "$temporary/rust-native" "$repo/testdata/joy" "$workload" "$iterations" \
                    > "$output/rust-$workload-$sample.json"
            else
                "$temporary/go-cgo.test" -test.run '^$' -test.bench "^BenchmarkRustCgo$benchmark$" \
                    -test.benchtime "${iterations}x" -test.count 1 -test.cpu 2 \
                    > "$output/go-$workload-$sample.txt"
            fi
        done
        if [[ "$engine" == rust ]]; then
            "$temporary/rust-native" "$repo/testdata/joy" decision 20000 \
                > "$output/rust-decision-$sample.json"
        fi
    done
done
test "$source" = "$(python3 "$repo/scripts/performance/source-hash.py" "$repo")"
test "$archive_hash" = "$(sha256sum "$archive" | cut -d ' ' -f 1)"
printf '%s\n' 'Source and native archive hashes remained unchanged during all samples.' >> "$output/environment.txt"
python3 "$repo/scripts/performance/summarize-rust-cgo.py" "$output"
