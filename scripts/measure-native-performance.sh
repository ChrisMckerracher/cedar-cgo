#!/usr/bin/env bash
set -euo pipefail
: "${CVC5:?Set CVC5 to the pinned cvc5 executable}"
repo=$(cd "$(dirname "$0")/.." && pwd)
baseline=${1:?Provide the pinned a7083b5 Wasm checkout}
output=${2:?Provide the measurement output directory}
mkdir -p "$output"
output=$(cd "$output" && pwd)
baseline=$(cd "$baseline" && pwd)
test "$(git -C "$baseline" rev-parse HEAD)" = a7083b5cb27dae4ec8be5f84d8f7b88b4a1fbcc6
comparison=$(mktemp -d)
trap 'rm -rf "$comparison"' EXIT
export GOMAXPROCS=2
export CEDAR_BENCH_FIXTURES="$repo/testdata"
export GOPROXY=off
export GOSUMDB=off
native_source=$(python3 "$repo/scripts/performance/source-hash.py" "$repo" "$output/native-source.json")
wasm_source=$(python3 "$repo/scripts/performance/source-hash.py" "$baseline" "$output/wasm-source.json")
archive="$repo/internal/native/lib/$(go env GOOS)_$(go env GOARCH)/libcgw_native.a"
native_archive=$(sha256sum "$archive" | cut -d ' ' -f 1)
python3 "$repo/scripts/performance/prepare-comparison.py" "$repo" "$baseline" "$comparison"
gofmt -w "$comparison"
go -C "$comparison" test -mod=mod -c -o "$output/wasm.test" .
go -C "$repo" test -c -o "$output/native.test" ./internal/verification/performance
{
    date -u +'%Y-%m-%dT%H:%M:%SZ'
    uname -a
    go version
    rustc --version
    "$CVC5" --version
    git -C "$repo" rev-parse HEAD
    git -C "$repo" status --short
    sha256sum "$repo/rust/Cargo.lock" "$repo/internal/native/include/cedar.h"
    sha256sum "$archive" "$output/native.test" "$output/wasm.test"
    sha256sum "$baseline/internal/modules/analysis/analysis.wasm" "$baseline/internal/modules/authorizer/authorizer.wasm"
    printf '%s\n' 'GOMAXPROCS=2; pool cap=2; native concurrency cap=2; Wasm concurrency follows two benchmark workers.'
    printf '%s\n' 'No compilation cache. Authorization reuses loaded state. Compiled analysis has one warm query.'
    printf '%s\n' 'Each sample starts a fresh benchmark process. Native static linking is outside timed Runtime construction.'
    printf '%s\n' 'Order alternates native/Wasm per sample. RSS measures the parent process after closed solver sessions.'
    printf 'Native source: %s\nWasm source: %s\n' "$native_source" "$wasm_source"
} > "$output/environment.txt"
for sample in 1 2 3 4 5; do
    if (( sample % 2 )); then order=(native wasm); else order=(wasm native); fi
    for engine in "${order[@]}"; do
        for workload in Serial Parallel Runtime Load Callback Compiled Solver; do
            case "$workload" in
                Serial|Parallel|Callback) iterations=1000 ;;
                Runtime) iterations=5 ;;
                Load|Compiled) iterations=100 ;;
                Solver) iterations=20 ;;
            esac
            "$output/$engine.test" -test.run '^$' -test.bench "^BenchmarkControlled$workload$" \
                -test.benchtime "${iterations}x" -test.count 1 -test.cpu 2 \
                > "$output/$engine-$workload-$sample.txt"
        done
    done
 done
"$output/native.test" -test.run '^TestNativeResourceTrend$' -test.v > "$output/resources.txt"
"$output/native.test" -test.run '^TestNativeResourceTrend$' -test.count 3 -test.cpu 2 -test.v > "$output/resources-followup.txt"
test "$native_source" = "$(python3 "$repo/scripts/performance/source-hash.py" "$repo")"
test "$wasm_source" = "$(python3 "$repo/scripts/performance/source-hash.py" "$baseline")"
test "$native_archive" = "$(sha256sum "$archive" | cut -d ' ' -f 1)"
printf '%s\n' 'Source and backend hashes remained unchanged throughout the measurements.' >> "$output/environment.txt"
rm "$output/native.test" "$output/wasm.test"
