#!/usr/bin/env bash
# Compile and run an independent Go consumer against the release source bundle.
set -euo pipefail

if [[ $# != 2 ]]; then
	echo 'usage: check-consumer.sh SOURCE_ZIP SOURCE_COMMIT' >&2
	exit 1
fi
repo=$(cd "$(dirname "$0")/.." && pwd)
bundle=$(realpath "$1")
consumer_tmp=$(mktemp -d)
trap 'rm -rf "$consumer_tmp"' EXIT

python3 "$repo/scripts/consumer/extract.py" "$bundle" "$2" "$consumer_tmp"
mkdir "$consumer_tmp/consumer" "$consumer_tmp/bin"
cp "$repo/scripts/consumer/smoke/main.go" "$consumer_tmp/consumer/main.go"
# These guards prove that the consumer does not build the Rust modules.
for tool in cargo rustc rustup; do
	printf '#!/bin/sh\necho "Unexpected Rust invocation" >&2\nexit 99\n' >"$consumer_tmp/bin/$tool"
	chmod +x "$consumer_tmp/bin/$tool"
done
export PATH="$consumer_tmp/bin:$PATH"
export GOMODCACHE="$consumer_tmp/modcache" GOCACHE="$consumer_tmp/buildcache"
export GOWORK=off GOFLAGS= GOTOOLCHAIN=local CGO_ENABLED=0
if [[ -n ${CONSUMER_GOPROXY:-} ]]; then
	export GOPROXY="$CONSUMER_GOPROXY"
fi
if [[ -n ${CONSUMER_GOSUMDB:-} ]]; then
	export GOSUMDB="$CONSUMER_GOSUMDB"
fi
cd "$consumer_tmp/consumer"
go mod init consumer.example
go mod edit -replace="github.com/ChrisMckerracher/cedar-go-wasm=$consumer_tmp/cedar-go-wasm"
go get github.com/ChrisMckerracher/cedar-go-wasm/cedar github.com/ChrisMckerracher/cedar-go-wasm/analysis
go run .
