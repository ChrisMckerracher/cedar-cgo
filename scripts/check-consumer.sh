#!/usr/bin/env bash
# Run an independent native consumer with isolated Go caches and blocked Rust tools.
set -euo pipefail
if [[ $# != 2 ]]; then
 echo 'usage: check-consumer.sh SOURCE_ZIP SOURCE_COMMIT' >&2
 exit 1
fi
repo=$(cd "$(dirname "$0")/.." && pwd)
bundle=$(realpath "$1")
consumer_tmp=$(mktemp -d)
cleanup() { chmod -R u+w "$consumer_tmp"; rm -rf "$consumer_tmp"; }
trap cleanup EXIT
platform=$(go env GOOS)_$(go env GOARCH)
case "$platform" in
 linux_amd64) target=x86_64-unknown-linux-gnu ;;
 linux_arm64) target=aarch64-unknown-linux-gnu ;;
 darwin_arm64) target=aarch64-apple-darwin ;;
 *) echo "unsupported native consumer platform: $platform" >&2; exit 1 ;;
esac
solver=$(command -v "${CVC5:-cvc5}")
solver_version=$("$solver" --version)
[[ ${solver_version%%$'\n'*} =~ ^This\ is\ cvc5\ version\ 1\.3\.1([[:space:]]|$) ]] || { echo 'consumer proof requires cvc5 1.3.1' >&2; exit 1; }
export CVC5="$solver"
mkdir "$consumer_tmp/bin"
for tool in cargo rustc rustup; do
 printf '#!/bin/sh\necho "Unexpected Rust invocation" >&2\nexit 99\n' >"$consumer_tmp/bin/$tool"
 chmod +x "$consumer_tmp/bin/$tool"
done
export PATH="$consumer_tmp/bin:$PATH"
python3 "$repo/scripts/consumer/extract.py" "$bundle" "$2" "$consumer_tmp" "$target"
mkdir "$consumer_tmp/consumer"
cp "$repo/scripts/consumer/smoke/main.go" "$consumer_tmp/consumer/main.go"
export GOMODCACHE="$consumer_tmp/modcache" GOCACHE="$consumer_tmp/buildcache"
export GOWORK=off GOFLAGS= GOTOOLCHAIN=local CGO_ENABLED=1
if [[ -n ${CONSUMER_GOPROXY:-} ]]; then export GOPROXY="$CONSUMER_GOPROXY"; fi
if [[ -n ${CONSUMER_GOSUMDB:-} ]]; then export GOSUMDB="$CONSUMER_GOSUMDB"; fi
cd "$consumer_tmp/consumer"
go mod init consumer.example
go mod edit -replace="github.com/ChrisMckerracher/cedar-cgo=$consumer_tmp/cedar-cgo"
go get github.com/ChrisMckerracher/cedar-cgo/cedar github.com/ChrisMckerracher/cedar-cgo/analysis
go version
go env GOOS GOARCH CC CGO_ENABLED
# Source identity comes from checked bundle manifests; extraction has no Git checkout.
go build -buildvcs=false -o "$consumer_tmp/consumer-native" .
"$consumer_tmp/consumer-native"
if [[ $platform == linux_* ]]; then
 ldd "$consumer_tmp/consumer-native"
 readelf --version-info "$consumer_tmp/consumer-native"
else
 otool -L "$consumer_tmp/consumer-native"
fi
