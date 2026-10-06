#!/usr/bin/env bash
# Verify an artifact before installing its library and linker requirements.
set -euo pipefail
if [[ $# != 3 ]]; then
 echo 'usage: install-native.sh ARTIFACT_DIR SOURCE_COMMIT RUST_TARGET' >&2
 exit 1
fi
repo=$(cd "$(dirname "$0")/.." && pwd)
artifact=$(cd "$1" && pwd)
CGO_ENABLED=0 GOTOOLCHAIN=local GOWORK=off GOFLAGS= go run "$repo/cmd/verify-native-artifact" "$artifact" "$2" "$3" "$repo/internal/native/include/cedar.h"
platform=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["platform"])' "$artifact/manifest.json")
mkdir -p "$repo/internal/native/lib/$platform"
if [[ "$artifact" != "$repo/internal/native/lib/$platform" ]]; then
 cp "$artifact/libcgw_native.a" "$repo/internal/native/lib/$platform/"
fi
cmp "$artifact/cedar.h" "$repo/internal/native/include/cedar.h"
cp "$artifact/link_flags.go" "$repo/internal/native/link_flags.go"
