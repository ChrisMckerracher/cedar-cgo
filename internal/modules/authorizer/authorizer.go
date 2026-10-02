// Package authorizer embeds the guest rebuilt by scripts/build-wasm.sh.
package authorizer

import _ "embed"

//go:embed authorizer.wasm
var Wasm []byte
