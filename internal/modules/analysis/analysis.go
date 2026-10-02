// Package analysis embeds the guest rebuilt by scripts/build-wasm.sh.
package analysis

import _ "embed"

//go:embed analysis.wasm
var Wasm []byte
