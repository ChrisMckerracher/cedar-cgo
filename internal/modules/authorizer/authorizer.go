// Package authorizer embeds the authorization module, built from
// rust/crates/authorizer by scripts/build-wasm.sh.
package authorizer

import _ "embed"

// Wasm is the module binary.
//
//go:embed authorizer.wasm
var Wasm []byte
