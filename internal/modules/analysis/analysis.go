// Package analysis embeds the change-analysis module, built from
// rust/crates/analysis by scripts/build-wasm.sh.
package analysis

import _ "embed"

// Wasm is the module binary.
//
//go:embed analysis.wasm
var Wasm []byte
