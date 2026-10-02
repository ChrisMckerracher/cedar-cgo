// Package wasmhost runs the cedar-go-wasm guest modules under wazero.
//
// It compiles a module once, checks its SHA-256 and its imports, and creates
// instances that grant no WASI capabilities beyond the ones listed in
// [Config.AllowedImports]. Each instance runs one call at a time.
package wasmhost
