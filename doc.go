// Package cedar evaluates Cedar authorization policies with Cedar's Rust
// reference implementation, the cedar-policy crate, compiled to
// WebAssembly and run by wazero. It needs no cgo and no Rust toolchain.
//
// A [Runtime] verifies and compiles the embedded module once per process.
// An [Authorizer] holds one schema, one policy set and one entity set, and
// evaluates requests against them. [Runtime.Validate] runs Cedar's strict
// validator. Package analysis compares two policy sets with Cedar's
// symbolic compiler.
//
// # Failure behavior
//
// Authorize fails closed. Every error comes with the [Deny] decision, and
// [Deny] is the zero value of [Decision]. When the module traps, exits,
// runs out of memory, exceeds its timeout or breaks the ABI, the error
// matches [ErrFault] and the instance is discarded; the pool creates a
// fresh one for the next call. When Cedar rejects an input, such as a
// context that does not match the schema, the error is an [*Error] with
// the matching [ErrorKind], and the instance stays in the pool, because
// Cedar's state is read-only during a call.
//
// # Capabilities
//
// The module may import only these WASI functions, and the host refuses a
// module that imports anything else: random_get, which reads crypto/rand
// and seeds Rust's hash maps; environ_get and environ_sizes_get, which see
// an empty environment; fd_write, which discards stdout and keeps the
// first 4 KiB of stderr for fault messages; and proc_exit, which ends the
// instance. The module gets no files, no network, no clock, no arguments
// and no stdin.
//
// # Limits
//
// [WithMemoryLimit] caps each instance's linear memory. [Limits] caps the
// request size, the call time, the number of instances and the memory an
// instance may keep between calls. [WithMaxSourceBytes] caps the size of a
// schema, policies and entities.
package cedar
