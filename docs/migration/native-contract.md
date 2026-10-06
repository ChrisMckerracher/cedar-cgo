# Native execution contract for Cedar Go consumers

This migration implements [tracker #49](https://github.com/ChrisMckerracher/cedar-cgo/issues/49).
The comparison source is commit `a7083b5cb27dae4ec8be5f84d8f7b88b4a1fbcc6`.
Cedar remains pinned to 4.13.0. SymCC remains pinned to 0.7.0.

## Execution and ownership

Go calls Rust synchronously through cgo. JSON envelopes preserve the existing operation inputs and outputs.
The C interface uses ABI version 2. It uses native pointers, `size_t` lengths, and opaque integer handles.
Rust owns session state and response buffers. Go copies each response before Rust releases its buffer.
Go lends input bytes only during the synchronous call. Rust copies all data that a session retains.
Callbacks use `runtime/cgo.Handle` identifiers. Rust never retains a Go pointer or a callback after the call.

Each loaded authorization session has a bounded pool.
The default pool contains at most eight entries. The runtime permits at most eight active native calls.
Consumers can set these explicit limits. The defaults do not depend on `GOMAXPROCS`. Each pool entry owns independently parsed Cedar state.
Ordinary, batched, and partial authorization share this session implementation.
Each analysis call owns a solver transport. Compiled analysis owns one transport for its session lifetime.
Compiled handles have monotonic identities. Release restores capacity but never reuses a handle identity.

Closing a runtime prevents new calls and invalidates its feature clients.
Closing a session waits for active native execution before releasing state.
Closing compiled analysis first closes the solver transport. This action unblocks solver input and output.
A loader callback must not close or recursively call its originating authorization session.

## Cancellation

An expired context prevents handle acquisition and native entry.
A callback observes its call context. An entity loader must observe cancellation itself.
A solver transport closes on cancellation to unblock solver input and output.
After native execution returns, Go rejects the result if it observes cancellation.
Go checks cancellation again after response decoding and clears canceled results.
An active-call cancellation invalidates mutable session state.

A Go deadline cannot forcibly stop Rust CPU execution.
The caller retains native state, input, callback identifiers, and buffers until Rust returns.
A blocked loader that ignores cancellation can therefore delay cancellation and close.

## Errors and panics

Concrete authorization returns Deny on every operation error.
Partial authorization returns Undecided on operation error.
Cedar policy evaluation diagnostics remain separate from transport errors. They can accompany an Allow decision.
Configuration loading parses and checks input. Strict policy validation remains an explicit operation.

Every foreign entry catches recoverable Rust panics. A caught panic invalidates affected mutable state.
The native build uses unwinding. No Rust unwind crosses the C interface.
Go callback panics become operation errors. Their callback identifiers remain valid until native execution returns.
Allocation aborts, stack overflow, and fatal process faults can terminate the process.
Native execution provides no process isolation against these faults.

## Resource limits and compatibility

Source, request, response, callback, solver output, handle count, and concurrency limits remain explicit.
Native allocation does not provide a per-session hard heap limit.
Go allocation counters exclude Rust allocation. Process memory must be measured separately.

| Previous control | Native replacement |
|---|---|
| Wasm linear-memory limit | Removed; use byte limits and concurrency limits |
| Wasm memory recycling threshold | Removed; release native state normally |
| Compilation cache | Removed; native code is compiled before Go links |
| Embedded module hash | Artifact manifest, source identity, and checksums |
| Interruptible guest CPU timeout | Context checks before entry, during callbacks, and after return |

Changed imports and constructors require a breaking release.
The module and repository use `cedar-cgo`.
Consumers must enable cgo and use a supported C compiler.
A source build also requires the pinned Rust toolchain. A verified prebuilt consumer bundle does not require Rust.
Analysis requires a separate solver. Verification uses cvc5 1.3.1.

## Platform completion

Linux amd64 GNU is the first implementation target.
Chris selected Linux amd64 GNU, Linux arm64 GNU, and macOS arm64 on 2026-10-05.
Windows and macOS amd64 are outside the new support matrix.
Each target needs an actual native build, consumer execution, compiler record, and runtime compatibility evidence.
The migration cannot declare untested targets supported or silently remove existing target coverage.
GNU, musl, and fully static builds have separate requirements and evidence.

The ownership rules follow [cgo pointer rules](https://pkg.go.dev/cmd/cgo#hdr-Passing_pointers).
Panic handling follows [Rust foreign-call unwinding rules](https://doc.rust-lang.org/nomicon/ffi.html#ffi-and-unwinding).
Linker requirements follow [Rust linkage rules](https://doc.rust-lang.org/reference/linkage.html).
