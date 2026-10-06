# Native ownership review

An independent agent reviewed the native interface on 2026-10-05.
The review found no concrete ownership defect within the declared C interface contracts.
The review covers the following files:

- [`ffi.rs`](../../rust/crates/native/src/ffi.rs)
- [`entries.rs`](../../rust/crates/native/src/entries.rs)
- [`buffers.rs`](../../rust/crates/native/src/buffers.rs)
- [`callback.rs`](../../rust/crates/abi/src/callback.rs)
- [`cedar.h`](../../internal/native/include/cedar.h)
- [`instance.go`](../../internal/native/instance.go)

The [migration snapshot](https://github.com/ChrisMckerracher/cedar-cgo/tree/2c35de826bde1350108eb5d4df653618a8a14206) retains the source and artifact records used for this review.

## Input and callback lifetime

Native calls borrow input and callback buffers until synchronous execution returns.
Empty inputs can use null pointers.
Nonempty inputs reject null pointers and lengths above `isize::MAX` before slice construction.
The C caller must provide a readable allocation for each accepted length.
These checks cannot establish whether an arbitrary foreign address is readable.

Callback buffers borrow writable Rust allocations for one invocation.
The caller retains the callback function and identifier until the native call returns.
Compiled analysis replaces its callback before each query and clears it afterward.
The Go transport retains active callback resources until native execution returns.

## State and close ordering

The registry assigns increasing handle identifiers and checks identifier exhaustion.
The registry never reuses a closed state identifier.
Calls retain an `Arc` reference and lock the state during execution.
Close removes the registry identifier before waiting for the state lock.
An active call retains its state until it releases that lock.

The Go instance sets its closing flag before waiting for an active call.
Queued calls check that flag under the instance lock.
This order rejects queued execution after close starts.
Module close also rejects new calls before waiting for existing instances.

## Response allocation and panic containment

Rust owns response allocations and registers each boxed byte slice.
The caller copies the response and frees the unchanged record exactly once.
Release checks the registered address and length before removing the allocation.
Allocation and release both use Rust ownership; Go does not free Rust memory directly.

Every exported native entry point contains recoverable Rust panics.
Panic payloads are forgotten because their destructors can panic during cleanup.
Failed execution removes its state before a separately contained drop.
This prevents a cleanup panic from unwinding across the C interface.
Fatal signals and allocation aborts remain process failures.

## Review limits

The exact-once response release rule is necessary.
An immediate repeated free test cannot establish safety after an allocator reuses the same address and length.
Foreign callers must preserve pointer validity, response records, and callback lifetime.
This source review does not prove Rust memory safety or replace native lifetime tests.
Go race and cgo pointer checks also do not inspect all Rust memory accesses.
