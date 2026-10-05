# Native security model for Cedar Go consumers

Cedar runs in the consumer process through cgo.
The native library provides Cedar semantics and explicit ownership checks.
It does not provide a Wasm sandbox or a separate process.

## Inputs and decisions

Source, request, response, callback, and solver output sizes have explicit limits.
Input validation rejects invalid UTF-8 before JSON encoding can change an identity.
Integer values retain their exact signed 64-bit representation.

Concrete authorization returns Deny on every operation error.
Partial evaluation returns Undecided on operation error.
Policy evaluation diagnostics remain separate from transport errors and can accompany an Allow decision.

Configuration loading parses policies, schemas, and entities.
Strict policy validation remains a separate operation.
Batched authorization requires a schema and strictly valid policies.

## Lifetime and concurrency

Runtime closure rejects new calls and invalidates dependent clients.
Session closure waits for active native execution before releasing state.
Opaque handle identities reject stale and foreign ownership.
Go callback identifiers remain live until their synchronous native call returns.

Loaded authorizers share one session implementation for ordinary, batched, and partial operations.
Explicit runtime and pool limits bound native concurrency.
Compiled analysis serializes solver interaction and retains immutable policy snapshots.

## Cancellation and faults

Context cancellation prevents acquisition and native entry when already observed.
Callbacks observe the call context. Solver cancellation closes its transport to unblock input and output.
After Rust returns, Go rejects a result if it observes cancellation.

A Go deadline cannot forcibly interrupt native CPU work.
A loader that ignores cancellation can delay both cancellation and closure.
Active-call resources remain owned until Rust returns.

The native profile catches recoverable Rust panics at the C interface.
A caught panic invalidates affected mutable state.
Go callback panics become operation errors.

Allocation aborts, stack overflow, and fatal process faults can terminate the process.
Deep-input fault tests use disposable child processes.
Use a separate worker process if your application requires fault containment or a hard process memory limit.

## Memory and formatting

Native memory has no per-session hard heap limit.
Go heap statistics do not measure Rust allocation.
Process memory measurements include shared runtime costs and allocator retention.

Positive formatter indentation cannot exceed its output byte limit.
The formatter rejects tokenized delimiter depth above 256 before recursive formatting.
Strings and comments do not contribute delimiters to this depth limit.
These checks do not establish a general bound for every Cedar parser.

## Solver process

The solver is a separate executable selected by the consumer.
The supplied process adapter uses an empty environment and explicit arguments.
It bounds solver output and stderr, closes pipes, and waits for process exit.
The adapter does not install or own the solver executable.

## Supply chain

The native artifact verifier checks exact files, checksums, source, target, header, ABI, and pinned build inputs.
Consumer extraction rejects unsafe paths, duplicate members, symbolic links, and altered source or artifact records.
Release gates require every expected CI job to succeed for the exact main commit.
Release files have checksums and build provenance.

The release environment defines tested compiler and system runtime requirements.
See [platform requirements](migration/platforms.md) and the [native contract](migration/native-contract.md).
Report vulnerabilities through [SECURITY.md](../SECURITY.md).
