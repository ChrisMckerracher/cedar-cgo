# Security model

[Documentation](README.md) · [Verification](verification.md) · [Report a vulnerability](../SECURITY.md)

## Contents

- [Execution model](#execution-model)
- [Guest capabilities](#guest-capabilities)
- [Resource limits](#resource-limits)
- [Failure behavior](#failure-behavior)
- [Solver process](#solver-process)
- [Build integrity](#build-integrity)

## Execution model

Cedar's Rust engine runs inside wazero's WebAssembly sandbox. The Go host
encodes inputs, calls the guest, and decodes results. Cedar makes the policy
decision. Each authorization instance owns its parsed configuration and
serves one call at a time; the pool provides concurrency through separate
instances.

Runtime startup verifies the embedded module's SHA-256, enforces an import
allowlist, rejects imported memories, and checks required exports. Each
instance must report the expected ABI version before use.

The ABI transfers JSON through guest linear memory. The guest owns input
buffers once a call starts. The host checks response addresses and sizes,
copies the response into Go memory, then frees the guest buffer. A failed
call marks the instance as faulted, and its resources are released when the
instance is discarded.

## Guest capabilities

The guest reaches host services through these imports:

| Import | Host behavior | Purpose |
|---|---|---|
| `random_get` | Reads `crypto/rand` | Seeds Rust's randomized hash maps |
| `environ_get`, `environ_sizes_get` | Empty environment | Rust standard-library startup |
| `fd_write` | Discards stdout; retains the first 4 KiB of stderr | Panic diagnostics |
| `proc_exit` | Ends the instance and produces a fault | Rust abort path |
| `clock_time_get` (analysis) | wazero's synthetic clock | tokio runtime |
| `poll_oneoff` (analysis) | wazero's no-op sleep | tokio runtime |
| `cgw_host.solver_write`, `cgw_host.solver_read` (analysis) | Solver stdin and stdout | SMT-LIB queries and replies |

Files, network access, arguments, stdin, and the real clock are not granted
to the guest. An added import requires an explicit allowlist change and
security review.

## Resource limits

| Resource | Authorization default | Analysis default |
|---|---|---|
| Linear memory per instance | 256 MiB | 1 GiB |
| Guest execution deadline | 1 s per `Authorize` call | 60 s per analysis call, including solver time |
| Instance creation and load deadline | 30 s | Included in the analysis deadline |
| Encoded request, including context and extra entities | 1 MiB | Included in source input |
| Encoded source input | 64 MiB per load or validation | 64 MiB per comparison |
| Response size | 16 MiB | 256 MiB |
| Retained linear memory before recycling | 64 MiB | Instance closed after each call |
| Instances | Up to `GOMAXPROCS` per authorizer | One per concurrent call |
| Solver output | — | 256 MiB per call |

Runtime options and per-authorizer `Limits` configure the budgets, except
for the fixed response-size caps. The caller's context bounds waiting for
an authorization instance and bounds validation, which uses a fresh
instance. Analysis concurrency is controlled by the application.

The guest's 8 MiB stack sits below its data. Stack overflow traps instead
of overwriting data. Actual nesting limits depend on the workload and
embedded version; the fault tests exercise deep policy input.

## Failure behavior

| Condition | Decision | Go error | Instance |
|---|---|---|---|
| Cedar rejects the request, entities, context, or a UID | Deny | `*cedar.Error` with the matching kind | Reused |
| Encoded input exceeds a size limit | Deny | `KindLimit` | Not acquired |
| Guest execution exceeds its deadline | Deny | Matches `ErrFault` and `context.DeadlineExceeded` | Discarded |
| Caller cancels or its deadline expires | Deny | Wraps the context error | Discarded when cancellation interrupts guest execution |
| Guest traps or aborts, including memory exhaustion and stack overflow | Deny | Matches `ErrFault`, with bounded guest stderr | Discarded |
| Guest response violates the protocol | Deny | Matches `ErrFault` | Discarded |

`Deny` is the zero value of `Decision`. `Authorizer.Stats` counts created
and discarded instances, and the pool creates replacements when needed.
Cedar input errors permit reuse because authorization reads the configured
state without mutating it.

Policy evaluation diagnostics in `Response.Errors` follow Cedar semantics:
Cedar skips those policies and decides using the remaining ones. They are
distinct from a returned Go error and can accompany an `Allow` decision.

## Solver process

The provided `analysis.Command` starts a solver with an empty environment,
uses pipes for SMT-LIB, captures bounded stderr, and kills the process on
context cancellation or session closure.

The solver is a native host process with the permissions of the application
user. The guest sandbox and linear-memory limit do not constrain that
process's filesystem access or memory. Deployments that need those limits
should apply OS-level process isolation or provide a `Solver` adapter with
the required controls.

Counterexamples are checked with Cedar's concrete authorizer. A property
that holds depends on the solver's `unsat` answer and SymCC's encoding.
The [verification guide](verification.md) separates these trust assumptions
from the tests and proofs.

## Build integrity

The repository commits the modules, their SHA-256 values, Cargo's lockfile,
and a pinned Rust toolchain. CI rebuilds the modules and requires identical
bytes. Hash checks catch module corruption; the source, expected hashes,
compiler, and host runtime remain part of the trusted build and execution
environment.

Release builds attest module provenance and publish checksums. See
[Maintenance](maintenance.md#reproducible-builds) for reproduction and
verification commands, and [SECURITY.md](../SECURITY.md) for private reporting.
