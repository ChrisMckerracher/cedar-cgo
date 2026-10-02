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
| Encoded source input | 64 MiB per load, validation or format | 64 MiB per comparison |
| Response size | 16 MiB | 256 MiB |
| Retained linear memory before recycling | 64 MiB | Instance closed after each call |
| Instances | Up to `GOMAXPROCS` per authorizer | One per concurrent call |
| Solver output | — | 256 MiB per call |

Runtime options and per-authorizer `Limits` configure the budgets, except
for the fixed response-size caps. The caller's context bounds waiting for
an authorization instance and bounds validation, which uses a fresh
instance. Formatting also uses a fresh instance per call, with the runtime's
source, response, and memory caps; only the caller's context bounds time.
`WithFormatMaxOutputBytes` can reduce the raw result limit below the fixed
16 MiB encoded-response cap. Intermediate allocations remain subject to the
memory cap. The application controls formatting and analysis concurrency.

The guest's 8 MiB stack sits below its data. Stack overflow traps instead
of overwriting data. Actual nesting limits depend on the workload and
embedded version; the fault tests exercise deep policy input.

## Failure behavior

All input strings must contain valid UTF-8. This includes source text, entity
types and IDs, values, record keys, and raw JSON bytes. The Go boundary checks
these inputs before JSON encoding can replace malformed bytes with `U+FFFD`.
Valid Unicode, including `U+FFFD`, retains its identity without normalization.

Malformed UTF-8 returns `KindInput` before instance acquisition in every request
mode. Ordinary authorization and reauthorization return `Deny`; partial
authorization returns `Undecided`. Analysis returns an input error before starting
the solver. Loader results are checked before transfer to the guest; malformed
UTF-8 returns `KindInput` and discards the interrupted instance.

The table describes ordinary authorization and residual reauthorization.
Experimental `PartialAuthorize` returns `Undecided` on these failures with the
same error and instance handling; see [partial evaluation](partial-evaluation.md).

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

Formatting returns no text on error and always closes its temporary instance.
Its input and raw output size failures use `KindLimit`; guest faults and an
oversized encoded response use `KindFault`. Loaded authorizers are unaffected.

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

### Experimental entity-loader callbacks

Batched authorization adds exactly two allowlisted imports,
`cgw_entity_loader.load` and `cgw_entity_loader.read`. Their state belongs to one
call context, with serial load/read ownership and no global callback registry.
The host checks guest memory bounds and byte/call budgets before deserializing
UIDs or invoking the application loader. The result is sized before a guest
allocation, then copied once into the exact destination. A failed host callback
closes and discards that instance; returned errors cannot become an allow or a
known-missing entity. Guest-side entity parsing errors are latched across the
remaining bounded upstream iterations and returned as errors.

Application loaders are trusted host code: they can allocate memory or block
outside Wasm's limits and must honor the supplied context. The bridge uses no
background callback goroutines. Complete ancestor data and consistency across
rounds remain the loader's responsibility, matching upstream's experimental
contract. This API does not imply a proof of convergence or correctness for
malicious/inconsistent entity stores.
