# Performance

[Documentation](README.md) · [API](api.md) · [Change analysis](analysis.md)

## Contents

- [Workload and environment](#workload-and-environment)
- [Authorization](#authorization)
- [Change analysis](#change-analysis)
- [Startup and memory](#startup-and-memory)
- [Reproduce](#reproduce)

## Workload and environment

The measurements below were recorded on **2026-10-01**, using an AMD Ryzen
5 5600X (6 cores, 12 threads), Linux 6.19, Go 1.27.1, Rust 1.99.0,
wazero 1.12.0, Cedar 4.13.0, SymCC 0.7.0, and cvc5 1.3.1.

The shared fixture is [`testdata/joy`](../testdata/joy): 45 policies and a
schema with 10 request environments. Authorization uses a `session.write`
request whose context contains datetime, IP address, and record values.
Ratios compare measurements from this workload on this machine; they are
not a general bound for other policy sets.

## Authorization

| Measurement | Time | Relative to native with JSON |
|---|---|---|
| Native Cedar, prebuilt request | 49 µs | Different scope |
| Native Cedar, building the request from JSON and serializing reason IDs | 127 µs | 1× |
| Go `Authorize`, one instance, Go request to Go response | 1.22–1.24 ms | **9.6–9.8×** |

The native baseline includes context parsing, request construction, and
reason-ID serialization. The Go measurement additionally includes Go JSON
encoding, the pool, Wasm calls, and response decoding. Comparing to the
prebuilt native request instead gives 24.9–25.3×; that omits request handling
from the native side.

With 12 concurrent callers and 12 instances, the measured throughput was
**184–203 µs of wall time per completed decision**, or approximately
**4,900–5,400 decisions/second**. This is aggregate throughput, not the
latency experienced by an individual caller.

The main costs were measured separately:

| Same Rust workload under the wazero CLI | Prebuilt request | With JSON parsing |
|---|---|---|
| Standard execution | 210 µs | 497 µs |
| With execution deadline checks | 456 µs | 1,121 µs |

Wazero execution accounts for roughly 4–5× the native cost. Interruptible
execution roughly doubles that cost in this workload: wazero inserts loop
checks so a context can stop guest execution. The Go encoding and pool
added about 70 µs in the original measurements. These experiments explain
the tradeoff; the shipped runtime enables deadline checks.

## Change analysis

Both paths use cvc5 1.3.1 and the same schema and policy sets.

| Question | Result | Native SymCC | Go/Wasm | Ratio |
|---|---|---|---|---|
| Does adding a binding permit anything new? | Yes, in 8 of 10 environments, with counterexamples | 0.79 s | 1.19 s | **1.5×** |
| Does raising a device level permit anything new? | No, in all 10 environments | 0.19 s | 0.58 s | **3.1×** |

These are complete comparison timings, including solver work. Solver cost
varies with the property, so the ratio differs substantially between the
two questions. The native analysis and CLI breakdowns above are recorded
experiments; the checked-in native benchmark reproduces authorization.

## Startup and memory

| Measurement | Result |
|---|---|
| `cedar.NewRuntime`, cold compilation | 3.7 s |
| `cedar.NewRuntime`, warm disk compilation cache | 130 ms, about **28× faster** |
| `analysis.New`, cold compilation | 4.4 s |
| Load one authorization instance | 32 ms |
| Strict validation, including a fresh instance | 67 ms |
| Go heap per loaded authorization instance | 11.4 MB, including 9.6 MB of linear memory |
| `authorizer.wasm` | 5.47 MB; 1.51 MB gzip |
| `analysis.wasm` | 6.33 MB; 1.75 MB gzip |
| Stripped binary: hello world / with `cedar` / with `analysis` too | 1.5 MB / 10.8 MB / 17.1 MB |

Sizes use decimal MB. Instance heap measurements are per loaded instance,
rather than total process memory. Binary sizes depend on application code,
linker options, and toolchain.

Compile once per process, reuse authorizers, and use a
[disk compilation cache](api.md#runtime-lifecycle) for faster restarts.
Choose the pool size to balance throughput and memory. Load and validation
costs are paid when creating instances or checking policy changes.

## Reproduce

From the repository root, with the pinned tools available:

```bash
go test -run '^$' -bench . -benchmem -count 3 ./cedar
go test -run '^$' -bench . -count 3 ./analysis
CVC5=/path/to/cvc5 go test -run '^TestNewlyPermittedJoy$' -count 1 -v ./analysis
```

The analysis benchmark measures compilation; `TestNewlyPermittedJoy` logs
the two policy-comparison timings. Run the native authorization baseline
from `rust/`:

```bash
cd rust
cargo run --locked --release -p cgw-native-bench -- ../testdata/joy
```

Use `-cpu 12` on the Go benchmark to reproduce the caller count in the
parallel measurement. Keep version pins and fixtures identical between
comparisons, and record CPU, OS, toolchains, cache state, and concurrency
alongside new results.
