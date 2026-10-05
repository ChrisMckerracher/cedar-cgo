# Native performance

[Documentation](README.md) · [API](api.md) · [Change analysis](analysis.md)

## Measurement scope

These measurements were recorded on 2026-10-05 with the production Go interfaces.
Both backends include Go encoding, Cedar parsing and evaluation, result serialization, and Go decoding.
The [historical Wasm record](history/wasm-performance.md) preserves the earlier prototype measurements.

The machine used an AMD Ryzen 5 5600X, Linux 6.19.10, Go 1.27.1, and Rust 1.99.0.
Dependencies were Cedar 4.13.0, SymCC 0.7.0, wazero 1.12.0, and cvc5 1.3.1.
The native library used the optimized Cargo `native` profile with panic unwinding.

The comparison checkout was pinned to `a7083b5cb27dae4ec8be5f84d8f7b88b4a1fbcc6`.
The native implementation used a migration worktree based on that commit.
[Environment records](../testdata/performance/native-migration/environment.txt) identify source, libraries, toolchains, and executable hashes.
[Source manifests](../testdata/performance/native-migration/native-source.json) identify production Go, Rust, headers, and vendored SymCC files.
The native source digest is `a13a839f9dcbf4efb87e3a4a27163eeb0b8f4e7f4c407a46e3b8658c94c7ca06`.
The recorded source includes cancellation checks after Go decoding.

Authorization uses the [Joy fixture](../testdata/joy) and a permitted `session.write` request.
The callback workload loads one missing entity through the Go loader.
Analysis compares equivalent integer bounds through the real cvc5 process.
These measurements exclude partial evaluation and partial reauthorization.

## Controls and results

Each workload has five raw samples.
Each sample starts a new process, and backend order alternates between samples.
`GOMAXPROCS`, the authorizer pool limit, and native call concurrency are two.
The Wasm parallel workload also uses two workers and two pooled instances.
No compilation cache is enabled.
Other builds, tests, and fuzzing were paused during the comparison.

The table reports medians.
The ratio divides the Wasm median by the native median.
Parallel time is wall time per completed decision, rather than individual request latency.
Ratios describe these inputs and this machine.

| Workload | Native median | Wasm median | Ratio |
|---|---:|---:|---:|
| Serial authorization | 135.027 µs | 885.308 µs | 6.56 |
| Parallel authorization | 73.869 µs | 493.184 µs | 6.68 |
| Load an authorizer | 2.083 ms | 21.736 ms | 10.44 |
| Batched authorization with a loader callback | 55.528 µs | 260.195 µs | 4.69 |
| Reuse compiled analysis | 1.878 ms | 2.095 ms | 1.12 |
| Stateless analysis with a new solver process | 4.947 ms | 18.114 ms | 3.66 |

[Raw samples](../testdata/performance/native-migration/) preserve every timing, Go allocation count, and workload counter.
[The summary](../testdata/performance/native-migration/summary.json) preserves the five values and median for each workload.
Serial, parallel, and callback samples contain 1,000 operations.
Load and compiled samples contain 100 operations; stateless analysis samples contain 20.

Authorization reuses loaded state.
Every serial sample created one instance; every parallel sample created two.
Each load sample created and closed 100 authorizers.
All authorization samples reported zero discarded instances.
Each callback sample made 1,000 loader calls and retained one idle instance.

Compiled analysis creates two handles and performs one untimed warm query.
Each sample starts and closes one solver session, with 101 solver reads and writes.
Each stateless sample starts and closes 20 solver sessions, with 20 reads and writes.
Compiled timings exclude initial compilation; stateless timings include it.

## Runtime construction

| Workload | Native median | Wasm median |
|---|---:|---:|
| Construct and close a Runtime | 1.944 µs | 3.817 s |

Each Runtime sample contains five operations.
Wasm Runtime construction includes cold, uncached module compilation.
Native static linking occurs before process execution and lies outside the timed operation.
This comparison measures API construction cost, rather than total application startup or build cost.

## Resource observations

The release workload creates and closes 100 runtimes, authorizers, analyzers, and compiled sessions.
It performs 100 loader callbacks and explicitly releases 200 compiled handles.
It records 100 created authorizer instances, zero discarded instances, and 100 solver starts and closes.
Every solver process was closed before the memory checkpoint.

Process resident memory, or RSS, includes resident Go and native allocations.
The Go heap counter measures live Go allocations after garbage collection.
Benchmark `B/op` and `allocs/op` counters exclude Rust allocations and solver subprocess memory.

| Completed cycles | Process RSS | Live Go heap |
|---:|---:|---:|
| 0 | 8.01 MB | 115,176 bytes |
| 20 | 21.82 MB | 213,240 bytes |
| 40 | 22.97 MB | 219,584 bytes |
| 60 | 23.49 MB | 213,760 bytes |
| 80 | 23.49 MB | 220,568 bytes |
| 100 | 23.98 MB | 214,968 bytes |

[The first resource record](../testdata/performance/native-migration/resources.txt) contains exact checkpoint values.
[Three further runs in one process](../testdata/performance/native-migration/resources-followup.txt) cover 300 additional cycles.
After the first 100 cycles, RSS remained near 24 MB during the next 200 cycles.
The final checkpoint was 24.59 MB, with a live Go heap of 230,424 bytes.
These short runs show stable later checkpoints, but they do not establish a zero-leak guarantee.
RSS includes allocator retention and excludes memory from the already closed solver processes.
All resource runs used the same verified executable while competing builds, tests, and fuzzing remained paused.
Their durations are outside the benchmark comparison.

## Reproduce

Use existing pinned tools and a checkout at the comparison commit.
Build the native artifact before the measurements.
Pause competing builds, tests, and fuzzing before running the comparison.

```bash
CVC5=/path/to/cvc5 scripts/measure-native-performance.sh /path/to/pinned-wasm-checkout /tmp/cedar-performance
```

The script creates a temporary consumer for the pinned Wasm interfaces.
It uses the same benchmark inputs without editing the comparison checkout.
It rejects source or native archive changes during the comparison.
It records 100 resource cycles, then another 300 cycles in a new process using the same executable.
Re-measure affected workloads when their implementation or inputs change.
