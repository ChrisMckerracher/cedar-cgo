# Performance

[Documentation](README.md) · [API](api.md) · [Change analysis](analysis.md)

## Native Rust and production Go/cgo

These measurements were recorded on 2026-10-06.
The native artifact identifies source commit `562355e087e3667a1c1e887513c7e4f878484ba7`.
The machine used an AMD Ryzen 5 5600X, Linux 6.19.10, Go 1.27.1, and Rust 1.99.0.
Both executables used pinned Cedar 4.13.0 and the optimized Cargo `native` profile.
That profile uses optimization level three, link-time optimization, one code generation unit, and panic unwinding.

Both implementations use the [Joy fixture](../testdata/joy): 45 policies, five supplied entities, and five schema action entities.
Authorization uses the same permitted `session.write` request, context values, schema, policies, and entities.
Every authorization result must allow access, report reason `policy1`, and contain no errors.
Strict validation must pass without errors, policy warnings, or schema warnings.
Both implementations check results inside their measured loops.

### Results and scope

The table reports the median of five samples for each workload.
The ratio divides the Go/cgo median by the native Rust median.
Ratios describe these inputs and measured scopes on this machine.
They do not isolate the cost of one cgo call.

| Workload | Native Rust median | Production Go/cgo median | Go/cgo ÷ Rust |
|---|---:|---:|---:|
| Authorization with request construction and result serialization | 95.694 µs | 135.021 µs | 1.41 |
| Load and release an authorizer | 1.664 ms | 2.018 ms | 1.21 |
| Strict validation with schema and policy parsing | 3.848 ms | 4.341 ms | 1.13 |

Native Rust calls upstream Cedar APIs directly.
Authorization reconstructs entity identifiers, parses the context JSON, builds the request, evaluates policies, and serializes the complete successful result.
It reuses the loaded schema, policies, entities, and Cedar authorizer.
Loading parses the schema, policies, and entities, then creates and releases Cedar state.
Validation parses the schema and policies, constructs a strict validator, and serializes the successful result.

Production Go/cgo measures the public Go interfaces.
It also encodes inputs, decodes the outer request in Rust, crosses cgo, and decodes results in Go.
Its runtime checks deadlines and input limits.
Authorization also obtains and returns a pooled authorizer instance.
Loading creates and closes that pool.
Native Rust excludes these Go interface and transport operations.

The separate native decision median is **40.955 µs**.
That workload reuses a parsed request and excludes request construction and result serialization.
It includes result checks and response release.
Its scope differs from the authorization row above.
These measurements exclude solver analysis, loader callbacks, partial evaluation, and concurrent authorization.

### Controls and evidence

Each sample starts a fresh process for one workload.
Engine order alternates between samples.
All workloads run serially.
`GOMAXPROCS`, the Go pool limit, and the native call limit are two.
Setup, input file reads, compilation, and static linking are outside measured loops.
Competing builds, tests, and fuzzing were paused during measurement.

Authorization and parsed-request decisions use 20,000 operations per sample.
Loading uses 500 operations; validation uses 200.
Each Go authorization sample retained one idle instance and reported zero discarded instances.
Each Go load operation checked one created instance and zero discarded instances before closing the authorizer.
CPU frequency and all host scheduling were not controlled.

[Raw samples](../testdata/performance/rust-cgo/) retain all five values for every workload.
[The summary](../testdata/performance/rust-cgo/summary.json) records medians, minimum values, maximum values, and ratios.
[The environment record](../testdata/performance/rust-cgo/environment.txt) identifies the kernel, CPU, toolchains, controls, and executable hashes.
[The artifact manifest](../testdata/performance/rust-cgo/artifact.json) identifies the installed native archive and its source commit.
[The source manifest](../testdata/performance/rust-cgo/source.json) identifies the measured implementation, inputs, and scripts.
Source and archive hashes remained unchanged throughout the measurements.
Go allocation counters exclude Rust allocations.

### Reproduce the Rust and Go/cgo comparison

Use a clean checkout with the existing pinned toolchains and cached dependencies.
Build and install the native artifact before measurement.
Pause competing builds, tests, and fuzzing.

```bash
scripts/build-native.sh
scripts/measure-rust-cgo-performance.sh /tmp/cedar-rust-cgo-performance
```

The runner builds both executables before taking samples.
It uses Cargo offline mode and preserves every raw sample.
If the verified artifact uses another directory, set `CEDAR_BENCH_ARTIFACT`.
If an implementation or input changes, re-measure the affected workloads.
