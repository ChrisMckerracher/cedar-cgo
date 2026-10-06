# Native migration verification for Cedar Go maintainers

Reference source: `a7083b5cb27dae4ec8be5f84d8f7b88b4a1fbcc6`.
Migration tracker: [#49](https://github.com/ChrisMckerracher/cedar-cgo/issues/49).
Chris selected Linux amd64 GNU, Linux arm64 GNU, and macOS arm64.
The [platform contract](platforms.md) records this explicit scope change.

## Feature and package coverage

All 20 authorization feature operations and both analysis operations now use the native C interface.
The [operation inventory](operations.md) maps each operation and public declaration to its domain.
The production Go path contains no wazero dependency, embedded Wasm, or Wasm fallback.
Independent fixture programs call pinned Cedar and SymCC directly.
Expected fixture files remain unchanged.

The former Cedar package contained 98 Go files.
The composition package now contains two Go files.
Its largest feature package contains 28 files; analysis contains 41 files.
Implementations and tests share their domain directories.
All maintained Go files and Rust production files meet the 150-line target.
The 192-line Rust analysis session test module contains only conditionally compiled tests.
It keeps coupled session lifetime and handle exhaustion cases together and contains no production code.

The [declaration audit](../../testdata/migration/cedar-declarations.json) retains all 219 original Cedar verification declarations through explicit equivalents.
Seven examples use valid feature-factory names and retain their output.
The native runtime benchmark replaces the obsolete Wasm compilation-cache benchmark.
All 54 original analysis verification declarations remain.
The [literal audit](../../testdata/migration/literal-audit.json) checks moved source inputs, JSON fields, and corpus filters.
The [saved-input hashes](../../testdata/migration/saved-fuzz-inputs.json) preserve both original fuzz regression files byte for byte.

## Semantic checks and statement coverage

The complete pinned corpus passes through the native Go interface.
It contains 7,523 tests and 60,184 requests.
Checks compare decisions, reason IDs, evaluation error IDs, and strict validation.
All 18 independent parity checks pass without changing expected output.
All nine analysis queries and reusable compiled sessions pass with real cvc5 1.3.1.

Coverage combines feature packages with shared execution and uses `-coverpkg=./...`.
The gate compares exact statement fractions with the pinned reference, without a rounding allowance.

| Coverage group | Reference | Native candidate |
|---|---:|---:|
| Cedar and shared execution | 1,423/1,579; 90.12% | 1,501/1,645; 91.25% |
| Analysis | 474/544; 87.13% | 533/595; 89.58% |
| Artifact verification | 48/55; 87.27% | 148/149; 99.33% |

All 25 fuzz targets remain present.
Each target passed a complete local run of at least 60 seconds.
The publication gate runs every target for at least 60 seconds.
A missing target, failed target, or incomplete run blocks publication.

## Ownership and local checks

The [independent ownership review](ownership-review.md) records handle, buffer, callback, and shutdown contracts.
Go race checks and `GOEXPERIMENT=cgocheck2` pass.
Native lifetime tests cover queued calls during close, parent closure, fault invalidation, callback panics, and response caps.
Deterministic tests cancel during result decoding and reject authorization, stateless output, and session construction.
The timeout regression confirms native entry through a loader callback before testing discard and recovery.
A deadline before entry retains the untouched native handle for reuse.
Partial continuations retain private frozen inputs after export, import, display edits, and pool replacement.
Solver lifetime tests verify cancellation, blocked input and output, process cleanup, and compiled-handle invalidation.

Rust formatting, Clippy, all workspace targets, and all 19 Rust tests pass under the native profile.
The native crate rejects panic-abort compilation.
Vendor integrity, dependency policy, Rust advisories, and license generation pass.
The third-party license output remains unchanged.
Go vet, Go advisories, arithmetic proofs, and the exact repository-wide `gofmt` check pass.

Go race and cgo checks do not prove Rust memory safety.
Accepted native stack and fatal faults run in disposable child processes.
Caught Rust panics invalidate state; allocation aborts and fatal faults can terminate the process.
Deadlines reject canceled results after native execution returns and cannot forcibly stop native CPU work.

## Production measurements

The [performance report](../performance.md) contains five samples for each of seven workloads on both backends.
It records complete Go encoding and decoding, native computation, concurrency, ordering, source hashes, and actual resource counts.
Serial authorization measured 139.602 microseconds natively and 928.937 microseconds with Wasm on the recorded machine.
The ratio is 6.65 for this workload.
Compiled analysis measured a smaller difference because real solver interaction remains in the timed path.

Resource checks cover 400 create, call, release, and close cycles.
Every recorded solver start has a matching close.
Later RSS checkpoints remain near 24 MB.
These runs support stable later checkpoints and do not prove that no allocation can leak.
Go heap counters exclude Rust allocation and solver subprocess memory.

## Artifact and publication gates

Verified native builds require committed source and reject untracked source files.
They compile an archive snapshot of the recorded commit.
Independent builds use separate Cargo output directories and compare their exact artifact files.
Artifact checks bind source, target, header, ABI, build pins, object architecture, linker requirements, and checksums.
Generated Go linker source includes the library checksum to invalidate cached builds when the archive changes.
Go does not detect changes to external C libraries in its [build cache](https://pkg.go.dev/cmd/go#hdr-Build_and_test_caching).
A disposable consumer test replaces an archive at the same path and verifies the second executable uses the replacement.
Consumer extraction rejects path escapes, duplicate entries, symbolic links, corrupted records, and mixed target objects.

Each supported target must pass native reproduction and an independent consumer in CI.
Consumers use isolated caches, enable cgo, and block Rust commands.
They run concrete authorization and real SAT and UNSAT solver outcomes.
The [CI workflow](../../.github/workflows/ci.yml) records target-specific compiler and system library evidence.
Local Linux amd64 checks cannot establish Linux arm64 or macOS runtime compatibility.

The release gate requires successful CI for the exact main commit and every expected job.
Release packaging downloads those exact artifacts, checks consumers again, and adds checksum files and provenance attestations.
A failed, skipped, missing, wrong-source, or incomplete check blocks release.
See the [maintenance lessons](../maintenance.md) for the complete publication procedure.
