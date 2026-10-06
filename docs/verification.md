# Native verification for Cedar Go maintainers

Verification covers semantics, transport ownership, cancellation, callbacks, and consumer artifacts.
Read the [migration evidence report](migration/verification.md) for measured results and remaining limits.
The [historical Wasm record](history/wasm-verification.md) preserves earlier measurements and proof scope.

## Conformance

The pinned Cedar corpus contains 7,523 tests and 60,184 requests.
The pin is `1999ea249229e26cabb398a279fea721854a471d`.
Its archive SHA-256 is `65476adf952c0574d6bf9b317d67d30c9ac462eb1dbf5e4c7b2a35856baf5205`.

The harness compares decisions, sorted reason IDs, evaluation error IDs, and strict validation results.
Setup and request errors fail the check.
The harness lives in `cedar/integration`. Feature tests live beside their domain implementations.

## Independent fixtures

The `cgw-verification` crate calls pinned Cedar and SymCC directly.
It retains fixture programs for all migrated feature operations.
It does not use the production C interface to derive expected outputs.

Parity scripts default to checks and leave expected files unchanged.
An explicit update command and review are required to change expected output.
The [operation inventory](migration/operations.md) maps every operation to its domain, task, and evidence.

## Coverage and fuzzing

All 25 existing fuzz targets and saved regression inputs remain available.
The CI fuzz duration remains 60 seconds per target.
Property tests, examples, benchmarks, and concrete counterexample replay remain part of verification.

The pinned pre-migration statement coverage is 90.12% for Cedar and 87.13% for analysis.
Artifact verification had 87.27% coverage.
The coverage check combines domain packages after the split and includes shared execution in Cedar's group.
Use `-coverpkg=./...` so cross-package tests contribute to the result.

## Native ownership and faults

Tests exercise explicit handles, response buffers, callback identities, state release, and concurrent closure.
The [independent ownership review](migration/ownership-review.md) records its findings and limits.
Go race checks detect Go data races. Strict cgo checks verify Go pointer rules.
Neither check proves Rust memory safety. Rust ownership receives separate interface review and native tests.

The final native build profile uses unwinding.
C-interface tests verify caught-panic conversion and state invalidation in that profile.
Disposable child tests exercise accepted fatal faults without terminating the test runner.
Tests reject expired results while retaining live native resources until execution returns.

Entity callback tests cover limits, malformed input, missing entities, panic conversion, isolation, and cancellation.
Solver tests cover SAT, UNSAT, UNKNOWN, EOF, short input and output, malformed replies, output limits, and process cleanup.
Compiled tests cover stale and foreign handles, release, capacity, reuse, invalidation, and close ordering.

## Arithmetic proofs

The obsolete Wasm pointer-packing proof is removed from production verification.
The historical record retains its claim and limitations.

The native proof checks response length conversion and checked monotonic handle increment.
The batched proof retains applicable byte-budget conservation and bounded callback-count arithmetic.
Source guards require review when the implementation changes.
The cleanup changes loader serialization to strict standard-library JSON v2.
The reviewed guard retains raw-size checks, remaining-byte subtraction, encoded-size rejection, and positive result lengths.
Explicit HTML and JavaScript escaping retain encoded byte budgets. JSON serialization remains outside the arithmetic model.

These proofs do not establish pointer validity, allocator ownership, JSON correctness, or Cedar semantics.
They also do not establish process fault containment.

## Artifacts and consumers

Each supported target builds two independent native artifacts and compares their exact files.
The verifier checks source, target, header, ABI, build pins, real object headers, and checksums.
Extraction rejects unsafe paths, duplicate entries, symbolic links, corruption, and altered source or native identity.

Each clean consumer uses isolated caches, enables cgo, and blocks Rust commands.
It runs concrete authorization and real cvc5 analysis, including a concrete counterexample.
Executable inspection records actual system libraries and runtime symbol requirements.

The release gate requires the exact main commit and every expected CI job.
It rejects missing, skipped, failed, incomplete, duplicate, and unexpected jobs.
Release packaging uses the exact native artifacts from that successful CI run.

## Reproduction

Follow the ordered [contributor lessons](../CONTRIBUTING.md).
Use [platform requirements](migration/platforms.md) when interpreting local and remote evidence.
Use the [performance guide](performance.md) for repeated production and resource measurements.
