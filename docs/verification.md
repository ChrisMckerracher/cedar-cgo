# Verification

[Documentation](README.md) · [Security model](security.md) · [Contributing](../CONTRIBUTING.md)

## Contents

- [Conformance](#conformance)
- [Fuzzing](#fuzzing)
- [Fault tests](#fault-tests)
- [ABI arithmetic proof](#abi-arithmetic-proof)
- [Upstream assurance](#upstream-assurance)
- [Build checks](#build-checks)

## Conformance

[`cedar/conformance_test.go`](../cedar/conformance_test.go) runs the upstream
[Cedar integration corpus](https://github.com/cedar-policy/cedar-integration-tests/tree/1999ea249229e26cabb398a279fea721854a471d)
through the public Go interface.

| Corpus pin | Tests | Requests | Decision / reason / error-ID / validation mismatches |
|---|---|---|---|
| `1999ea249229e26cabb398a279fea721854a471d` | 7,523 | 60,184 | 0 / 0 / 0 / 0 |

The harness checks authorization decisions, sorted deciding policy IDs,
evaluation error policy IDs, and strict-validation outcomes. Setup and
request failures also fail the run. CI pins both the corpus commit and
archive checksum, and requires zero mismatches.

This is evidence of Rust-compatible semantics for the exposed authorization
and validation operations. It does not establish coverage of every input
or expose every API in the Rust library. See
[supported operations](api.md#supported-operations).

For reproduction, use the corpus setup in [Contributing](../CONTRIBUTING.md#tests).

Experimental slicing has a separate [native differential suite](../testdata/parity/slicing/README.md).
`scripts/slicing-fixtures.sh --check` compares regenerated direct native Cedar
results with committed fixtures. `TestSliceEntitiesNativeParity` checks Wasm
decisions, selected entity data, and load rounds against that oracle, then
compares ordinary authorization using full and reduced stores. This covers the
listed fixtures, not general minimality or equivalence for arbitrary requests.

## Fuzzing

The authorization and slicing packages contain these Go fuzz targets:

| Target | Exercises |
|---|---|
| `FuzzAuthorize` | UIDs, contexts, per-request entities, and response handling |
| `FuzzPolicies` | Policy parsing, strict validation, loading, and authorization |
| `FuzzEntities` | Entity parsing and authorization, with and without a schema |
| `FuzzSliceEntities` | Source entity parsing, fail-closed slicing, and full/reduced authorization agreement |

The three authorization targets reject unexpected module faults and check that authorization
errors return `Deny`. Fuzz inputs deeper than 200 nested brackets are
skipped to focus on logic failures; stack exhaustion has a separate fault
test. When a corpus directory is supplied, up to 200 corpus policies seed
`FuzzPolicies`.

The slicing target bounds its input to 64 KiB and four loading rounds. On a
successful slice it checks full and reduced authorization decisions; on any
error it requires an empty denying result. Explicit slicing resource tests
cover input-size boundaries, response limits, memory faults, iteration
exhaustion, cancellation, and subsequent recovery.

Ordinary `go test` runs the seeds. CI fuzzes each target for 60 seconds.
For a longer local run:

```bash
go test -run '^$' -fuzz '^FuzzAuthorize$' -fuzztime 5m ./cedar
```

These targets exercise the Go/Wasm glue. Cedar's upstream
[differential testing](https://github.com/cedar-policy/cedar-spec/tree/main/cedar-drt)
separately compares its Rust implementation with its formal model.

## Fault tests

The `cedar/failclosed*_test.go` tests cover memory exhaustion, call deadlines,
caller cancellation, stack overflow, corrupted instances, incorrect module
hashes, and forbidden imports. They check
denial and instance disposal where applicable, including recovery with a
fresh instance.

Analysis tests compare the fixture policy sets with cvc5 and inspect
counterexamples. Every returned counterexample also passes a concrete
Cedar authorization check inside the guest.

## ABI arithmetic proof

[`internal/verification/abi.smt2`](../internal/verification/abi.smt2) models
the Rust response-word packing expression and the Go unpacking and
response-header predicates as fixed-width bitvector arithmetic. cvc5 checks
the negation of each property and returns `unsat` for all three:

1. Every 32-bit pointer and length round-trips through the 64-bit response
   word without losing or mixing bits.
2. The packed word is zero exactly when both input fields are zero.
3. The host's header predicates accept exactly nonzero pointers and lengths
   whose unsigned length is at most the response limit.

These checks cover all possible values of the modeled 32-bit fields,
including their maximum values. The accompanying Go test checks that the
specific Rust and Go source expressions still match the model; changes to
those expressions require reviewing and updating the proof.

Run it with the same cvc5 executable used for analysis:

```bash
CVC5=/path/to/cvc5 go test -v ./internal/verification
```

CI runs this check alongside the analysis tests. The proof's scope is the
modeled arithmetic, with the source-to-model correspondence checked for
those expressions. It does not prove allocation validity, memory ownership,
JSON decoding, control flow, concurrency, the compiler, or the full glue.
Fault and conformance tests provide separate evidence about runtime behavior.

## Upstream assurance

Cedar maintains a [Lean specification and proofs](https://github.com/cedar-policy/cedar-spec/tree/main/cedar-lean)
for properties such as forbid-overrides-permit and typechecker soundness.
Its formal development also includes SymCC encoding proofs. Upstream
differential tests connect that model to the Rust implementation used here.

These proofs apply to the formal model and its stated assumptions; this
repository's Go/Rust transport, runtime, and solver are separate parts of
the trusted implementation. Concrete counterexamples are checked with Cedar;
successful universal analysis results depend on the solver's `unsat` answer.

## Build checks

- Runtime startup checks module hashes and import allowlists, and each
  instance checks the ABI version.
- CI rebuilds the embedded modules from pinned source and requires
  byte-identical output.
- Tests compare `CedarVersion` and `SymCCVersion` with `rust/Cargo.lock`.
- CI checks vendored SymCC against its release archive plus the local patch,
  and regenerates third-party license notices from the lockfile.

See [Maintenance](maintenance.md) for the upgrade and release checks.

### Batched loading parity and bounded arithmetic

`scripts/check-batched-parity.sh` regenerates `testdata/parity/batched/expected.json`
with a native program that calls pinned `cedar_policy::PolicySet::is_authorized_batched`
and implements its own `EntityLoader`, independently of the guest bridge. It
compares the regenerated fixture and runs `TestBatchedNativeParity` through the
exported Go API and embedded Wasm, comparing decisions, upstream error text, and
sorted callback UID traces. Fixtures cover incremental loading, nonexistent and
omitted data, extra entities, ancestry, invalid policies, early decisions, and
iteration boundaries. The Rust CI job regenerates and compares the fixture.
`FuzzBatchedEntities` exercises the callback JSON boundary; other batched tests
cover callback failures, ownership, concurrency, cancellation, pool waits, and
resource bounds.

`internal/verification/batched.smt2` models bounded nonnegative byte-budget
subtraction, the guarded uint32 callback-counter increment, and positive int32
result lengths below the 64 MiB cap. Source fingerprints require review when the
modeled Go functions or limits change. These are arithmetic proofs only: they do
not prove JSON parsing, memory ownership, callback termination, Rust evaluation,
Cedar semantics, or batched convergence.

### Policy construction and editing

`TestPoliciesNativeParity` compares the exported Go API and embedded Wasm with
fixtures generated by direct upstream `cedar-policy` 4.13.0 calls in
`rust/crates/authorizer/examples/policies_oracle.rs`. The oracle does not invoke
our guest operations. It covers explicit/empty IDs, parse diagnostics, duplicate
and missing IDs, merge conflicts and renaming, PST construction, linked-set
preservation, strict validation diagnostics and edited-policy authorization.
Regenerate with `scripts/policies-parity.sh --write`; check reproducibility with
`scripts/policies-parity.sh --check`. CI rebuilds and compares the native fixture
and lints the native example. Go tests additionally cover immutable snapshots,
JSON/PST/Cedar round trips, malformed syntax, duplicate JSON map keys, input and
response limits, memory exhaustion, cancellation and runtime recovery.
`FuzzPolicySyntax` exercises the new structured construction boundary.

These are differential and resource tests, not a proof of policy semantics. The
feature introduces no new ABI arithmetic or shared mutable guest state; the
existing ABI proof remains the applicable bitvector evidence. No new solver
claim is made for parsing, PST conversion or authorization.
