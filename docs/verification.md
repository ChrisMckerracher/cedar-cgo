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

## Fuzzing

[`cedar/fuzz_test.go`](../cedar/fuzz_test.go) contains three Go fuzz targets:

| Target | Exercises |
|---|---|
| `FuzzAuthorize` | UIDs, contexts, per-request entities, and response handling |
| `FuzzPolicies` | Policy parsing, strict validation, loading, and authorization |
| `FuzzEntities` | Entity parsing and authorization, with and without a schema |

Each target rejects unexpected module faults and checks that authorization
errors return `Deny`. Fuzz inputs deeper than 200 nested brackets are
skipped to focus on logic failures; stack exhaustion has a separate fault
test. When a corpus directory is supplied, up to 200 corpus policies seed
`FuzzPolicies`.

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
