# Verification

[Documentation](README.md) · [Security model](security.md) · [Contributing](../CONTRIBUTING.md)

## Contents

- [Conformance](#conformance)
- [Native template parity](#native-template-parity)
- [Formatting parity](#formatting-parity)
- [Fuzzing](#fuzzing)
- [Fault tests](#fault-tests)
- [ABI arithmetic proof](#abi-arithmetic-proof)
- [Upstream assurance](#upstream-assurance)
- [Build checks](#build-checks)
- [Batched loading and arithmetic](#batched-loading-parity-and-bounded-arithmetic)
- [Policy construction and editing](#policy-construction-and-editing)
- [Property-based testing](#property-based-testing)

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

CI regenerates each feature's fixtures through the pinned native Rust APIs.
Ordinary Go tests compare the embedded guest with those fixtures:

| Feature | Native regeneration check | Go/Wasm comparison |
|---|---|---|
| Templates | `scripts/check-template-parity.sh` | `TestTemplateNativeParity` |
| Partial evaluation | `scripts/partial-fixtures.sh --check` | `TestPartialNativeFixtures` |
| Batched loading | `scripts/check-batched-parity.sh` | `TestBatchedNativeParity` |
| Slicing | `scripts/slicing-fixtures.sh --check` | `TestSliceEntitiesNativeParity` |
| Policy construction | `scripts/policies-parity.sh --check` | `TestPoliciesNativeParity` |
| Formatting | `scripts/format-parity.sh --check` | `TestFormatNativeParity` |

Experimental slicing has a separate [native differential suite](../testdata/parity/slicing/README.md).
`scripts/slicing-fixtures.sh --check` compares regenerated direct native Cedar
results with committed fixtures. `TestSliceEntitiesNativeParity` checks Wasm
decisions, selected entity data, and load rounds against that oracle, then
compares ordinary authorization using full and reduced stores. This covers the
listed fixtures, not general minimality or equivalence for arbitrary requests.

[`TestCombinedPolicyEvaluationPaths`](../cedar/combined_parity_test.go) carries one
policy set through formatting, PST construction, static edits, template linking,
JSON snapshots, ordinary authorization, partial evaluation/reauthorization,
batched loading, and slicing. It checks exact raw IDs and explicit allow/deny
outcomes. The loader must supply missing data, and a fresh authorizer evaluates
the reduced store, so earlier request data cannot hide missing slice entities.


## Native template parity

[`template_fixtures.rs`](../rust/crates/authorizer/examples/template_fixtures.rs)
calls pinned native `cedar-policy` 4.13.0 directly, independently of the guest
operation implementation. It emits committed fixtures for valid links,
missing/extra bindings, duplicate IDs, unlinking, and removal. Successful
operations include native authorization decisions/reasons and strict-validation
outcomes, including a link that succeeds but fails schema validation.

`TestTemplateNativeParity` replays these operations through the exported Go
API and compares policy-set JSON, upstream error diagnostics, authorization,
and validation. CI regenerates and compares the native fixtures before running
the Go comparison. Reproduce with existing Rust and Go tools:

```bash
scripts/check-template-parity.sh
```

Template tests also cover JSON inspection/round trips, escaped IDs, concurrent
immutable snapshots, malformed envelopes, exact input bounds, response/memory
limits, cancellation/deadlines, and calls after runtime closure. `FuzzTemplates`
checks parsing, EST round trips, binding discovered slots, link/unlink state
transitions with authorization restoration, and non-UTF-8 rejection. These are
differential and boundary tests, not a formal proof of template semantics.
The operations reuse the existing ABI arithmetic and fresh-instance lifecycle;
no new arithmetic or mutable handle state is introduced.

## Formatting parity

[`testdata/parity/format`](../testdata/parity/format) contains representative
policies, templates, annotations, comments, Unicode, extensions, layout options,
and invalid sources. `scripts/format-parity.sh --check` calls the pinned native
`cedar-policy-formatter` API directly and checks the committed output. CI runs
this regeneration check and lints the native example.

The native oracle checks formatting idempotence, complete Cedar JSON equality
(including templates and annotations), and concrete authorization results both
before and after formatting and template linking. `TestFormatNativeParity`
compares the exported Go API's Wasm output byte-for-byte with that native output,
then checks authorization against the native decisions and reasons. These are
finite differential tests, not a proof of semantic preservation for all inputs.

The formatting boundary tests cover source/output limits including JSON
expansion and exact boundaries, parser diagnostics, invalid UTF-8, malformed
envelopes/responses, cancellation during guest execution, memory and stack
exhaustion, concurrent calls, recovery, and isolation from loaded authorizers.
The existing ABI arithmetic proof applies unchanged; formatting introduces no
new memory-packing or state-transition arithmetic.

## Fuzzing

The `cedar` package contains these Go fuzz targets:

| Target | Exercises |
|---|---|
| `FuzzAuthorize` | UIDs, contexts, per-request entities, and response handling |
| `FuzzPolicies` | Policy parsing, strict validation, loading, and authorization, seeded with corpus-derived literals |
| `FuzzEntities` | Entity parsing and authorization, with and without a schema |
| `FuzzBatchedEntities` | Callback entity JSON, bounded loading, and fail-closed results |
| `FuzzBatchedDifferential` | Batched loading against single-shot authorization with identical data, plus failing/oversized/malformed loaders |
| `FuzzSliceEntities` | Source entity parsing, fail-closed slicing, and full/reduced authorization agreement |
| `FuzzPolicySyntax` | Structured policy construction and malformed syntax envelopes |
| `FuzzPolicyEdits` | Add/remove sequences over parsed sets, membership coherence, and JSON reparse stability |
| `FuzzTemplates` | Template parsing, EST round trips, binding, link/unlink state transitions, and authorization restoration |
| `FuzzPartialEntities` | Unknown entity input and undecided results |
| `FuzzPartialReauthorize` | Residual reauthorization against direct authorization with concrete values |
| `FuzzFormatPolicies` | Policy/template text and layout options, malformed UTF-8, errors, idempotence, and decision preservation |

Each target rejects unexpected module faults; authorization errors must return
`Deny`, partial-evaluation errors return `Undecided`, and formatting errors return
no text. Batched, slicing, partial, and formatting targets skip inputs deeper
than 40 nested brackets; other targets use the 200-bracket bound. Dedicated fault
tests cover stack exhaustion. Formatting also bounds input to 4 KiB and output
to 1 MiB. When a corpus directory is supplied, up to 200 corpus policies seed
`FuzzPolicies`; eight small corpus-derived literals are baked in unconditionally.

Several bodies also check semantic invariants beyond fail-closed behavior:

- `FuzzFormatPolicies` requires successful output to be a formatting fixed
  point and to leave the decision (and error outcome) of a fixed request
  unchanged against the original source.
- `FuzzBatchedDifferential` serves the same closed entity store through the
  callback and an ordinary authorizer and requires equal decisions and error
  outcomes; its adversarial legs inject loader errors, oversized batches, and
  malformed JSON, which must fail closed without faults.
- `FuzzPolicyEdits` requires each add/remove to either succeed with the
  inspected membership updated or fail with the set still reparsing to the
  same JSON and policy list.
- `FuzzTemplates` requires an accepted template to survive its EST round trip,
  links to be listed consistently, unlinking to restore both the pre-link
  policy set and its decision, and non-UTF-8 inputs to be rejected as input
  errors before the guest runs.
- `FuzzPartialReauthorize` requires reauthorizing the residual with concrete
  principal, resource, and context values to match direct authorization with
  those values, including matching error outcomes.

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

## Property-based testing

`cedar/*_property_test.go` and `analysis/analysis_property_test.go` carry
property tests built on [`pgregory.net/rapid`](https://pgregory.net/rapid)
v1.3.0, a test-only Go dependency. Generators in
[`cedar/property_gen_test.go`](../cedar/property_gen_test.go) compose policies
from a small grammar of fixture-proven, strictly valid Joy-schema expressions,
plus contexts, entity stores, requests, values, templates, and malformed JSON.
Each property asserts only contracts documented here or in the package tests:

| Area | Property |
|---|---|
| Formatting | `format` is idempotent, output re-parses, and authorization is unchanged before/after formatting |
| Templates | linking authorizes identically to textual slot substitution; inspection round-trips IDs/slots/annotations/bindings; unlink removes exactly the link |
| Policy editing | add/remove sequences track a Go-side ID model; JSON and EST views round-trip; edits never disturb unrelated policies |
| Partial evaluation | reauthorizing residuals equals direct authorization; fully known inputs decide exactly like full evaluation |
| Slicing | the sliced decision equals full-store and reduced-store authorization |
| Batched loading | loader-served, preloaded, and sequential authorization agree |
| Validation | identical diagnostics across calls; sampled corpus tests that should validate always pass |
| Values/entities | value and entity JSON reach a fixpoint; malformed entity input fails closed |
| Authorizer | decisions are deterministic and stateless across reused calls |
| Analysis | sampled cvc5 counterexamples replay as deny→allow in the concrete authorizer; a set is equivalent to itself |

rapid selects a random seed for each run and prints the seed on failure.
To reproduce a failure, use
`go test ./cedar -run TestPropertyFormatIdempotent -rapid.seed=N`
or `-rapid.failfile`. By default, rapid runs 100 checks per property.
Use `-rapid.checks` or `RAPID_CHECKS` to change this count for the test process.
Use `go test -short` to divide the check count by five.
Each check runs its assertions without a time guard, including during replay
and shrinking. Generator limits control policy size and entity count.

The analysis property checks every counterexample's reported decisions.
It replays up to three counterexamples per report through concrete authorization.
A run with `-rapid.seed=1` checked 100 cases.
It recorded 858 solver-held environments and replayed 88 counterexamples.

The validation determinism property uncovered real upstream nondeterminism:
cedar-policy's validator picks its `did you mean` suggestion by hash iteration,
so identical inputs can render different hint text across calls. The property
normalizes those `(help: did you mean ...)` substrings before comparing
diagnostics; Passed, policy IDs, counts, and all remaining message text stay
exact.
