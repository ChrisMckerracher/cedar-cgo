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
| Entity store mutations | `scripts/entity-store-parity.sh --check` | `TestEntityStoreNativeParity` |
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
| `FuzzEntityStoreUnrelatedDecisions` | Native mutation sequences preserve decisions for unrelated entities |
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
| `FuzzEntityLiteralSubstitution` | Native simultaneous substitutions, successful reparse and inspection, malformed source and targets |
| `FuzzEvalResult` | Decode typed expression results; reject malformed variants and preserve integer precision |
| `FuzzNativeUIDRoundTrip` | Native UID render/parse equality for arbitrary valid UTF-8 identifiers; reject malformed UTF-8 |
| `FuzzSourceTokenSpans` | Native lexer results, valid byte spans, exact source reconstruction, and malformed UTF-8 rejection |
| `FuzzUTF8Values` | Reject malformed UTF-8; preserve valid identity bytes, values, and record keys during JSON encoding |

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

`TestApplicabilityNativeFixtures` compares policy and template metadata with native Cedar enumeration.
Fixtures cover unconstrained policies, action groups, type constraints, template slots, linked templates, multiple namespaces, and invalid conditions.
JSON fixtures cover empty IDs, quotes, newlines, backslashes, NUL characters, and Unicode for static, template, and linked policies.
The tests compare result keys with source IDs independently of the native oracle.
`TestRequestEnvironmentJSONRoundTrip` checks action identity and slot metadata after JSON serialization.
`TestApplicabilityBoundaries` checks empty schemas and malformed inputs.
`TestApplicabilityDoesNotAuthorize` checks that applicability metadata can coexist with a denied request.
Regenerate these fixtures with `scripts/applicability-parity.sh --write`.

`TestStructuredDiagnosticsNativeFixtures` compares diagnostic categories, severity, and byte spans with native Cedar.
It checks schema shadowing warnings, Unicode source locations, policy type errors, and invalid action applicability.
JSON policy fixtures check that temporary parser offsets do not become source spans.
`TestDiagnosticJSONPolicySpans` checks the same contract after a policy set converts to JSON.
`TestDiagnosticMetadataIgnoresSpellingHints` repeats validation with ambiguous spelling suggestions.
It compares metadata after removing variable suggestion text.
`TestDiagnosticMetadataIgnoresNativeOrder` compares errors with equal text and different source spans.
`TestDiagnosticRawPolicyIDs` checks empty policy IDs and policy IDs with control characters.
`FuzzDiagnostics` checks validation and schema-warning response decoders without guest execution.
Malformed spans, missing fields, contradictory status, and invalid severity fail decoding.
Regenerate native fixtures with `scripts/diagnostics-parity.sh --write`.

`TestSchemaNativeFixtures` compares conversion, inspection, action entities, and validation with pinned native Cedar.
Fixtures include cross-fragment references, qualified namespaces, common types, optional attributes, extensions, and enumerated entity types.
They also check empty schemas and invalid policy validation.
`TestSchemaCompositionResolvesAfterCombining` checks a fragment that fails alone and succeeds after composition.
It also checks authorization with the composed schema.
Boundary tests cover duplicate declarations, cycles, annotations, UTF-8, and input limits.
`FuzzSchemaFragments` checks that successful composition supports inspection and action extraction.
Regenerate the native fixtures with `scripts/schema-parity.sh --write`.

### Entity store mutation checks

The entity-store oracle invokes native Cedar APIs directly.
Its ten fixtures retain one native store across mutation sequences.
The Go API compares normalized exports, direct parents, ancestry, membership, and deep equality at each step.
Fixtures cover replacement, deletion, redundant direct edges, missing parents, duplicate upserts, cycles, and schema validation.
They also check schema action deletion and exact integer, extension, Unicode, and tag values.

The opaque snapshot records direct parents from the native AST.
A chain deletion fixture detects accidental reconstruction from transitive normalized JSON.
The mutation fuzz target changes an isolated graph component.
It then checks that an unrelated authorization decision stays unchanged.

### Context, request, and name utilities

`testdata/parity/utilities` records results from direct native Cedar operations.
The fixtures cover UID parsing, native escapes, typed context readback, merge errors, context validation, scope validation, confusable warnings, and language metadata.
Confusable tests check structured warnings, raw policy IDs, and omitted spans for JSON policy inputs.
Malformed warning categories, severity, and source spans fail response decoding.
Regenerate these fixtures with `scripts/utility-parity.sh --write`.
`TestUtilityNativeFixtures` compares the Wasm results against every native result.
The comparison preserves JSON integer text instead of converting integers to floating-point values.

`TestNativeUIDRoundTripProperty` checks native render/parse equality and stable normalized text.
`TestContextMergeContract` checks duplicate rejection, nested-value preservation, unchanged inputs, extensions, and the empty-context identity.
`TestContextMergeDisjointProperty` checks arbitrary integer and string values after a disjoint merge.
`TestUtilityReadbackExactIntegers` checks readback and merge with integers beyond floating-point precision and both signed 64-bit bounds.
`TestUtilityContextInputProtocol` checks missing fields, unexpected fields, and explicit null context values.
`TestUtilityPreflight` checks UTF-8 rejection and source limits before guest execution.

`TestPermissionQueryNativeFixtures` compares all three query operations with direct native TPE calls.
Twenty cases cover schema-driven action enumeration, known and unknown context, unknown IDs, empty results, and unsatisfiable residual conditions.
The additional cases distinguish loaded entities from per-query concrete or partial additions.
The oracle converts loaded entities with native `PartialEntities::from_concrete` before it adds partial query entities.
They check UID conflicts, unknown attributes, and unchanged loaded entities after successful or failed queries.
Concrete resource, principal, and action query results are replayed through ordinary authorization.
`TestActionQueryResultJSONRoundTrip` checks flat UID fields, exact Unicode values, empty lists, and invalid UTF-8.
Native ABI decoding tests check all query operations before direct native execution.
They preserve raw context and entity JSON, including exact signed 64-bit integers and escaped Unicode.
They reject missing fields, duplicate operations, and fields from other query operations.
`TestPermissionQueryBoundaries` covers unknown types, missing schemas, and cancellation.
`TestPermissionQueryLimitsBeforeGuest` checks input limits and invalid UTF-8 before guest execution.
Regenerate native fixtures with `scripts/queries-parity.sh --write`.
`TestSchemaNativeFixtures` compares conversion, inspection, action entities, and validation with pinned native Cedar.
Fixtures include cross-fragment references, qualified namespaces, common types, optional attributes, extensions, and enumerated entity types.
They also check empty schemas and invalid policy validation.
`TestSchemaCompositionResolvesAfterCombining` checks a fragment that fails alone and succeeds after composition.
It also checks authorization with the composed schema.
Boundary tests cover duplicate declarations, cycles, annotations, UTF-8, and input limits.
`FuzzSchemaFragments` checks that successful composition supports inspection and action extraction.
Regenerate the native fixtures with `scripts/schema-parity.sh --write`.

The partial evaluation oracle exports native PST through its JSON EST mapping.
It compares each entry with `policy_set().policy(id)` and checks `residual_policies()` membership.
It records nested residual errors through native `Expr::has_error`.
Native PST replay must match native reauthorization and direct authorization.
`partial::tests` runs the actual structured import helper with nested errors and empty or escaped IDs.
The native tests reject changed versions, Cedar versions, effects, conditions, and missing policies.
They compare exact diagnostics with native residual reauthorization.
Direct authorization comparisons retain decisions, reasons, and error policy IDs because residual errors discard original error details.
Go fixture tests also export, import, and replay every successful partial response.
The partial authorization property checks randomized export and import before replay.
Separate tests reject changed versions, policies, and effects.
They also check copied projections and frozen exports.
`TestResidualPolicyIDPresence` rejects missing or null policy IDs while preserving explicit empty IDs.
`TestResidualRawPolicyIDs` checks export, import, and native replay with empty IDs and control characters.

`pst_fixtures` compares policy and template EST with native PST bodies.
It checks template links through native `PolicySet::to_pst`.
Native authorization must remain equal after `PolicySet::from_pst` reconstruction.
Go tests compare the mapped JSON and verify authorization after full-set JSON reconstruction.
The randomized set property checks the same authorization result across both source forms.
Special expression fixtures verify the residual error, unknown, and slot mappings.
Regenerate them with `scripts/pst-parity.sh --write`.

### Source tokens and comment preservation

`testdata/parity/source-tokens` records native formatter lexer results.
The fixtures cover comments, annotations, Unicode, CRLF, slots, operators, incomplete grammar, and lexical errors.
Regenerate these fixtures with `scripts/source-token-parity.sh --write`.
`TestSourceTokenNativeFixtures` compares every token, byte span, and comment summary against the native result.

`TestSourceTokensPreserveCommentsAndSpacing` reconstructs the original source, then replaces one entity ID token.
The edit preserves every other source byte, including comments and spacing.
The test reparses the result and compares authorization through the edited source and its semantic JSON representation.
`TestSourceTokensSeparateLexingFromValidation` checks incomplete grammar and malformed lexical input.
`TestMalformedSourceTokenResponses` rejects invalid spans, overlapping tokens, source mismatches, and spans that split UTF-8.
Comment-field tests reject missing or null strings and null array entries.
Lexical response tests reject omitted tokens, incorrect token kinds, and truncated native tokens.
Native spelling tests preserve Unicode whitespace, lone-CR comments, raw string line breaks, and unsupported semantic escapes.
`TestSourceTokenPreflight` checks input encoding and source limits before guest execution.

### Entity store mutation checks

The entity-store oracle invokes native Cedar APIs directly.
Its ten fixtures retain one native store across mutation sequences.
The Go API compares normalized exports, direct parents, ancestry, membership, and deep equality at each step.
Fixtures cover replacement, deletion, redundant direct edges, missing parents, duplicate upserts, cycles, and schema validation.
They also check schema action deletion and exact integer, extension, Unicode, and tag values.

The opaque snapshot records direct parents from the native AST.
A chain deletion fixture detects accidental reconstruction from transitive normalized JSON.
The mutation fuzz target changes an isolated graph component.
It then checks that an unrelated authorization decision stays unchanged.

### Symbolic error and matching checks

`scripts/analysis-queries-parity.sh --check` requires the pinned cvc5 executable.
Its native oracle runs optimized boolean queries and their counterexample variants.
The oracle confirms each failed property with the concrete authorizer.
`TestAnalysisQueriesNativeParity` compares the Wasm results with these native fixtures.

The cvc5-gated tests cover safe policies, integer overflow, unconditional matches, and nonmatches.
They also cover pairwise matching and policy-set disjointness.
Empty-schema cases reject templates in either set and retain vacuous results for valid static sets.
Response decoding requires property flags and action ID fields.
Explicit false flags and empty action IDs remain valid.
Counterexample requests require complete UIDs that match their reported request environment.
Context objects and entity arrays retain their original JSON bytes and exact integer values.
Entity records require complete flat UIDs, attribute objects, parent UID arrays, and optional tag objects.
The decoder checks these containers without interpreting Cedar values or graph semantics.
Forbid fixtures preserve distinct matching conditions while both final decisions deny.
Generated tests compare matching thresholds and replay each returned counterexample.
The response decoder rejects missing evaluations and evidence that does not violate the queried property.
It requires Deny for singleton nonmatches and errors, and permits at most one error per singleton policy.
Unary queries require Deny and no evaluation for the unused second policy set.
It also rejects missing results, incomplete environment types, and incomplete error messages.
An explicit empty result list remains valid for a schema with no request environments.
Native fixtures check real error evidence with empty policy IDs and IDs containing quotes, newlines, backslashes, and NUL.
The Go comparison preserves those raw IDs and compares native error messages.

### Compiled analysis sessions

Native session tests cover environment selection, handle ownership, monotonic IDs, release, and the 128-handle limit.
They also check repeated native queries and solver-fault invalidation.
Go tests check blocked solver reads, active timeouts, queued cancellation, malformed responses, and foreign handles.
Session creation rejects missing or null action ID fields, while preserving explicit empty IDs.
Malformed environment responses close the solver and invalidate the session.
Malformed error records also invalidate the session; complete compilation errors leave it usable.
Mixed success/error envelopes, nested report errors, and invalid UTF-8 replies close both session resources.
Delayed solver startup tests preserve cancellation and late cleanup errors through construction and analyzer closure.
Real CVC5 tests cancel 100 session lifetimes and require successful resource cleanup.
Deterministic process tests cover cancellation, deadlines, wrapped cleanup errors, and repeated waits.
Solver cleanup suppresses a direct cancellation error only when the process exits successfully.
Wrapped cancellation errors and other cleanup errors remain observable.
Run these ownership tests with `go test -race ./analysis -run '^TestCompiled'`.

The cvc5-gated integration tests compare compiled checks with stateless checks.
They replay returned counterexamples through the concrete authorization runtime.
They check one solver start across repeated compiled calls and cleanup after analyzer closure.
The output-limit test verifies whole-session invalidation.

`BenchmarkRepeatedEquivalent` compares repeated equivalence checks through both APIs.
Its policies use `context.n < 0` and `context.n <= -1` under one schema environment.
The compiled benchmark excludes session creation and compilation, and performs one warm-up check.
Run `go test ./analysis -run '^$' -bench '^BenchmarkRepeatedEquivalent$' -benchmem -benchtime=10x` with CVC5 set.
Record timings, allocations, tool versions, and iterations with the final module artifacts.
The final native preflight passed four session tests and all 26 query fixtures.
The normal CVC5 guest suite passed in 108.482 seconds.
The lifetime guest test also passed twice under the race detector in 91.318 seconds.

The final artifact measurement used three samples with ten iterations each on 2026-10-03 at 06:43 UTC.
It used Linux/amd64, an AMD Ryzen 5 5600X, Go 1.27.1, Rust 1.99.0, and cvc5 1.3.1.
The analysis guest SHA-256 was `8a9598239fbc7f23969ac613098e7489ab89ffb86379504cb1136b8f3ea031cd`.
The authorizer guest SHA-256 was `9ef3546a6aff09c3e69ac600f7640e1a6899d23bd0bf97fa5e2e42805e9a511e`.
Analyzer construction was excluded from both paths.
The compiled path also excluded session creation, handle compilation, and one warm-up check.

| Path | Sample | Time per check | Bytes per check | Allocations per check |
| --- | --- | --- | --- | --- |
| Stateless | 1 | 32.11 ms | 20,539,621 | 5,810 |
| Stateless | 2 | 35.34 ms | 20,537,971 | 5,806 |
| Stateless | 3 | 29.89 ms | 20,536,812 | 5,803 |
| Compiled | 1 | 2.41 ms | 13,616 | 69 |
| Compiled | 2 | 2.55 ms | 13,808 | 70 |
| Compiled | 3 | 2.31 ms | 13,617 | 69 |

The stateless median was 32.11 ms; the compiled median was 2.41 ms.
The compiled median was 13.31 times faster for these inputs.
These short samples do not establish performance for other schemas or policies.
