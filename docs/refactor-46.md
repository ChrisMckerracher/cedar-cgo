# Post-cgo cleanup report for maintainers

Issue [#46](https://github.com/ChrisMckerracher/cedar-go-wasm/issues/46) uses released main `1b635277b1bb5183083279622059aa414c74487e` as its baseline.
The cleanup targets the breaking pre-v1 v0.3.0 interface. It does not tag a release.
The module path, supported platforms, Cedar 4.13.0, and SymCC 0.7.0 remain unchanged.
Go 1.27.1 is the sole supported Go release.
No dependencies or maintainer tools were added.

## Library decisions

Strict `encoding/json/v2` replaces selected legacy encoding and token-based variant decoding.
Nested custom encoders use the same strict implementation. Malformed UTF-8 and duplicate names cannot change identities silently.
Explicit nil options preserve unknown inputs and known empty records, collections, and identifiers.
Operation envelopes retain HTML and JavaScript escaping for existing encoded-byte limits.
Raw-source checks remain where error classification or check order requires them.

Raw strings retain existing escape sequences. This removes repeated unquoting and preserves encoded-byte limits.

Cedar JSON replaces the parallel typed policy syntax interface.
Native Cedar owns parsing, construction, scope normalization, and expression semantics.
Individual bodies retain exact integers. Complete sets retain IDs, templates, links, and slot bindings.
This is not direct serialization of the upstream Programmatic Syntax Tree.
The [consumer lessons](migration/consumer.md) list removed exports and replacement examples.

SymCC uses its exact unmodified registry release and lockfile checksum.
The obsolete Wasm patch, path override, and vendor maintenance script are removed.
Pinned upstream context serialization replaces custom counterexample conversion.
The native dispatcher removes the operation prefix once.

Puddle retains native pool ownership. Rapid retains generators, shrinking, and state-machine tests.
The solver adapter retains injected transport, cancellation, output bounds, and process cleanup.
No reviewed upstream replacement supplied these complete contracts.

## Deleted, shared, and moved implementation

Deleted behavior includes the Go formatter lexer duplicate, typed policy translation, unused load record, and test-only analysis context key.
The token decoder retains required fields, UTF-8, ordered spans, bounds, and exact source text.
Fabricated native streams no longer receive a second semantic lexer pass.
Independent native token fixtures retain lexical and comment regression coverage.

Rust shares concrete decision projection, matching request parsing, and entity merging.
Go shares stateless input encoding, native calls, error envelopes, cancellation, and result clearing.
Domain packages retain result variants and required fields.
Loaded authorization, partial continuations, compiled analysis, and formatter limits retain their different ownership or error contracts.

The arithmetic source guard was reviewed after changing loader serialization. Its size, subtraction, and positive-length premises remain unchanged.
Raw-string preservation retains the final-length checks and the same arithmetic premises. The SMT model and assertions remain unchanged.

Python build and consumer tools invoke the existing Go artifact policy through a trusted, cgo-free command.
They never execute verifier source from an unvalidated bundle.
Strict manifests retain duplicate-name, unknown-field, trailing-data, target, header, ABI, object-header, and checksum checks.
The extraction adapter retains exact-file, path, duplicate-entry, mode, and symbolic-link checks.

One read-only parity runner replaces 18 shell wrappers. Its case catalog retains every independent oracle.
Only `--update` writes expectations. Invalid arguments fail before an oracle runs.
Template and batched cases retain their additional Go comparisons.
The fuzz catalog requires every existing target and its current package. Durations below 60 seconds fail.

The [contributor package tree](../CONTRIBUTING.md#package-responsibilities) records implementation and test ownership.
Entity stores, entity literals, partial input, permission queries, compiled sessions, options, and reports now have distinct packages.
Feature packages do not import runtime composition. Partial clients retain one shared loaded session.
Parent analysis shutdown registers children and pending constructors in one implementation.
Compiled sessions retain exclusive native handles and solver ownership without a shutdown goroutine for each child.

## Source inventory

Counts use physical lines, including comments and blank lines.
Go production excludes tests, shared verification support, verification programs, and consumer smoke code.
Rust production excludes separate test modules, independent programs, and inline test modules.
Script tests, case data, and removed vendor files are separate.
Moved local test helpers count with their destination test files, not production savings.

| Category | Baseline files / lines | Cleanup files / lines |
|---|---:|---:|
| Go production | 115 / 6,871 | 118 / 6,480 |
| Rust production | 54 / 4,088 | 53 / 3,871 |
| C interface contract | 1 / 30 | 1 / 30 |
| Supporting scripts | 43 / 1,161 | 25 / 967 |
| New explicit case data | 0 / 0 | 2 / 47 |
| Go test files, including local helpers | 185 / 15,065 | 206 / 16,222 |
| Shared Go support and consumer programs | 38 / 2,119 | 25 / 1,407 |
| Rust separate tests and independent programs | 36 / 3,027 | 36 / 3,027 |
| Rust inline test modules | 6 / 106 | 7 / 152 |
| Python script tests | 7 / 425 | 9 / 667 |

Combined Go and Rust production decreases by 608 lines. Supporting scripts and explicit catalogs decrease by 147 lines.
Removed vendor footprint is 76 files and 1,022,445 bytes. It is not custom-code savings.
Shared support moves into focused packages or local test files. Rapid's ten generator files remain unchanged.
Analysis adds 159 production lines for explicit configuration, decoding, callback, and shutdown boundaries.
This cost is included in the combined reduction.

## Crowded directory review

Counts include implementation and tests. They are review triggers, not fixed limits.

| Directory | Go files | Responsibility and decision |
|---|---:|---|
| `analysis` | 17 | Stateless queries and parent shutdown. Compiled execution, reports, configuration, transport, and decoding are extracted. |
| `analysis/compiled` | 21 | One atomic session, handle, solver, cancellation, and close lifetime. Further splits expose mutable ownership or add forwarding. |
| `cedar/policy` | 25 | Immutable policy and set workflow after deleting typed syntax and extracting literals. Further snapshot splits create inverse source dependencies. |
| `cedar/authorization/partial` | 18 | Frozen continuations, projection persistence, and reauthorization. Input records and permission queries are extracted. |
| `cedar/authorization/batched` | 14 | One call-local loader protocol, with its fault, budget, schema, and property checks. |
| `cedar/policy/template` | 14 | Template inspection and immutable set edits, including slot and link checks. |
| `cedar/schema` | 12 | Source, fragment composition, and native inspection share schema ownership. Separate contracts remain explicit. |
| `cedar/utility` | 15 | Small native language and value utilities. Tests cover different upstream contracts; no mutable ownership is shared. |
| `internal/artifact` | 14 | One strict artifact identity policy and target/object-header tests. |
| `internal/execution` | 13 | Runtime admission, loaded-session lifetime, encoding, and cancellation. New tests verify raw-string compatibility. |
| `internal/testsupport/generator` | 10 | Coherent Rapid generators and state-machine data. No implementation or assertions are removed. |
| `cedar/integration` | 17 | Corpus and cross-feature checks, examples, failure modes, and performance. Domain-only helpers moved beside feature tests. |

No maintained Go, Rust, C, or script production file exceeds 150 lines.
Rust inline tests remain beside their implementation. Larger test files verify one named domain or ownership contract.
Public factories retain existing internal composition seams where hiding their names would add replacement interfaces without removing behavior.
Application code uses runtime factories and domain records instead of those seams.

## Verification inventory

All 25 fuzz targets remain in [the explicit catalog](../scripts/fuzz/targets.json).
Saved fuzz and Rapid regressions retain their exact bytes.
The two saved fuzz SHA-256 values still match the migration inventory.
Independent oracle source, expected fixtures, and SMT arithmetic models remain unchanged.
JSON policy fuzzing retains independent ID mutation, exact integers, immutable copies, native reparse, and authorization comparisons.
Six former typed-syntax rejection cases now verify upstream acceptance and canonical removal of inapplicable scope fields.
Ordered JSON clauses remain intact. Cedar rendering can normalize their spelling.

The corpus check now requires exactly 7,523 files, 7,523 completed tests, and 60,184 requests.
Every decision, reason, error, validation, setup, and request mismatch must remain zero.
New checks cover strict nested values, duplicate names, unpaired surrogates, exact integers, and unknown-versus-empty inputs.
Shared exchange checks reject native errors, malformed output, canceled results, and invalid inputs without delivering partial results.
Analysis retains real-solver replay, callback failures, pending construction, close ordering, stale handles, and solver cleanup.
Direct lifetime checks reject results even before the asynchronous cancellation callback runs.

Publication requires every applicable local CI check against the final candidate.
This includes reproducibility, trusted consumer extraction, coverage, real solver proofs, race checks, cgo checks, and every fuzz target.
Grouped coverage includes all moved packages. Native adapter coverage must be reported separately because the existing gate excludes it.
Performance comparisons require the same host, compiler, solver, concurrency, fixtures, and workload.
Historical performance records and migration evidence remain historical. They are not relabeled as cleanup measurements.
Issue comments and the pull request record final execution evidence and measured performance.
