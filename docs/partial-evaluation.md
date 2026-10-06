# Partial evaluation (experimental)

`partial.Client.PartialAuthorize` exposes Cedar 4.13.0's type-aware partial
evaluation (TPE). Cedar labels this API experimental and recommends `tpe`
instead of the older `partial-eval` feature. This package uses `tpe` only;
it does not implement legacy unknown-expression substitution. The Go API,
residual representation, and upstream behavior may change with Cedar upgrades.

Sources: [Cedar feature status](https://docs.rs/cedar-policy/4.13.0/cedar_policy/),
[`PartialRequest`](https://docs.rs/cedar-policy/4.13.0/cedar_policy/struct.PartialRequest.html),
[`PartialEntities`](https://docs.rs/cedar-policy/4.13.0/cedar_policy/struct.PartialEntities.html),
and [`TpeResponse`](https://docs.rs/cedar-policy/4.13.0/cedar_policy/struct.TpeResponse.html).

## Inputs and decisions

Import `cedar/authorization/partial/input` for partial request, identity, and entity records.
Use `a.Partial()` for continuations. Use `a.Queries()` for permission queries from `partial/query`.

Create an ordinary `Authorizer` with `Config.Schema`. Rust TPE requires that
schema and strictly validates the policies before evaluating them.

| Input | Supported unknown data |
| --- | --- |
| Principal and resource | `PartialEntityUID.ID == nil`; the entity type must be known |
| Action | None: its type and ID must both be known |
| Context | A nil `*Context` means wholly unknown; `&Context{}` means known empty |
| Entity attributes | A nil `*Record` means the entire attribute record is unknown |
| Entity parents | A nil slice means unknown; a non-nil empty slice means known empty |
| Entity tags | A nil `*Record` means the entire tag record is unknown |

Use `KnownEntityUID(uid)` and `UnknownEntityUID(typeName)` to construct the
principal and resource. A pointer to an empty ID is a known empty ID.
TPE does not accept unknowns embedded in a known context or attribute/tag
record. Missing entities have unknown data. An entity's known parents must
have known ancestry; Rust computes transitive closure and rejects inconsistent
hierarchies. Action entities come from the schema and cannot appear in a
`PartialEntitiesFromJSON` input.

`PartialRequest.Entities` augments the authorizer's loaded concrete entities.
Duplicate UIDs are errors, including overlaps with loaded entities. Known
empty tags in loaded concrete entities stay known empty. `PartialEntity`
and `NewPartialEntities` provide typed construction; `PartialEntitiesFromJSON`
accepts the upstream TPE entity array, where omitted/null `attrs`, `parents`,
and `tags` mean unknown. These semantics differ from ordinary entity JSON's
optional empty tags.

The result uses a separate `PartialDecision`: `Undecided`, `PartialDeny`, or
`PartialAllow`. Its zero value is `Undecided`. Only `PartialAllow` grants
permission, and callers must check the returned error first. An unknown
forbid can prevent an Allow even if a permit is already true. TPE can also
produce a concrete Deny while other policies remain residual.

## Inspecting and resuming residuals

`PartialResponse.Residuals` contains every residual in policy-ID order,
including constant true, constant false, and error residuals. Each entry
retains its policy ID and effect, has a `ResidualState`, and includes Cedar's
display text. `Reasons` contains the known determining policy IDs in sorted
order; it is empty for an undecided response. Evaluation errors are represented
by `ResidualError` entries; Cedar skips those policies. Parsing, validation,
and consistency errors are returned as Go errors. Residual IDs, reasons, and
evaluation-error IDs preserve the original policy IDs exactly, including
control characters; rendered Cedar and diagnostic text may escape them.

Use `PartialResponse.Reauthorize(ctx, concreteRequest)` to supply the remaining
data. Rust checks the concrete request and entities against the schema and
against **all** previously known input. Previously supplied entities must
still be present, and known IDs, context, attributes, parents, and tags must
remain consistent. `Request.Entities` augments the original authorizer's loaded
entities, so supply complete replacements for per-call partial entities there.

The response privately retains its original input snapshot and authorizer.
Reauthorization recomputes TPE in a pooled instance and then invokes native
`TpeResponse::reauthorize` on those residuals. This avoids retained native library handles
and works after an instance is recycled. It repeats the TPE cost on each call.
The authorizer and runtime must remain open. Reauthorization is safe to call
concurrently; callers must not concurrently mutate input records or slices.

`PartialResponse.Projection()` returns a copy of the native residual structure.
The projection contains a representation version, the Cedar version, and policies keyed by original ID.
Each policy uses the JSON EST mapping of its native PST.
The special expression `{"error":[]}` represents a residual error at any nesting depth.
An unresolved condition can contain this node without always producing an error.
Short-circuit evaluation can skip it.

`PartialResponse.Export()` serializes the frozen partial input and projection.
`partial.Client.ImportPartialResponse()` recomputes partial evaluation and requires the complete versioned projection to match.
It then reconstructs the matching native PST through `PolicySet::from_pst`.
Ordinary Cedar JSON parsing cannot accept internal residual error expressions.
Unknown representation versions, different Cedar versions, and changed residual policies return `KindInput`.
Import can use another authorizer with matching schema, policies, and loaded entities.
Changes to the public decision, residual text, or projection copy do not change the export.

Reauthorization checks the original known data through native `TpeResponse::reauthorize`.
It then evaluates the imported native policy set.
Its diagnostics match native residual reauthorization.
Direct authorization has the same decisions, reasons, and error policy IDs.
Its error messages can differ because residual errors discard the original error details.
The original authorizer must stay open for its continuation.
An imported continuation uses the authorizer that accepted the import.
Request, response, and cancellation limits also apply to import and replay.

Residual display text does not serialize the full residual state.
Cedar can emit internal residual-error expressions that ordinary source parsing
does not accept. Editing the response's public fields does not change the
private continuation. In particular, evaluating only the nontrivial residuals
would lose constant permit/forbid/error information. Use `Reauthorize` to retain
that information and receive ordinary `Response.Errors` diagnostics.

Run the complete example with:

```bash
go test ./cedar/authorization/partial -run '^ExamplePartialResponse_Reauthorize$' -v
```

It leaves the principal, resource IDs, and MFA context unknown, inspects an
undecided residual, then resolves the same response to Allow with MFA and Deny
without it. Source: [executable example](../cedar/authorization/partial/partial_example_test.go).

## Bounds and verification

Both operations share the existing authorizer pool, per-call
timeout, caller cancellation, response-byte limit, and fault recycling.
`MaxRequestBytes` bounds the full JSON envelope. For reauthorization that
includes the original partial input **and** the concrete completion; reserve
space for both when configuring this limit. Each response retains at most one
bounded partial-input snapshot and residual projection on the Go heap, with no native library handle cache.
As with ordinary authorization, callers control how many responses they retain.
Errors from partial evaluation return `Undecided`; reauthorization errors return
`Deny`. No error or undecided result becomes Allow implicitly.

`testdata/parity/partial` compares the public Go/native API with a separate native
program calling the pinned Cedar APIs directly. Successful native completions
are also checked against ordinary native authorization. Fixtures cover concrete
and unknown requests/entity data, forbid precedence, integer overflow, invalid
inputs, and inconsistent completions. Regenerate or verify them with:

```bash
python3 scripts/parity/run.py partial --update
python3 scripts/parity/run.py partial --check
go test ./cedar/authorization/partial -run 'TestPartial|ExamplePartial|FuzzPartial' -count=1
```

CI regenerates and compares the fixtures and fuzzes the partial-entity input
boundary. Tests also exercise cancellation during execution and pool waits,
recovered panics, malformed output, response limits, corrupted native state,
and recovery. These are differential and boundary tests, not a proof of Cedar
semantics. Native arithmetic proofs cover checked lengths and handle identity.
They do not prove partial-evaluation semantics or pointer ownership.
