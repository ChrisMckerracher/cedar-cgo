# Partial evaluation (experimental)

`Authorizer.PartialAuthorize` exposes Cedar 4.13.0's type-aware partial
evaluation (TPE). Cedar labels this API experimental and recommends `tpe`
instead of the older `partial-eval` feature. This package uses `tpe` only;
it does not implement legacy unknown-expression substitution. The Go API,
residual representation, and upstream behavior may change with Cedar upgrades.

Sources: [Cedar feature status](https://docs.rs/cedar-policy/4.13.0/cedar_policy/),
[`PartialRequest`](https://docs.rs/cedar-policy/4.13.0/cedar_policy/struct.PartialRequest.html),
[`PartialEntities`](https://docs.rs/cedar-policy/4.13.0/cedar_policy/struct.PartialEntities.html),
and [`TpeResponse`](https://docs.rs/cedar-policy/4.13.0/cedar_policy/struct.TpeResponse.html).

## Inputs and decisions

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
and consistency errors are returned as Go errors.

Use `PartialResponse.Reauthorize(ctx, concreteRequest)` to supply the remaining
data. Rust checks the concrete request and entities against the schema and
against **all** previously known input. Previously supplied entities must
still be present, and known IDs, context, attributes, parents, and tags must
remain consistent. `Request.Entities` augments the original authorizer's loaded
entities, so supply complete replacements for per-call partial entities there.

The response privately retains its original input snapshot and authorizer.
Reauthorization recomputes TPE in a pooled instance and then invokes native
`TpeResponse::reauthorize` on those residuals. This avoids retained guest handles
and works after an instance is recycled. It repeats the TPE cost on each call.
The authorizer and runtime must remain open. Reauthorization is safe to call
concurrently; callers must not concurrently mutate input records or slices.

Residual display text is for inspection, not a portable serialized continuation:
Cedar can emit internal residual-error expressions that ordinary source parsing
does not accept. Editing the response's public fields does not change the
private continuation. In particular, evaluating only the nontrivial residuals
would lose constant permit/forbid/error information. Use `Reauthorize` to retain
that information and receive ordinary `Response.Errors` diagnostics.

Run the complete example with:

```bash
go test ./cedar -run '^ExamplePartialResponse_Reauthorize$' -v
```

It leaves the principal, resource IDs, and MFA context unknown, inspects an
undecided residual, then resolves the same response to Allow with MFA and Deny
without it. Source: [executable example](../cedar/partial_example_test.go).

## Bounds and verification

Both operations share the existing authorizer pool, memory limit, per-call
timeout, caller cancellation, response-byte limit, and fault recycling.
`MaxRequestBytes` bounds the full JSON envelope. For reauthorization that
includes the original partial input **and** the concrete completion; reserve
space for both when configuring this limit. Each response retains at most one
bounded partial-input snapshot on the Go heap, with no guest handle cache.
As with ordinary authorization, callers control how many responses they retain.
Errors from partial evaluation return `Undecided`; reauthorization errors return
`Deny`. No error or undecided result becomes Allow implicitly.

`testdata/parity/partial` compares the public Go/Wasm API with a separate native
program calling the pinned Cedar APIs directly. Successful native completions
are also checked against ordinary native authorization. Fixtures cover concrete
and unknown requests/entity data, forbid precedence, integer overflow, invalid
inputs, and inconsistent completions. Regenerate or verify them with:

```bash
scripts/partial-fixtures.sh
scripts/partial-fixtures.sh --check
go test ./cedar -run 'TestPartial|ExamplePartial|FuzzPartial' -count=1
```

CI regenerates and compares the fixtures and fuzzes the partial-entity input
boundary. Tests also exercise cancellation during execution and pool waits,
memory exhaustion, malformed output, response limits, corrupted guest state,
and recovery. These are differential and boundary tests, not a proof of Cedar
semantics. The existing ABI arithmetic proof remains applicable; this feature
adds no pointer arithmetic or guest handle protocol.
