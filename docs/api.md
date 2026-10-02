# Go API

[Documentation](README.md) · [Change analysis](analysis.md) · [Security model](security.md)

## Contents

- [Packages and imports](#packages-and-imports)
- [Runtime lifecycle](#runtime-lifecycle)
- [Schemas and policies](#schemas-and-policies)
- [Templates (experimental)](#templates-experimental)
- [Entities and values](#entities-and-values)
- [Authorization](#authorization)
- [Entity slicing](#entity-slicing)
- [Strict validation](#strict-validation)
- [Errors](#errors)
- [Configuration reference](#configuration-reference)
- [Supported operations](#supported-operations)

## Packages and imports

```go
import (
	"github.com/ChrisMckerracher/cedar-go-wasm/cedar"
	"github.com/ChrisMckerracher/cedar-go-wasm/analysis"
)
```

`cedar` provides authorization and strict validation. `analysis` provides
policy comparison. Importing only `cedar` embeds only the authorization module.

The package reorganization moves the former module-root import to
`github.com/ChrisMckerracher/cedar-go-wasm/cedar`. Existing callers should
update that import; exported names and behavior are preserved.

See the [authorization example](../cedar/example_test.go),
[analysis example](../analysis/example_test.go), and generated references for
[`cedar`](https://pkg.go.dev/github.com/ChrisMckerracher/cedar-go-wasm/cedar)
and [`analysis`](https://pkg.go.dev/github.com/ChrisMckerracher/cedar-go-wasm/analysis).

## Runtime lifecycle

Create one `Runtime` per process and share it. `NewRuntime` verifies the
embedded module's SHA-256, checks its imports, and compiles it with wazero.
Each `Authorizer` holds a schema, policy set, and entity set, with a pool of
instances that parse their own copy of that configuration.

Both `Runtime` and `Authorizer` are safe for concurrent use. Close authorizers
before closing their runtime. `Authorizer.Close` waits for active calls;
`Runtime.Close` releases all of its instances.

For faster startup, supply a compilation cache:

```go
cache, err := wazero.NewCompilationCacheWithDir(cacheDir)
if err != nil {
	return err
}
defer cache.Close(ctx)
rt, err := cedar.NewRuntime(ctx, cedar.WithCompilationCache(cache))
if err != nil {
	return err
}
defer rt.Close(ctx)
```

This snippet uses `github.com/tetratelabs/wazero`. Keep the cache alive for
the lifetime of the runtimes using it. See [Performance](performance.md).

## Schemas and policies

| Constructor | Input |
|---|---|
| `SchemaFromCedar(text)` | Cedar schema text |
| `SchemaFromJSON(data)` | Cedar JSON schema |
| `PoliciesFromCedar(text)` | Cedar policy text |
| `PoliciesFromJSON(data)` | Cedar JSON policy set |

These constructors retain source text. Parsing happens when an authorizer
loads the configuration or `Runtime.Validate` runs. `Format()` and `Text()`
return the retained syntax and text.

Supplying `Config.Schema` enables entity, context, and request checks, and
adds the schema's action entities. Run `Runtime.Validate` separately to
check the policies themselves.

In Cedar text, policies receive IDs `policy0`, `policy1`, and so on in source
order. An `@id` annotation is metadata; it does not assign the policy ID.

## Templates (experimental)

Template management is an experimental Go API and may change in a minor release.
Its Cedar semantics come from the pinned Rust `PolicySet` operations.

| Operation | Result |
|---|---|
| `TemplateFromCedar(text)`, `TemplateFromJSON(data)` | Immutable template source; parsed on add |
| `rt.AddTemplate(ctx, set, templateID, template)` | New set containing a template with an explicit ID |
| `rt.Templates(ctx, set)` | Templates sorted by ID, with Cedar/JSON, annotations, and sorted slot names |
| `rt.LinkTemplate(ctx, set, templateID, policyID, bindings)` | New set containing the named template-linked policy |
| `rt.TemplateLinks(ctx, set)` | Links sorted by policy ID, with template IDs and slot bindings |
| `rt.UnlinkTemplate(ctx, set, policyID)` | New set without the linked policy; template retained |
| `rt.RemoveTemplate(ctx, set, templateID)` | New set without the template; fails if links remain |

`SlotBindings` maps `PrincipalSlot` (`?principal`) and `ResourceSlot`
(`?resource`) to `EntityUID` values. Bindings must exactly match the slots
in the template. Rust rejects missing/extra bindings, invalid UIDs, duplicate
IDs across templates and policies, and attempts to unlink static policies.
Upstream diagnostics are returned as `*cedar.Error` with `KindPolicies`.
An empty `PolicySet{}` starts a new set. A slot-free policy is not a template.

Each successful edit returns an immutable JSON-backed `PolicySet`, preserving
static policies, template IDs, linked-policy IDs, annotations, and bindings.
It can be passed directly to `NewAuthorizer` and `Validate`, or persisted
using `Text()` and restored with `PoliciesFromJSON`. Failed operations return
an error and a zero result. Always check the error before replacing your set.
Invalid UTF-8 is rejected before JSON encoding so IDs cannot be silently
changed by replacement characters. Input values and previously created
authorizers do not change. Original source
formatting is not retained by the JSON conversion.

Linking does not validate schema types: a syntactically valid binding can
produce a policy that fails strict validation. Call `Runtime.Validate` on the
result before creating a new authorizer when schema correctness is required.
Unlinked templates do not participate in authorization; linked policy IDs
appear in decision reasons. Returned ID fields retain the raw ID, including
quotes, backslashes, and control characters; diagnostic messages use Rust
formatting.

Every call uses a fresh guest instance and releases it on success, failure,
or cancellation. The caller's context bounds execution; `WithMaxSourceBytes`
bounds the whole encoded input (including source, IDs, and bindings), and the
existing memory and response limits apply. These calls are safe to invoke
concurrently but are not governed by an authorizer's `MaxInstances` pool;
callers should bound their own concurrency. Do not mutate bindings during a
call. Returned inspection maps/slices are owned by the caller and do not
alter policy snapshots.

The [runnable template example](../cedar/templates_example_test.go) adds a
template, links it, validates and authorizes it, then unlinks and removes it:

```bash
go test -run '^ExampleRuntime_LinkTemplate$' -v ./cedar
```

## Entities and values

Build entities with `NewEntities` and contexts with `NewContext`, or pass
Cedar JSON through `EntitiesFromJSON` and `ContextFromJSON`. The JSON
constructors copy their byte slices. Typed records and slices should be
treated as immutable while being used by a call.

| Go type | Cedar value |
|---|---|
| `Bool`, `Long`, `String` | Boolean, signed 64-bit integer, string |
| `Set`, `Record` | Set of values, map of attribute names to values |
| `EntityUID` | Entity reference, constructed with `NewEntityUID(typeName, id)` |
| `Decimal` | Decimal constructor string, such as `"12.3456"` |
| `IPAddr` | Address or range, such as `"10.0.0.0/8"` |
| `Datetime`, `Duration` | Constructor strings, such as `"2026-10-01T12:00:00Z"` and `"1h30m"` |

An `Entity` has a `UID`, `Attrs`, `Parents`, and `Tags`. Cedar computes the
transitive closure of its parents. The zero `Entities` value represents an
empty entity set; the zero `Context` value represents an empty record.

Values marshal using Cedar's JSON conventions, including `__entity` and
`__extn` escapes. Cedar interprets a record containing only either of these
keys as the corresponding escape. `EntityUID.String()` is for display;
use its fields or JSON representation when passing it to Cedar.

## Authorization

`Runtime.NewAuthorizer(ctx, Config)` parses the configuration and loads the
first instance. `Authorizer.Authorize(ctx, Request)` evaluates one request.

| Request field | Meaning |
|---|---|
| `Principal`, `Action`, `Resource` | Entity UIDs for the request |
| `Context` | Context record, checked against the action's schema |
| `Entities` | Optional additional entities for this call |

Per-request entities are merged with the configured entities for that call.
Conflicting definitions of the same UID are errors.

| Response field | Meaning |
|---|---|
| `Decision` | `Allow` or `Deny`; the zero value is `Deny` |
| `Reasons` | Sorted IDs of policies that determined the decision |
| `Errors` | Evaluation diagnostics, sorted by policy ID |

Policy IDs in reasons and diagnostics preserve the original identity, including
quotes, newlines, backslashes, and NUL. Diagnostic message text uses Cedar's
human-readable rendering.

Always handle the returned Go error. On any Go error, the response denies.
`Response.Errors` is different: Cedar skips policies whose evaluation fails
and computes a decision from the remaining policies, which can still allow.

`Authorizer.Stats()` reports `Created`, `Discarded`, and `Idle` instance counts.

## Entity slicing

`Runtime.SliceEntities(ctx, SliceConfig, Request)` computes a whole-entity slice
for one concrete request from a complete entity snapshot. This is useful when
preparing smaller authorization inputs for storage or transport. It parses the
complete source, so it does not reduce the cost of fetching that source initially.
`Request.Entities` augments `SliceConfig.Entities`, with the same conflict checks
as ordinary authorization.

The implementation uses Cedar 4.13.0's experimental
[`PolicySet::is_authorized_batched`](https://docs.rs/cedar-policy/4.13.0/cedar_policy/struct.PolicySet.html#method.is_authorized_batched)
and [`EntityLoader`](https://docs.rs/cedar-policy/4.13.0/cedar_policy/trait.EntityLoader.html).
Rust chooses which UIDs to load; Go does not analyze policy dependencies.
The `tpe` feature replaces the deprecated `entity-manifest` path. No legacy
manifest compatibility is provided because there is no existing Go manifest
contract to preserve. This API is experimental and tied to the pinned Cedar
version; its signature and behavior may change with upstream TPE.

| Result field | Meaning |
|---|---|
| `Decision` | Concrete allow or deny; any Go error returns an empty denying result |
| `Entities` | Requested existing entities, retaining all attributes, tags, and transitive ancestor UIDs |
| `Batches` | Sorted UID requests per loader round, including nonexistent entities |

Keep the same schema when reusing the slice: schema action entities are supplied
by Cedar and may require no loader call. Ancestor UIDs are retained even when
their own attributes were never requested. Missing entities remain absent.
Conditional branches can avoid loads; the result is neither a minimal entity
set nor a statement that every returned entity or attribute was necessary.

The supported loader requests whole entities. It does **not** provide a static
manifest covering all requests, nested attribute projections, or a list of
attributes to fetch. The slice is valid only for the same policies, schema,
principal, action, resource, context, and entity snapshot. Invalidate it when
any of those change. The guarantee concerns the authorization decision, not
identical evaluation diagnostics or determining-policy lists after early TPE
decisions. For applications that need to fetch data on demand, use the batched
authorization loader path instead of first building a complete source snapshot.

```go
slice, err := rt.SliceEntities(ctx, cedar.SliceConfig{
    Schema: schema, Policies: policies, Entities: source,
}, request)
if err != nil {
    return err
}
authorizer, err := rt.NewAuthorizer(ctx, cedar.Config{
    Schema: &schema, Policies: policies, Entities: slice.Entities,
})
```

See the [executable example](../cedar/slicing_test.go). Source data, request, and
context are validated against the required schema; TPE typechecks policies for
the request's types. `MaxIterations` bounds loading rounds (zero selects 32).
Exhaustion or TPE validation failure returns `KindSlicing`, never a partial slice.
The caller's context bounds the entire operation; there is no implicit timeout.
`WithMaxSourceBytes` caps the encoded combined input (64 MiB by default),
`WithMemoryLimit` caps each guest (256 MiB), and responses are capped at 16 MiB.
Exceeding guest memory or response limits returns `KindFault`. Each operation
uses a fresh instance and closes it on success, cancellation, or error.
Limit concurrent slicing calls in the application; these runtime calls have no
instance pool or aggregate memory cap.

## Strict validation

```go
result, err := rt.Validate(ctx, schema, policies)
if err != nil {
	return err
}
if !result.Passed {
	return fmt.Errorf("invalid policies: %v", result.Errors)
}
```

`ValidationResult` contains `Passed`, `Errors`, and `Warnings`. Each
`PolicyMessage` has a `PolicyID` and `Message`. Warnings alone do not fail
validation. Parse errors are returned as Go errors; type errors appear in
the validation result. The caller's context bounds validation time.

## Errors

Use `errors.As` to inspect `*cedar.Error` and its `Kind`, and `errors.Is` to
check `cedar.ErrFault`, `context.DeadlineExceeded`, or `context.Canceled`.

| Error kind | Meaning |
|---|---|
| `KindSchema`, `KindPolicies` | Source parsing or policy/template operation failed |
| `KindEntities`, `KindContext`, `KindRequest` | Data parsing or schema checks failed |
| `KindPrincipal`, `KindAction`, `KindResource` | A UID failed to parse |
| `KindInput` | Request envelope or Go value encoding failed |
| `KindSlicing` | TPE validation or entity-loading iteration limit failed |
| `KindLimit` | Encoded input exceeded its configured size limit |
| `KindFault` | Guest trap, timeout, abort, or broken module protocol |

The [failure behavior table](security.md#failure-behavior) explains when an
instance is reused or discarded. Callers should treat any returned error
as a failed authorization operation, including pool and context errors
that are not `*cedar.Error`.

## Configuration reference

| Runtime option | Purpose |
|---|---|
| `WithMemoryLimit(bytes)` | Maximum linear memory per instance |
| `WithCompilationCache(cache)` | Reuse compiled machine code |
| `WithMaxSourceBytes(bytes)` | Maximum encoded runtime operation input |

| `Config.Limits` field | Purpose |
|---|---|
| `MaxInstances` | Maximum concurrent module instances |
| `CallTimeout` | Maximum guest execution time per authorization |
| `LoadTimeout` | Maximum time to create and load an instance |
| `MaxRequestBytes` | Maximum encoded request size |
| `RecycleMemoryBytes` | Replace instances that retain too much linear memory |

Zero-valued limit fields select defaults. A negative `CallTimeout` disables
the per-call deadline; the caller's context still applies. The caller's
context also bounds waiting for an available instance.
See [default limits](security.md#resource-limits).

`CedarVersion`, `SymCCVersion`, and `ModuleSHA256()` identify the embedded
implementation. See [versioning](maintenance.md#versioning).

## Supported operations

The Go interface exposes authorization, strict validation, parsed policy
inspection and static policy edits, template management, experimental partial
evaluation, on-demand entity loading and
request-specific entity slicing, and the policy comparisons in `analysis`. These
execute Cedar's Rust implementation, including its core and extension value types.

Conformance results establish agreement for the tested operations. The Rust
library also exposes APIs for deprecated entity manifests and formatting;
those APIs are outside this Go interface. See
[verification scope](verification.md) for the evidence behind compatibility
claims.

## Experimental on-demand entity loading

`Authorizer.AuthorizeBatched(ctx, request, loader, options)` calls Cedar 4.13.0's
experimental `PolicySet::is_authorized_batched`. This authorizes **one request**
using Rust type-aware partial evaluation to discover entity UIDs as needed. It
returns `(Decision, error)`, with `Deny` on every error. Rust returns no policy
reasons or residual result from this operation. A schema and policies that pass
upstream strict validation are required. Experimental APIs may change with the
pinned Cedar version.

```go
loader := cedar.EntityLoaderFunc(func(ctx context.Context, uids []cedar.EntityUID) (cedar.EntityLoadResult, error) {
    // Query your store using ctx. Each returned entity includes all ancestor UIDs.
    entities, missing, err := store.Load(ctx, uids)
    return cedar.EntityLoadResult{Entities: entities, Missing: missing}, err
})
decision, err := authorizer.AuthorizeBatched(ctx, request, loader,
    cedar.BatchedOptions{MaxIterations: 8})
```

`EntityLoadResult.Entities` is a Cedar JSON entity array (`json.RawMessage`). Use
`json.Marshal(cedar.NewEntities(...))` for typed data. Raw JSON lets the bridge
reject oversized results before parsing or copying them. `Missing` explicitly
marks nonexistent UIDs, matching Rust's `None`. Omitting a UID from both fields
leaves it unknown: Rust can request it again and eventually report insufficient
iterations. Callback errors are never converted into missing entities. Extra
entities are allowed; duplicate or conflicting entries are errors. Callback data
must not repeat any configured/request entity UID, even with identical data, or
mark such a UID missing. Unlike the
ordinary `Entity.Parents` contract, callback entity parents must contain the
**complete transitive ancestor set**, as upstream's loader assumes ancestry is
already computed. The bridge parses callback entities individually and does not
infer ancestry across callback rounds.

`MaxIterations` is explicit and capped at 1024. Zero allows only the initial Rust
evaluation; a request already determined can succeed without loading. Each Rust
loader round counts, including rounds served entirely from configured or
request-specific entities. Rust checks for a decision after the last round;
unresolved results return `KindBatched` with upstream's insufficient-iterations
error. Loaded/request entities are a per-call cache. Callback results never
change the authorizer or subsequent requests.

Callbacks run synchronously and serially within a call. A shared loader may be
called concurrently by separate authorizations and must synchronize its own
state. Each callback receives a Go-owned UID slice that it may retain. Returned
JSON and missing UID slices must remain immutable until `AuthorizeBatched`
returns. The bridge copies encoded results into guest-owned memory. A loader
must not recursively call or close the same authorizer: the call holds a pooled
instance, and waiting on that pool can deadlock.

The request envelope uses `Limits.MaxRequestBytes`. `MaxBatchBytes` defaults to
1 MiB and caps each encoded UID request and result, with a 64 MiB maximum.
`MaxLoaderBytes` defaults to 16 MiB and caps their cumulative bytes across the
call. Raw callback JSON must also fit the remaining budgets before encoding;
JSON envelope and escaping bytes count. Existing guest memory, response,
recycling, and load limits remain in force. `Limits.CallTimeout` includes guest
execution and callbacks; the caller context also bounds waiting for an instance.
Callbacks must honor their context. Go cannot interrupt a callback that blocks
or bound allocations made by application callback code, so loaders remain trusted
host code. No detached callback goroutines are created.

Callback errors use `KindLoader`, preserve their cause for `errors.Is`, and discard
the guest. Callback panics become `KindLoader` without exposing the panic value.
Host byte limits use `KindLimit`; context cancellation/timeouts use `KindFault`
with the context cause. Invalid entity data uses `KindEntities`. Rust TPE and
iteration failures use `KindBatched`. See the executable
`ExampleAuthorizer_AuthorizeBatched` and the native parity fixtures in
`testdata/parity/batched`.

## Parsed policies and static policy edits

The existing `PoliciesFromCedar` and `PoliciesFromJSON` constructors still defer
parsing. Use `Runtime.ParsePolicySet` for immediate parsing and an immutable
`ParsedPolicySet`, or `Runtime.ParsePolicy(ctx, id, cedarText)` for one static
policy with an explicit ID. `Runtime.PolicyFromJSON` accepts one policy's Cedar
JSON and an explicit ID. Even the empty ID is preserved; `@id` is an annotation,
not an instruction to set the policy ID.

A `ParsedPolicy` exposes its ID, permit/forbid effect, annotations, principal,
action and resource constraints, whether it has condition clauses, and whether
it is linked to a template. `Policy(id)` looks up an ID without parsing again;
`Policies()` lists static and linked policies in ID order, excluding templates.
Snapshots are independent of the runtime's lifetime and safe to share. Returned
maps, byte slices, syntax and constraints are copies. The zero `ParsedPolicySet`
is empty; the zero `ParsedPolicy` is invalid.

`Runtime.AddPolicy`, `RemovePolicy`, and `MergePolicySets` accept source-based
`PolicySet` values and return new parsed snapshots. Feed their `Source()` into
`NewAuthorizer`, `Validate`, template operations, or another edit. Rust performs
all parsing and set operations. Addition rejects duplicate IDs. Removal accepts
only static IDs; missing IDs, template IDs and linked policy IDs produce Rust's
`remove_static` error. Merge follows Rust's equality/conflict handling and can
rename conflicts, returning its old-to-new ID map. Failed edits leave the inputs
unchanged. For replacement, remove the old static ID then add its replacement;
keep the original snapshot until both operations succeed.

```go
policy, err := rt.ParsePolicy(ctx, "read-photos",
    `@owner("photos") permit(principal, action == Action::"view", resource is Photo);`)
if err != nil { return err }
set, err := rt.AddPolicy(ctx, cedar.PoliciesFromCedar(""), policy)
if err != nil { return err }
// This source preserves "read-photos" in authorization and validation diagnostics.
source := set.Source()
```

`PolicySyntax` and `Runtime.PolicyFromSyntax` are **experimental**. They expose a
static-policy projection of Cedar 4.13's policy syntax tree (PST): ID, effect,
annotations, typed head constraints, and ordered `when`/`unless` conditions.
Rust constructs the actual upstream PST and calls `Policy::from_pst`; inspection
calls `Policy::to_pst`. Upstream PST has no JSON serialization. Each condition
body therefore uses Cedar's JSON policy expression format (`json.RawMessage`),
with its full expression vocabulary and exact integer representation. No Cedar
parser or evaluator is implemented in Go. `Syntax()` returns an editable copy;
pass the modified value to `PolicyFromSyntax` to validate it. Scope constraints
must specify their `Kind`; `eq`/`in` use `Entity`, `is` uses `EntityType`, and
`is_in` uses both. Action `in` uses `Entities`, including an empty set. Unused
constraint fields must be empty. Conditions are optional; malformed names,
constraints, expressions, and slots are rejected by Rust. A parsed policy need
not pass schema validation: call `Validate` before using it if schema validity
is required.

Persistence and display have different contracts:

| Conversion | IDs and template links |
| --- | --- |
| `ParsedPolicySet.JSON()` / `Source()` | Preserve IDs, templates, and links; use for persistence |
| `ParsedPolicy.JSON()` | One policy body only; ID must be supplied on reparse; linked bodies are materialized without link metadata |
| `ParsedPolicy.Syntax()` | Static policies only; includes the explicit ID; PST normalization can change syntax spelling |
| `Cedar()` on a policy or set | Omits IDs; reparsing a set assigns `policy0`, `policy1`, etc.; rejects linked policies to avoid silently discarding their representation |

Set Cedar output sorts static policies by ID, followed by templates by ID.
Cedar rendering is not a formatter and does not promise comment, whitespace,
annotation spelling, or source order preservation. PST normalizes empty and
valueless annotations. Use template operations for editing linked policies.

All runtime policy operations use a fresh Wasm instance and honor cancellation,
`WithMaxSourceBytes` (the whole encoded operation, including all inputs), memory
limits, and response bounds. They have no implicit timeout: use a context deadline
for untrusted input. Large snapshots repeat policy information, so response limits
can be reached before source limits. Parse/edit failures return `*Error` with
`KindPolicies`; malformed operation/syntax envelopes may return `KindInput`.
New policy operation inputs must contain valid UTF-8; malformed bytes are rejected
before Go JSON encoding could replace them and change an ID.
Resource exhaustion and interrupted execution return faults; canceled operations
do not invalidate other snapshots or the runtime.

See the executable `ExampleRuntime_ParsePolicy` and
`ExampleRuntime_PolicyFromSyntax` examples in `cedar/policies_example_test.go`.

## Partial evaluation (experimental)

`Authorizer.PartialAuthorize` uses Cedar 4.13.0 TPE with explicit unknown inputs
and a separate `PartialDecision` (`Undecided`, `PartialDeny`, `PartialAllow`).
Inspect `PartialResponse.Residuals`, then supply consistent concrete data with
`PartialResponse.Reauthorize`. A schema is required. See
[partial evaluation](partial-evaluation.md) for supported unknowns, limits,
upstream experimental status, and the executable example.
