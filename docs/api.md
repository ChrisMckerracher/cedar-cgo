# Go API

[Documentation](README.md) · [Change analysis](analysis.md) · [Security model](security.md)

## Contents

- [Packages and imports](#packages-and-imports)
- [Runtime lifecycle](#runtime-lifecycle)
- [Schemas and policies](#schemas-and-policies)
- [Entities and values](#entities-and-values)
- [Authorization](#authorization)
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

Always handle the returned Go error. On any Go error, the response denies.
`Response.Errors` is different: Cedar skips policies whose evaluation fails
and computes a decision from the remaining policies, which can still allow.

`Authorizer.Stats()` reports `Created`, `Discarded`, and `Idle` instance counts.

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
| `KindSchema`, `KindPolicies` | Source parsing failed |
| `KindEntities`, `KindContext`, `KindRequest` | Data parsing or schema checks failed |
| `KindPrincipal`, `KindAction`, `KindResource` | A UID failed to parse |
| `KindInput` | Request envelope or Go value encoding failed |
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
| `WithMaxSourceBytes(bytes)` | Maximum encoded load or validation input |

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

The Go interface exposes static-policy authorization, strict validation,
and the policy comparisons in `analysis`. These execute Cedar's Rust
implementation, including its core and extension value types.

Conformance results establish agreement for the tested operations. The Rust
library also exposes APIs for template linking, partial evaluation, entity
slicing, and formatting; those APIs are outside this Go interface. See
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
