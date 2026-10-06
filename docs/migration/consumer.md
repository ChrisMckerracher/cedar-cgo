# Native migration lessons for Go consumers

The module path remains `github.com/ChrisMckerracher/cedar-go-wasm`.
This migration changes the public Go API and native build requirements.
Use a breaking pre-v1 minor release for these changes.
The post-cgo cleanup targets v0.3.0. It changes the v0.2.0 public interface.
This decision does not create a release tag.
See the [native contract](native-contract.md) and [supported platforms](platforms.md).

## Lesson 1: Change imports and construction

Objective: Select domain records and create the native runtime.

1. Build the native source or extract a verified prebuilt source bundle.
2. Enable cgo and select the supported C compiler.
3. Replace former `cedar` record imports with their domain packages.

```go
import (
    "context"
    "github.com/ChrisMckerracher/cedar-go-wasm/analysis"
    "github.com/ChrisMckerracher/cedar-go-wasm/analysis/compiled"
    "github.com/ChrisMckerracher/cedar-go-wasm/analysis/options"
    "github.com/ChrisMckerracher/cedar-go-wasm/analysis/report"
    "github.com/ChrisMckerracher/cedar-go-wasm/analysis/solver"
    "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
    "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization"
    "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/partial"
    partialinput "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/partial/input"
    permissionquery "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/partial/query"
    "github.com/ChrisMckerracher/cedar-go-wasm/cedar/authorization/request"
    "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity"
    "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/slicing"
    "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/store"
    "github.com/ChrisMckerracher/cedar-go-wasm/cedar/entity/uid"
    "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy"
    "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy/literal"
    "github.com/ChrisMckerracher/cedar-go-wasm/cedar/policy/template"
    "github.com/ChrisMckerracher/cedar-go-wasm/cedar/schema"
    "github.com/ChrisMckerracher/cedar-go-wasm/cedar/value"
)
```

Each following worked example assumes a function that returns `error`.
Import only the packages that the function uses.

```go
ctx := context.Background()
rt, err := cedar.NewRuntime(ctx, cedar.WithMaxConcurrentCalls(8))
if err != nil { return err }
defer rt.Close(ctx)
s := schema.SchemaFromCedar(`entity User; entity Photo;
    action view appliesTo {principal: User, resource: Photo, context: {mfa: Bool}};`)
p := policy.PoliciesFromCedar(`permit(principal, action, resource) when {context.mfa};`)
```

Knowledge check: Does `NewRuntime` compile Wasm? No. It checks the linked native ABI.

## Lesson 2: Replace options and feature methods

Objective: Apply supported bounds without promising native heap containment.

1. Keep source and request byte limits.
2. Set explicit native concurrency limits.
3. Remove unsupported Wasm controls.
4. Obtain feature clients from the runtime or authorizer.

| Previous API | Native API or behavior |
|---|---|
| `rt.Validate(...)` | `rt.Validation().Validate(...)` |
| `rt.ParsePolicySet(...)` | `rt.Policies().ParsePolicySet(...)` |
| `rt.LinkTemplate(...)` | `rt.Templates().LinkTemplate(...)` |
| `rt.FormatPolicies(...)` | `rt.Formatter().FormatPolicies(...)` |
| `rt.TokenizePolicies(...)` | `rt.Source().TokenizePolicies(...)` |
| `rt.InspectSchema(...)` | `rt.Schemas().InspectSchema(...)` |
| `rt.ParseEntityStore(...)` or `rt.Entities().ParseEntityStore(...)` | `rt.EntityStore().ParseEntityStore(...)` |
| `rt.EvalExpression(...)` | `rt.Expressions().EvalExpression(...)` |
| `rt.LanguageVersion(...)` | `rt.Utilities().LanguageVersion(...)` |
| `rt.ApplicableEnvironments(...)` | `rt.Applicability().ApplicableEnvironments(...)` |
| `rt.SliceEntities(...)` | `rt.Slicing().SliceEntities(...)` |
| `a.AuthorizeBatched(...)` | `a.Batched().AuthorizeBatched(...)` |
| `a.PartialAuthorize(...)` | `a.Partial().PartialAuthorize(...)` |
| Permission query methods | `a.Queries()` methods; records in `partial/query` |
| Partial input records | Import `partial/input`; continuations remain in `partial` |
| Entity-store records | Import `entity/store`; collections remain in `entity` |
| Entity-literal methods | `rt.PolicyLiterals()`; records in `policy/literal` |
| Context utility methods | Pass `rt.Utilities()` instead of `rt` |
| `EntityUID` as a `Value` | Use `value.EntityRef(uid.NewEntityUID(...))` |
| `WithMemoryLimit`, `WithCompilationCache` | Removed in v0.3.0; v0.2.0 rejected these options |
| `RecycleMemoryBytes` | Removed in v0.3.0; v0.2.0 rejected nonzero values |
| `CedarVersion`, `SymCCVersion` | Constants in `cedar/syntax` |
| `ModuleSHA256()` | Removed; use the native artifact manifest |
| `analysis.CVC5(...)` | `solver.CVC5(...)` |
| Analysis `With*` options, `Option`, and default limit constants | Import `analysis/options` |
| `CompiledSession`, `CompiledPolicySet`, `RequestEnvironment`, `ErrCompiledClosed` | Use `compiled.Session`, `PolicySet`, `RequestEnvironment`, `ErrClosed` |
| Analysis `Report`, `Error`, and result records | Import `analysis/report` |

Pass `*schema.Schema` or nil to `store.Client.ParseEntityStore`. The removed `entity.SchemaSource` interface no longer accepts custom wrappers.
Permission decoders `DecodeQuery` and `DecodeQueryUIDs` move from `partial` to `partial/query`.
Analysis defaults `DefaultTimeout`, `DefaultMaxSourceBytes`, and `DefaultMaxSolverOutput` move to `analysis/options`.

Worked example: Set `authorization.Limits{MaxInstances: 4, MaxRequestBytes: 1 << 20}` when creating an authorizer.
The runtime also caps shared active native calls.
Deadlines reject canceled results after native execution returns.
They cannot interrupt native CPU work without a cooperative callback.

Knowledge check: Can the removed Wasm memory option bound native heap allocation? No. Use process controls when required.

## Lesson 3: Validate and authorize

Objective: Retain explicit strict validation and Deny on operation failure.

1. Validate policies before creating an authorizer when schema correctness is required.
2. Create an authorizer with domain records.
3. Check the Go error before using the decision.

```go
checked, err := rt.Validation().Validate(ctx, s, p)
if err != nil { return err }
if !checked.Passed { return fmt.Errorf("policy validation failed: %v", checked.Errors) }
a, err := rt.NewAuthorizer(ctx, authorization.Config{Schema: &s, Policies: p})
if err != nil { return err }
defer a.Close()
req := request.Request{
    Principal: uid.NewEntityUID("User", "alice"),
    Action: uid.NewEntityUID("Action", "view"),
    Resource: uid.NewEntityUID("Photo", "beach"),
    Context: request.NewContext(value.Record{"mfa": value.Bool(true)}),
}
response, err := a.Authorize(ctx, req)
if err != nil { return err }
fmt.Println(response.Decision) // allow
```

Add `fmt` to the imports for this example.
The [executable authorization example](../../cedar/integration/example_test.go) also demonstrates Deny behavior.
Cedar evaluation diagnostics can accompany Allow.
They remain different from Go operation errors.

Knowledge check: Does configuration loading perform strict policy validation? No. Call the validation client explicitly.

## Lesson 4: Link templates

Objective: Preserve template identities and linked policy identities.

1. Add a template with an explicit ID.
2. Bind its slots to concrete UIDs.
3. Validate the returned policy set.

```go
set, err := rt.Templates().AddTemplate(ctx, policy.PolicySet{}, "share",
    template.TemplateFromCedar(`permit(principal == ?principal,
        action == Action::"view", resource == ?resource);`))
if err != nil { return err }
set, err = rt.Templates().LinkTemplate(ctx, set, "share", "alice-beach", template.SlotBindings{
    template.PrincipalSlot: uid.NewEntityUID("User", "alice"),
    template.ResourceSlot: uid.NewEntityUID("Photo", "beach"),
})
if err != nil { return err }
```

The [executable template example](../../cedar/policy/template/templates_example_test.go) validates, authorizes, unlinks, and removes this template.
Persist `set.Text()` and restore it through `policy.PoliciesFromJSON`.

Knowledge check: Does linking validate schema types? No. Validate the result before use.

## Lesson 5: Persist partial continuations

Objective: Preserve frozen inputs and complete native residual semantics.

1. Represent unknown inputs explicitly.
2. Export the versioned continuation instead of display text.
3. Import it through a compatible open authorizer.
4. Supply a consistent concrete completion.

```go
result, err := a.Partial().PartialAuthorize(ctx, partialinput.PartialRequest{
    Principal: partialinput.UnknownEntityUID("User"),
    Action: uid.NewEntityUID("Action", "view"),
    Resource: partialinput.UnknownEntityUID("Photo"),
})
if err != nil { return err }
stored, err := result.Export()
if err != nil { return err }
restored, err := a.Partial().ImportPartialResponse(ctx, stored)
if err != nil { return err }
response, err := restored.Reauthorize(ctx, req)
if err != nil { return err }
```

The [partial example](../../cedar/authorization/partial/partial_example_test.go) demonstrates Allow and Deny completions.
The [persistence tests](../../cedar/authorization/partial/residual_export_test.go) check corruption and incompatible inputs.
Public display edits cannot alter the private continuation.

Knowledge check: Can residual display text replace `Export()`? No. It omits required native state.

## Lesson 6: Slice entities

Objective: Build a request-specific entity slice with native Cedar.

1. Supply the complete source snapshot and schema.
2. Slice for one concrete request.
3. Reuse the slice only with the same request, policies, schema, and source data.

```go
slice, err := rt.Slicing().SliceEntities(ctx, slicing.SliceConfig{
    Schema: s, Policies: p, Entities: entity.NewEntities(),
}, req)
if err != nil { return err }
sliced, err := rt.NewAuthorizer(ctx, authorization.Config{
    Schema: &s, Policies: p, Entities: slice.Entities,
})
if err != nil { return err }
defer sliced.Close()
```

The [slicing tests](../../cedar/entity/slicing/slicing_test.go) compare sliced and complete authorization decisions.
For external entity loading, use `a.Batched()` and honor callback contexts.
Callbacks must not recursively call or close the same authorizer.

Knowledge check: Is a slice a static manifest for all requests? No. Its validity depends on the concrete request.

## Lesson 7: Use solver-backed analysis

Objective: Preserve real solver transport and compiled-session ownership.

1. Provide the separate cvc5 executable.
2. Construct analysis through `analysis.New` and `solver.CVC5`.
3. Check the Go error before interpreting the report.
4. Close compiled sessions and the analyzer after their work finishes.

```go
analyzer, err := analysis.New(ctx, solver.CVC5("/absolute/path/to/cvc5"))
if err != nil { return err }
defer analyzer.Close(ctx)
report, err := analyzer.Equivalent(ctx, s, p, p)
if err != nil { return err }
fmt.Println(report.Holds()) // true
```

The [independent consumer](../../scripts/consumer/smoke/main.go) runs native authorization and both solver outcomes without Rust.
The [analysis guide](../analysis.md) covers compiled reuse, counterexample replay, and solver limits.
`analyzer.OpenCompiled` creates a child session. Closing the analyzer cancels and closes that child.
For independent ownership, use `compiled.New(ctx, solver.CVC5(path), s, nil)` and close the returned session explicitly.
The standalone constructor accepts the same selection records and `options.Option` values.

Knowledge check: Does a native archive include cvc5? No. The solver has separate installation and license requirements.

## Lesson 8: Edit Cedar JSON policies

Objective: Replace typed syntax editing without changing IDs, links, or exact integers.

1. Obtain an owned policy body through `ParsedPolicy.JSON()`.
2. Change Cedar JSON fields without converting integers to floating point.
3. Supply the policy ID separately to `PolicyFromJSON`.
4. Persist complete sets through `ParsedPolicySet.JSON()` or `Source()`.

```go
body := []byte(`{"effect":"permit","principal":{"op":"All"},
    "action":{"op":"==","entity":{"type":"Action","id":"view"}},
    "resource":{"op":"All"},"conditions":[]}`)
edited, err := rt.Policies().PolicyFromJSON(ctx, "read-photos", body)
if err != nil { return err }
set, err := rt.Policies().AddPolicy(ctx, policy.PolicySet{}, edited)
if err != nil { return err }
stored := set.JSON()
```

The [executable JSON example](../../cedar/policy/policies_example_test.go) constructs, inserts, and authorizes a JSON policy.
The [mapping checks](../../cedar/policy/pst_mapping_test.go) preserve exact integer conditions.
The ID is not part of the individual policy body. Full-set JSON retains IDs and template links.
Upstream Cedar can discard inapplicable scope fields and normalize clause spelling during Cedar rendering.
The adapter no longer applies separate typed-syntax rejection rules.

Removed editing exports: `PolicySyntax`, `PolicyCondition`, `ConstraintKind`, `ScopeConstraint`, and `ActionConstraint`, including their constants.
Removed constants: `ConstraintAny`, `ConstraintEq`, `ConstraintIn`, `ConstraintIs`, and `ConstraintIsIn`.
Removed methods: `Syntax()`, `PolicyFromSyntax`, `PrincipalConstraint`, `ActionConstraint`, and `ResourceConstraint`.
Inspect constraints through `JSON()`. Keep the returned body separate from the immutable snapshot.

Removed implementation exports: `ParsedPolicyData`, `ParsedSetData`, `PolicyOutput`, `ScopeWire`, `ActionWire`, `CloneScope`, and `CloneAction`.
Also removed: `PolicyUID`, `FromPolicyUID`, `PolicyInputUTF8`, `InvalidParsedPolicy`, `LiteralReplacement`, and `LiteralOutput`.
Private template records replace `TemplateInput` and `TemplateOutput`. Strict encoding replaces the removed `TemplateUTF8` helper.
Private entity records replace `EntityJSON`, `EntityStoreInput`, `EntityStoreOutput`, `NativeUIDs`, and `DecodeEntityRecord`.
The unused `authorization.LoadOutput` and implementation record `authorization.LoadInput` are removed.
Private extension encoding replaces `ExtnJSON` and `MarshalExtn`. Construct public `value` records instead of wire envelopes.
These exports exposed adapter implementation. Use domain constructors, snapshots, and feature clients for application code.

Removed lexer helpers: `SourceTokenSpelling`, `SourceTokenIdentifierByte`, `SourceTokenKeyword`, `SourceTokenTrivia`, `SourceTokenCommentGap`, `SourceTokenCommentSummaries`, and `SourceTokenKind`.
Use `rt.Source().TokenizePolicies` for the pinned native lexer. Keep the original source for exact token spans and comments.

Knowledge check: Does individual policy JSON preserve its ID or template link? No. Persist the complete set for those identities.
