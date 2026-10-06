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
- [Policy formatting](#policy-formatting)
- [Errors](#errors)
- [Configuration reference](#configuration-reference)
- [Supported operations](#supported-operations)
- [On-demand entity loading](#experimental-on-demand-entity-loading)
- [Parsed policies and static edits](#parsed-policies-and-static-policy-edits)
- [Partial evaluation](#partial-evaluation-experimental)

## Packages and imports

The module path is `github.com/ChrisMckerracher/cedar-cgo`.
Import `cedar` for runtime construction.
Import domain packages for records and feature clients.

```go
import (
    "github.com/ChrisMckerracher/cedar-cgo/cedar"
    "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"
    "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
    "github.com/ChrisMckerracher/cedar-cgo/cedar/entity"
    "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
    "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
    "github.com/ChrisMckerracher/cedar-cgo/cedar/schema"
    "github.com/ChrisMckerracher/cedar-cgo/cedar/value"
)
```

This migration changes the public Go API.
See the [consumer migration lessons](migration/consumer.md) for each feature.
The [operation inventory](migration/operations.md) records the earlier v0.2.0 migration.
The consumer guide also lists the v0.3.0 cleanup changes.
The [authorization example](../cedar/integration/example_test.go) and [analysis example](../analysis/example_test.go) are executable.

## Runtime lifecycle

Create one `Runtime` and share it between feature clients and authorizers.
`NewRuntime` checks the linked native ABI version.
Each authorizer holds a schema, policies, entities, and a pool of native states.
Each state parses its own configuration copy.

```go
rt, err := cedar.NewRuntime(ctx, cedar.WithMaxConcurrentCalls(8))
if err != nil {
    return err
}
defer rt.Close(ctx)
```

`Runtime` and `Authorizer` support concurrent calls.
Close authorizers before their runtime.
Close waits for active native calls and callbacks to return.
A runtime permits eight active native calls by default.
An authorizer permits eight pooled states by default.
Neither default depends on `GOMAXPROCS`.

A canceled context prevents entry or rejects a returned result.
It cannot interrupt native computation without a cooperative callback.
Native memory has no hard per-instance heap cap.
See the [native contract](migration/native-contract.md) for ownership and failure behavior.

## Schemas and policies

| Constructor | Input |
|---|---|
| `SchemaFromCedar(text)` | Cedar schema text |
| `SchemaFromJSON(data)` | Cedar JSON schema |
| `PoliciesFromCedar(text)` | Cedar policy text |
| `PoliciesFromJSON(data)` | Cedar JSON policy set |

These constructors retain source text. Parsing happens when an authorizer
loads the configuration or `validation.Client.Validate` runs. `Format()` and `Text()`
return the retained syntax and text.

Supplying `Config.Schema` enables entity, context, and request checks, and
adds the schema's action entities. Run `validation.Client.Validate` separately to
check the policies themselves.

In Cedar text, policies receive IDs `policy0`, `policy1`, and so on in source
order. An `@id` annotation is metadata; it does not assign the policy ID.

## Templates (experimental)

Template management is an experimental Go API and may change in a minor release.
Its Cedar semantics come from the pinned Rust `PolicySet` operations.

| Operation | Result |
|---|---|
| `TemplateFromCedar(text)`, `TemplateFromJSON(data)` | Immutable template source; parsed on add |
| `rt.Templates().AddTemplate(ctx, set, templateID, template)` | New set containing a template with an explicit ID |
| `rt.Templates().Templates(ctx, set)` | Templates sorted by ID, with Cedar/JSON, annotations, and sorted slot names |
| `rt.Templates().LinkTemplate(ctx, set, templateID, policyID, bindings)` | New set containing the named template-linked policy |
| `rt.Templates().TemplateLinks(ctx, set)` | Links sorted by policy ID, with template IDs and slot bindings |
| `rt.Templates().UnlinkTemplate(ctx, set, policyID)` | New set without the linked policy; template retained |
| `rt.Templates().RemoveTemplate(ctx, set, templateID)` | New set without the template; fails if links remain |

`SlotBindings` maps `PrincipalSlot` (`?principal`) and `ResourceSlot`
(`?resource`) to `EntityUID` values. Bindings must exactly match the slots
in the template. Rust rejects missing/extra bindings, invalid UIDs, duplicate
IDs across templates and policies, and attempts to unlink static policies.
Upstream diagnostics are returned as `*diagnostic.Error` with `KindPolicies`.
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
produce a policy that fails strict validation. Call `validation.Client.Validate` on the
result before creating a new authorizer when schema correctness is required.
Unlinked templates do not participate in authorization; linked policy IDs
appear in decision reasons. Returned ID fields retain the raw ID, including
quotes, backslashes, and control characters; diagnostic messages use Rust
formatting.

Every call uses a fresh native library instance and releases it on success, failure,
or cancellation. The caller's context controls admission and result acceptance; `WithMaxSourceBytes`
bounds the whole encoded input (including source, IDs, and bindings), and the
response limits apply. The runtime bounds concurrent native calls.
These calls do not use an authorizer pool. Do not mutate bindings during a
call. Returned inspection maps/slices are owned by the caller and do not
alter policy snapshots.

The [runnable template example](../cedar/policy/template/templates_example_test.go) adds a
template, links it, validates and authorizes it, then unlinks and removes it:

```bash
go test -run '^Example_linkTemplate$' -v ./cedar/policy/template
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
| `value.EntityRef` | Entity reference, constructed from `uid.NewEntityUID(typeName, id)` |
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

### Parsed entity stores

`store.Client.ParseEntityStore(ctx, entities, schema)` returns an immutable `store.ParsedEntityStore`.
Import `cedar/entity/store` for parsed stores. Import `cedar/entity` for entity collections.
Pass a nil schema to omit schema validation.
The schema argument is `*schema.Schema`, not the removed `entity.SchemaSource` interface.
A supplied schema validates entities and inserts its action entities.
The store remains tied to its runtime.
Close the runtime when all operations finish.

| Operation | Native result |
| --- | --- |
| `Get(ctx, uid)` | Entity values, direct parents, transitive ancestors, and an existence flag |
| `Ancestors(ctx, uid)` | Transitive ancestors and an existence flag |
| `IsAncestorOf(ctx, ancestor, descendant)` | Cedar membership, including equality for absent UIDs |
| `DeepEqual(ctx, other)` | Equality of UIDs, values, tags, and transitive ancestor sets |
| `Remove(ctx, uids...)` | A new store after deletion and edge cleanup |
| `Upsert(ctx, additions)` | A new store after replacement, schema validation, and ancestry computation |
| `Export()` | Native normalized entity JSON in an `Entities` value |

`Get` returns typed `EvalRecord` attributes and tags.
These values preserve signed 64-bit integers and extension results.
`ParsedEntity.JSON()` returns a copy of the native normalized entity JSON.

Mutations preserve the original store.
An invalid update returns an error and leaves the original graph available.
If an upsert contains duplicate UIDs, the last entity wins.
Removal deletes graph edges, but preserves entity-valued attribute references.
Native removal of an absent UID has no effect.

Normalized JSON contains transitive ancestors in each `parents` array.
Normalized exports sort JSON object keys.
The opaque snapshot retains direct parents separately through the native AST.
Use snapshot mutations to preserve those direct edges.
Reparsing normalized JSON treats all exported ancestors as direct parents, as native Cedar does.
Deep equality compares ancestry, so it does not distinguish these direct-parent histories.

```go
store, err := rt.EntityStore().ParseEntityStore(ctx, entities, &schema)
if err != nil {
    return err
}
changed, err := store.Remove(ctx, uid.NewEntityUID("Group", "old"))
if err != nil {
    return err
}
entity, found, err := changed.Get(ctx, principal)
if err != nil {
    return err
}
if found {
    fmt.Println(entity.Parents, entity.Ancestors)
}
normalized := changed.Export()
```

Operations reconstruct and mutate the graph in Rust.
The Go snapshot contains no editable graph maps.
Each call uses a fresh native library instance and the runtime's source and response limits.
Cancellation rejects the result after native execution returns.

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

`slicing.Client.SliceEntities(ctx, SliceConfig, Request)` computes a whole-entity slice
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
slice, err := rt.Slicing().SliceEntities(ctx, slicing.SliceConfig{
    Schema: schema, Policies: policies, Entities: source,
}, request)
if err != nil {
    return err
}
authorizer, err := rt.NewAuthorizer(ctx, authorization.Config{
    Schema: &schema, Policies: policies, Entities: slice.Entities,
})
```

See the [executable example](../cedar/entity/slicing/slicing_test.go). Source data, request, and
context are validated against the required schema; TPE typechecks policies for
the request's types. `MaxIterations` bounds loading rounds (zero selects 32).
Exhaustion or TPE validation failure returns `KindSlicing`, never a partial slice.
The caller's context controls admission and result acceptance.
`WithMaxSourceBytes` caps the encoded input at 64 MiB by default.
Responses have a 16 MiB default cap.
The runtime bounds simultaneous calls through `WithMaxConcurrentCalls`.
Each operation closes its native state after execution returns.
Native allocations have no hard per-instance or aggregate heap cap.

## Strict validation

```go
result, err := rt.Validation().Validate(ctx, schema, policies)
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
the validation result. Cancellation rejects the result after native validation returns.

`validation.Client.ValidateWithLevel(ctx, schema, policies, maxDereferenceLevel)` first runs
strict validation. If that passes, Cedar checks the maximum entity dereference
depth. An entity dereference reads an entity's attributes or hierarchy. Level
zero permits no entity dereferences. A longer chain requires a higher level:
`principal.photo.owner.admin` requires level three.

`Validate` applies no depth limit. `ValidateWithLevel` accepts every `uint32`
level and uses Cedar 4.13.0's stable level validation API. Experimental upstream
permissive and partial validation modes remain outside this API. Both methods
return the same diagnostics and use the same context and resource limits.

## Full policy and template shape

`ParsedPolicy.JSON`, `TemplateInfo.JSON`, and `ParsedPolicySet.JSON` expose the full ordinary JSON EST shape.
They cover templates, links, slots, annotations, scope constraints, conditions, and expressions.
The [PST mapping](pst-mapping.md) lists each native form and its JSON representation.
Use full-set JSON to preserve policy IDs and template links.
The versioned residual projection uses the same per-policy expression mapping.

## Structured residual export

`PartialResponse.Projection()` exposes versioned native PST through Cedar's JSON EST mapping.
Policies retain their original IDs, effects, annotations, and complete expression trees.
`{"error":[]}` preserves a nested residual error expression.
Display text is an inspection aid and is not a faithful residual serialization.

`PartialResponse.Export()` captures the frozen partial input and native projection.
`partial.Client.ImportPartialResponse()` verifies both versions and the complete projection against native evaluation.
It rebuilds the matching native PST with the loaded schema and policies.
Reauthorization checks consistency with known data before it evaluates the imported residual policies.
See [partial evaluation](partial-evaluation.md) for the continuation rules.

## Schema operations

`SchemaFragmentFromCedar` and `SchemaFragmentFromJSON` retain fragment source.
Fragments can reference declarations from other fragments.
`schema.Client.ConvertSchemaFragment` calls native `SchemaFragment` conversion for either output format.
Conversion parses syntax but does not require external declarations to exist.
It preserves declarations and annotations, but does not preserve comments or formatting.

`schema.Client.ComposeSchema` calls native `Schema::from_schema_fragments` before it combines declaration maps.
Cedar resolves references after it collects all fragments.
Undefined references, duplicate declarations, action hierarchy cycles, and common type cycles return `KindSchema`.
Recursive entity type hierarchies follow native Cedar rules.
The result is a normalized JSON `Schema` for validation, authorization, or inspection.
Namespace annotations with the same key use the last fragment's value.

`schema.Client.InspectSchema` returns two native schema projections.
`ResolvedSchema` retains common type declarations and classifies qualified references as entity types or common types.
`ExpandedSchema` inlines common types in entity attributes and action contexts.
The expanded projection omits annotations and common type declarations.
It contains transitive hierarchy relationships.
`Ancestors`, `Actions`, `ActionGroups`, and `Environments` provide sorted metadata.
Request environments describe schema applicability and do not grant access.

`schema.Client.ActionEntities` returns Cedar's action entities, including their transitive parent relationships.
Use the returned `Entities` with an authorizer or serialize it with `json.Marshal`.
All schema operations enforce the runtime's input, response, and cancellation limits.
Invalid UTF-8 returns `KindInput` before module execution.

## Entity literals

`literal.Client.EntityLiterals` lists sorted literal occurrences by policy and template
ID. The method delegates inspection to Cedar's native syntax tree. Slot bindings
are available through `template.Client.TemplateLinks`.

Use `rt.PolicyLiterals()` and import `cedar/policy/literal` for this client and its records.

`literal.Client.SubstituteEntityLiterals` accepts a map from original UIDs to replacement
UIDs. Cedar applies the map simultaneously. With `A → B` and `B → C`, the
original `A` becomes `B`. String literals that contain entity-like text stay
unchanged. Policy IDs, template IDs, annotations, slots, and link IDs retain their
identities. Link bindings also receive one simultaneous lookup.

Static policies use `Policy::sub_entity_literals`. Templates use the same native
EST transformation, followed by `Template::from_json`. Cedar 4.13.0 has no
separate public template substitution method. Reparse and authorization tests
check the transformed template and its links.

The result uses semantic Cedar JSON. Comments and source spacing are not part
of this representation. Run `Validate` if replacements can change schema
validity. Source, response, and caller-context limits apply.

## Source tokens and comment preservation

`source.Client.TokenizePolicies(ctx, text)` uses the pinned Cedar formatter lexer.
It returns `SourceTokens` containing native tokens, comment summaries, and UTF-8 byte spans.
`TokenSpan.Start` is the first byte offset.
`TokenSpan.End` is the byte offset immediately after the token.
Each token's `Text` exactly matches that source range.
The decoder checks required fields, UTF-8, ordered spans, source bounds, and source-text equality.
The pinned native formatter owns spelling, keyword, trivia, and comment-attachment rules.
Fabricated native token streams receive no second semantic lexer check in Go.

`SourceToken.Kind` is `identifier`, `number`, or `string` for those token variants.
For other variants, the kind is the native token spelling, such as `permit`, `?principal`, or `==`.
Whitespace and comments are not separate tokens.
`LeadingComments`, `TrailingComment`, and final `TrailingComments` use the formatter's trimmed comment summaries.
These summaries omit original indentation and trailing spaces.

Keep the original source to preserve every byte of comments, line endings, and spacing.
The ranges between tokens contain those original bytes.
Apply an edit to one token range, then lex the changed source again.
Old spans belong to the previous source snapshot.

```go
stream, err := rt.Source().TokenizePolicies(ctx, source)
if err != nil {
    return err
}
for _, token := range stream.Tokens {
    if token.Kind == "string" && token.Text == `"old"` {
        source = source[:token.Span.Start] + `"new"` + source[token.Span.End:]
        break
    }
}
parsed, err := rt.Policies().ParsePolicySet(ctx, policy.PoliciesFromCedar(source))
```

Lexing does not validate policy grammar or policy semantics.
An incomplete source such as `permit(` can produce tokens.
An invalid lexical character returns `KindPolicies` and no token stream.
Use `ParsePolicySet` and schema-based `Validate` for the existing semantic checks.

Source spans support comment-preserving editor operations; they do not replace the semantic JSON path.
Parsed policy JSON remains the semantic authority for identity, templates, links, and authorization.
JSON-based edits do not retain original comments or spacing.
After a source edit, reparse it before you use the resulting policy JSON.
Runtime source, response, and caller context limits apply.

## Context, request, and name utilities

Context operations use native Cedar parsing and require a `Runtime`.
`Context.Values(ctx, rt.Utilities())` returns every attribute as an `EvalRecord`.
`Context.Get(ctx, rt.Utilities(), key)` returns a value, a presence flag, and an error.
A missing attribute returns `nil`, `false`, and no error.
Readback preserves exact signed 64-bit integers, entity identities, nested values, and extension values.

`Context.Merge(ctx, rt.Utilities(), other)` returns a new context containing both records.
The operation rejects every overlapping top-level key, including keys with equal values.
It performs no recursive merge and preserves both inputs.
An empty context acts as the merge identity.
The returned context uses native Cedar JSON value encoding.

```go
base := request.NewContext(value.Record{"count": value.Long(1)})
extra := request.NewContext(value.Record{"enabled": value.Bool(true)})
merged, err := base.Merge(ctx, rt.Utilities(), extra)
if err != nil {
    return err
}
count, found, err := merged.Get(ctx, rt.Utilities(), "count")
```

`Context.Validate(ctx, rt.Utilities(), schema, action)` checks an existing context against the action's schema.
It parses without schema inference, then invokes native context validation.
Use explicit `__entity` and `__extn` encodings when you supply raw context JSON.
`utility.Client.ValidateScopeVariables` checks principal, action, and resource independently of context.
Both checks already occur when authorization constructs a schema-validated request.
These methods let callers check each part before authorization.
Context failures return `KindContext`; scope failures return `KindRequest`.

`utility.Client.ConfusableStrings(ctx, policies)` returns warnings without requiring a schema.
It checks static policies and templates for native Cedar confusable-string warnings.
Warnings retain raw policy IDs, native categories, and warning severity.
Cedar policy inputs include native source spans. JSON policy inputs omit spans from temporary parser sources.
Linked policies share their template's source and do not duplicate its warnings.
`validation.Client.Validate` already includes these checks with its schema-based policy validation.
These warnings describe confusing text; they do not grant or deny access.

`utility.Client.ParseEntityUID(ctx, text)` parses Cedar's normalized UID syntax.
`EntityUID.CedarText(ctx, rt.Utilities())` renders that syntax with native Cedar escapes.
Use `CedarText` for text that you must parse again.
`EntityUID.String` remains a Go-quoted log representation; some escapes differ from Cedar.
Invalid UID text or types return `KindEntityUID`.
Invalid UTF-8 returns `KindInput` before native execution.

`utility.Client.LanguageVersion(ctx)` returns the native Cedar language version, currently `4.5.0`.
The language version differs from the pinned Cedar SDK version, `4.13.0`.
Runtime source, response, and caller context limits apply to every utility operation.

## Standalone expressions

`expression.Client.ParseExpression` parses a Cedar expression. `ParseRestrictedExpression`
accepts literals, sets, records, and extension constructors. Convert its result
with `RestrictedExpression.Expression()` before evaluation.

`expression.Client.EvalExpression` evaluates a parsed expression with an `ExpressionEnv`.
The environment supplies principal, action, resource, context, and entities.
Nil entity UIDs mean unknown variables. Unknown or invalid evaluation results
return `KindExpression` and no value. A zero expression returns `KindInput`.

```go
expr, err := rt.Expressions().ParseExpression(ctx, "principal.age + 1")
if err != nil {
    return err
}
evaluated, err := rt.Expressions().EvalExpression(ctx, expr, expression.ExpressionEnv{
    Principal: &principal,
    Entities: entities,
})
if err != nil {
    return err
}
age := int64(evaluated.(value.Long))
```

`EvalResult` has seven variants: `Bool`, `Long`, `String`, `EntityRef`, `EvalSet`,
`EvalRecord`, and `ExtensionValue`. `Long` preserves the full signed 64-bit range.
Sets remove duplicates. Records retain attribute names and typed nested results.
`ExtensionValue` preserves upstream's canonical restricted-expression string,
such as `decimal("1.25")`. It does not convert extension values to numbers.

Expression evaluation does not validate policies or grant authorization. Use
`Authorize` for decisions. Evaluation uses a fresh instance, the runtime's source
and response limits, and the caller's context deadline.

## Policy formatting

`format.Client.FormatPolicies` is experimental and may change before v1. It invokes
`cedar-policy-formatter` 4.13.0 in a fresh native state, separately from loaded
authorizers. It accepts UTF-8 Cedar text, including templates, annotations, and
comments; it does not convert Cedar to JSON or validate policies against a schema.

```go
formatted, err := rt.Formatter().FormatPolicies(ctx,
    `permit(principal,action,resource)when{context.mfa};`)
if err != nil {
    return err
}
fmt.Print(formatted)
```

Before:

```cedar
permit(principal,action,resource)when{context.mfa};
```

After:

```cedar
permit (principal, action, resource)
when { context.mfa };
```

The [executable example](../cedar/policy/format/format_test.go) checks this output.
Formatting follows the pinned upstream version, including its trailing newline,
comment placement, and blank lines between policies. An empty source formats to
one newline. Formatting is idempotent for the tested inputs; native fixtures
compare full policy/template JSON and authorization results before and after.

| Format option | Default | Contract |
|---|---|---|
| `WithFormatLineWidth(uint32)` | 80 | Upstream target width; zero is supported. Long tokens/comments may exceed it. |
| `WithFormatIndentWidth(int32)` | 2 | Upstream indentation per nesting level, including zero and negative values. |
| `WithFormatMaxOutputBytes(int)` | 16 MiB | UTF-8 result cap; must be positive and at most `DefaultMaxResponseBytes`. |

Line width controls layout and does not cap allocation.
The formatter rejects positive indentation widths above its output cap.
It rejects token nesting deeper than 256 before invoking the recursive formatter.
These guards return `KindLimit`.
`WithMaxSourceBytes` limits the encoded input envelope.
The response cap also applies to JSON-encoded output and diagnostics.
JSON escaping can reach that cap before the raw output cap.

The runtime bounds simultaneous formatting calls.
Cancellation rejects the result when native execution returns.
A recovered Rust panic returns `KindFault` and invalidates that state.
A fatal native fault can terminate the process.
No partial formatted text is returned on an error.

Invalid UTF-8 is `KindInput`, rejected before JSON could replace bytes. Invalid
Cedar is `KindPolicies`, with upstream error/help text and source labels rendered
as zero-based, half-open UTF-8 byte spans. Input/raw-output limit failures return
`KindLimit`; an oversized encoded response is `KindFault`, matching the shared
native boundary. A formatter failure on otherwise valid Cedar is also `KindFault`.

## Errors

Use `errors.As` to inspect `*diagnostic.Error` and its `Kind`, and `errors.Is` to
check `diagnostic.ErrFault`, `context.DeadlineExceeded`, or `context.Canceled`.

| Error kind | Meaning |
|---|---|
| `KindSchema`, `KindPolicies` | Source parsing or policy/template operation failed |
| `KindEntities`, `KindContext`, `KindRequest` | Data parsing or schema checks failed |
| `KindPrincipal`, `KindAction`, `KindResource` | A UID failed to parse |
| `KindInput` | Request envelope or Go value encoding failed |
| `KindSlicing` | TPE validation or entity-loading iteration limit failed |
| `KindBatched` | Native TPE validation or batched-authorization failure |
| `KindLoader` | Host entity-loader error or panic |
| `KindLimit` | Input or formatted output exceeded its configured size limit |
| `KindFault` | Recovered panic, canceled result, or broken native protocol |

The [failure behavior](security.md#cancellation-and-faults) explains when an
instance is reused or discarded. Callers should treat any returned error
as a failed authorization operation, including pool and context errors
that are not `*diagnostic.Error`.

## Configuration reference

| Runtime option | Purpose |
|---|---|
| `WithMaxSourceBytes(bytes)` | Encoded operation input cap; default 64 MiB |
| `WithMaxResponseBytes(bytes)` | Encoded response cap; default 16 MiB |
| `WithMaxConcurrentCalls(count)` | Shared active native call cap; default 8 |

| `authorization.Config.Limits` field | Purpose |
|---|---|
| `MaxInstances` | Pooled native state cap; default 8 |
| `CallTimeout` | Result deadline after pool acquisition; default one second |
| `LoadTimeout` | State creation and load deadline; default 30 seconds |
| `MaxRequestBytes` | Encoded request cap; default 1 MiB |

Zero-valued supported limit fields select defaults.
A negative `CallTimeout` disables its deadline.
The caller context also controls pool admission.
Deadlines cannot interrupt native computation without cooperative callbacks.
`Stats()` retains `Created`, `Discarded`, and `Idle` counts.
The native artifact manifest identifies Cedar, SymCC, ABI, compiler, target, and source commit.
`ModuleSHA256()` is removed.
The v0.3.0 interface removes the previously rejected Wasm options and `RecycleMemoryBytes`.
See the [native contract](migration/native-contract.md) and [release maintenance](maintenance.md).

## Supported operations

The Go interface exposes authorization, strict validation, parsed policy
inspection and static policy edits, template management, experimental partial
evaluation, on-demand entity loading, request-specific entity slicing, policy
formatting, and the policy comparisons in `analysis`. These execute Cedar's Rust
implementation, including its core and extension value types.

Conformance establishes agreement for the tested cases, not complete public-API
parity. Deprecated entity manifests remain unsupported; request-specific slicing
uses TPE. See
[verification scope](verification.md) for the evidence behind compatibility
claims.

## Experimental on-demand entity loading

`batched.Client.AuthorizeBatched(ctx, request, loader, options)` calls Cedar 4.13.0's
experimental `PolicySet::is_authorized_batched`. This authorizes **one request**
using Rust type-aware partial evaluation to discover entity UIDs as needed. It
returns `(Decision, error)`, with `Deny` on every error. Rust returns no policy
reasons or residual result from this operation. A schema and policies that pass
upstream strict validation are required. Experimental APIs may change with the
pinned Cedar version.

```go
loader := batched.EntityLoaderFunc(func(ctx context.Context, uids []uid.EntityUID) (batched.EntityLoadResult, error) {
    // Query your store using ctx. Each returned entity includes all ancestor UIDs.
    entities, missing, err := store.Load(ctx, uids)
    return batched.EntityLoadResult{Entities: entities, Missing: missing}, err
})
decision, err := authorizer.Batched().AuthorizeBatched(ctx, request, loader,
    batched.BatchedOptions{MaxIterations: 8})
```

`EntityLoadResult.Entities` is a Cedar JSON entity array (`json.RawMessage`). Use
`json.Marshal(entity.NewEntities(...))` for typed data. Raw JSON lets the bridge
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
returns. The bridge copies encoded results into native library-owned memory. A loader
must not recursively call or close the same authorizer: the call holds a pooled
instance, and waiting on that pool can deadlock.

The request envelope uses `Limits.MaxRequestBytes`. `MaxBatchBytes` defaults to
1 MiB and caps each encoded UID request and result, with a 64 MiB maximum.
`MaxLoaderBytes` defaults to 16 MiB and caps their cumulative bytes across the
call. Raw callback JSON must also fit the remaining budgets before encoding;
JSON envelope and escaping bytes count. Request, response, concurrency, and load limits remain in force. `Limits.CallTimeout` includes native library
execution and callbacks; the caller context also bounds waiting for an instance.
Callbacks must honor their context. Go cannot interrupt a callback that blocks
or bound allocations made by application callback code, so loaders remain trusted
host code. No detached callback goroutines are created.

Callback errors use `KindLoader`, preserve their cause for `errors.Is`, and discard
the native library. Callback panics become `KindLoader` without exposing the panic value.
Host byte limits use `KindLimit`; context cancellation/timeouts use `KindFault`
with the context cause. Invalid entity data uses `KindEntities`. Rust TPE and
iteration failures use `KindBatched`. See the executable
`Example_authorizeBatched` and the native parity fixtures in
`testdata/parity/batched`.

## Parsed policies and static policy edits

The existing `PoliciesFromCedar` and `PoliciesFromJSON` constructors still defer
parsing. Use `policy.Client.ParsePolicySet` for immediate parsing and an immutable
`ParsedPolicySet`, or `policy.Client.ParsePolicy(ctx, id, cedarText)` for one static
policy with an explicit ID. `policy.Client.PolicyFromJSON` accepts one policy's Cedar
JSON and an explicit ID. Even the empty ID is preserved; `@id` is an annotation,
not an instruction to set the policy ID.

A `ParsedPolicy` exposes its ID, permit/forbid effect, annotations, condition presence,
and template identity. Inspect head constraints through its Cedar JSON body.
`Policy(id)` looks up an ID without parsing again;
`Policies()` lists static and linked policies in ID order, excluding templates.
Snapshots are independent of the runtime's lifetime and safe to share. Returned
maps and byte slices are copies. The zero `ParsedPolicySet`
is empty; the zero `ParsedPolicy` is invalid.

`policy.Client.AddPolicy`, `RemovePolicy`, and `MergePolicySets` accept source-based
`PolicySet` values and return new parsed snapshots. Feed their `Source()` into
`NewAuthorizer`, `Validate`, template operations, or another edit. Rust performs
all parsing and set operations. Addition rejects duplicate IDs. Removal accepts
only static IDs; missing IDs, template IDs and linked policy IDs produce Rust's
`remove_static` error. Merge follows Rust's equality/conflict handling and can
rename conflicts, returning its old-to-new ID map. Failed edits leave the inputs
unchanged. For replacement, remove the old static ID then add its replacement;
keep the original snapshot until both operations succeed.

```go
parsedPolicy, err := rt.Policies().ParsePolicy(ctx, "read-photos",
    `@owner("photos") permit(principal, action == Action::"view", resource is Photo);`)
if err != nil { return err }
set, err := rt.Policies().AddPolicy(ctx, policy.PoliciesFromCedar(""), parsedPolicy)
if err != nil { return err }
// This source preserves "read-photos" in authorization and validation diagnostics.
source := set.Source()
```

Use Cedar's documented JSON policy representation for editing and construction.
`JSON()` returns an owned copy. Pass the changed body and explicit ID to `PolicyFromJSON`.
Keep expression integers exact. Use `json.RawMessage` or `json.Decoder.UseNumber()` when editing untyped nodes.
Rust validates the body through pinned upstream Cedar APIs.
This format is not direct serialization of the upstream Programmatic Syntax Tree (PST).
The v0.3.0 interface removes `PolicySyntax`, `Syntax()`, `PolicyFromSyntax`, and typed head-constraint records and getters.
A parsed policy can fail schema validation. If schema correctness is required, call `Validate` before use.
See the [JSON mapping](pst-mapping.md) and [consumer editing example](migration/consumer.md#lesson-8-edit-cedar-json-policies).

Persistence and display have different contracts:

| Conversion | IDs and template links |
| --- | --- |
| `ParsedPolicySet.JSON()` / `Source()` | Preserve IDs, templates, and links; use for persistence |
| `ParsedPolicy.JSON()` | One policy body only; ID must be supplied on reparse; linked bodies are materialized without link metadata |
| `Cedar()` on a policy or set | Omits IDs; reparsing a set assigns `policy0`, `policy1`, etc.; rejects linked policies to avoid silently discarding their representation |

Set Cedar output sorts static policies by ID, followed by templates by ID.
Cedar rendering is not a formatter and does not promise comment, whitespace,
annotation spelling, or source order preservation. PST normalizes empty and
valueless annotations. Use template operations for editing linked policies.

All policy operations use a fresh native state.
They apply source, response, and shared concurrency limits.
Cancellation rejects the result after native execution returns. They have no implicit timeout: use a context deadline
for untrusted input. Large snapshots repeat policy information, so response limits
can be reached before source limits. Parse/edit failures return `*Error` with
`KindPolicies`; malformed operation/syntax envelopes may return `KindInput`.
New policy operation inputs must contain valid UTF-8; malformed bytes are rejected
before Go JSON encoding could replace them and change an ID.
Recovered panics and rejected canceled results return faults; canceled operations
do not invalidate other snapshots or the runtime.

See the executable `Example_parsePolicy` and
`Example_policyFromJSON` examples in `cedar/policy/policies_example_test.go`.

## Partial evaluation (experimental)

`partial.Client.PartialAuthorize` uses Cedar 4.13.0 TPE with explicit unknown inputs
and a separate `PartialDecision` (`Undecided`, `PartialDeny`, `PartialAllow`).
Import `cedar/authorization/partial/input` for partial request and entity records.
Inspect `PartialResponse.Residuals`, then supply consistent concrete data with
`PartialResponse.Reauthorize`. A schema is required. See
[partial evaluation](partial-evaluation.md) for supported unknowns, limits,
upstream experimental status, and the executable example.

### Policy applicability

`applicability.Client.ApplicableEnvironments` invokes Cedar's native `get_valid_request_envs` operation.
It returns schema principal types, action UIDs, resource types, and template slot types.
`PolicyApplicability` separates policy IDs and template IDs.
Policy and template IDs preserve their source values, including empty IDs, control characters, and Unicode.
Linked policy IDs also preserve their source values.
Native enumeration also retains slot type metadata for linked policies.
Environment lists retain native Cedar enumeration order.
JSON serialization preserves flat action UID fields, including its type and ID.

The result describes potential applicability. It does not grant access or provide a satisfying request.
Use `Authorize` to decide access for a concrete request.
An empty schema or an inapplicable policy produces an empty environment list.
Malformed schemas and policies return their existing error kinds.
Source, response, and context limits apply.

### Structured diagnostics

`ValidationResult.Errors` and `ValidationResult.Warnings` include native diagnostic categories, severity, and source spans.
`ValidationResult.SchemaWarnings` returns Cedar schema syntax warnings.
`schema.Client.SchemaWarnings` returns the same warnings without policy validation.
JSON schemas produce no Cedar syntax warnings.

`SourceSpan.Offset` and `SourceSpan.Length` count UTF-8 bytes in the original source.
Use the policy source for policy spans. Use the schema source for schema spans.
Some native diagnostics have no span. JSON policy inputs have no source spans.
Native JSON policy offsets can refer to temporary parser sources. The bridge omits these offsets.
For Cedar inputs, the bridge retains every native label span and omits label text.

Categories use stable names for native variants, such as `unexpected_type`, `invalid_action_application`, and `shadows_builtin`.
A future unknown native variant uses an `unknown_` category.
Cedar 4.13.0 reports `invalid_action_application` as a warning. This warning does not fail validation.
Cedar can choose spelling suggestions through hash iteration. Rendered suggestions can differ across runs.
Categories and spans do not use these suggestions.
Diagnostic policy IDs retain their original bytes. Rendered messages can escape control characters in these IDs.

`PolicyMessage` now contains a span slice. Compare messages with `reflect.DeepEqual` instead of Go equality.
Authorization evaluation messages retain their existing policy ID and text fields.

### Permission queries

Permission queries use Cedar's experimental type-aware partial evaluation API.
Create an authorizer with a schema before you call these methods.
The authorizer's request, response, and time limits apply.
Use `a.Queries()` and import `cedar/authorization/partial/query` for request and result records.

`query.Client.QueryResources` selects allowed resources of one type from the native entity store.
Supply a concrete principal, action, and context.
`query.Client.QueryPrincipals` selects allowed principals of one type from the native entity store.
Supply a concrete action, resource, and context.
Per-query `Entities` augments the loaded store through Cedar's existing conflict checks.
Both methods return only candidates that native Cedar permits.

`query.Client.QueryActions` enumerates applicable actions through the schema in Rust.
Principal and resource types must be known. Their IDs can be unknown.
A nil context is wholly unknown. A pointer to `Context{}` is known empty.
The method returns separate `Allowed` and `Undecided` lists.
`ActionQueryResult` JSON uses flat UID objects and preserves both lists during decoding.
It excludes definite denial and requests that fail per-action schema validation.
An undecided action does not prove that a satisfying completion exists.
Use ordinary authorization for a concrete request before granting access.
