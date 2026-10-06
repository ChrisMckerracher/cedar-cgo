# Cedar PST mapping for Go policy tools

This document maps Cedar 4.13.0 PST forms to the JSON EST exposed by this package.
PST means Programmatic Syntax Tree.
EST means External Syntax Tree.
Both represent policy syntax.
Rust parses and evaluates the trees.
Go retains the JSON expression nodes as `json.RawMessage`.

Use `ParsedPolicy.JSON()` for one policy.
Use `TemplateInfo.JSON` for one template.
Use `ParsedPolicySet.JSON()` to retain the full set, including IDs and template links.
Use `ResidualProjection` version 1 for type-aware partial evaluation residuals.
The residual wrapper uses the same per-policy EST mapping described here.
It records the Cedar version because these native types can change between releases.

## Policies, templates, and links

| PST form | EST mapping |
|---|---|
| `PolicySet.policies` | `staticPolicies`, keyed by policy ID |
| `PolicySet.templates` | `templates`, keyed by template ID |
| `PolicySet.template_links` | `templateLinks`, with `templateId`, `newId`, and `values` |
| `Template.effect` | `effect`: `permit` or `forbid` |
| `Template.annotations` | `annotations`, keyed by annotation name |
| `Template.principal`, `.action`, `.resource` | Corresponding scope object |
| `Template.clauses` | Ordered `conditions` array |
| `Clause::When(expr)` | `{"kind":"when","body":expr}` |
| `Clause::Unless(expr)` | `{"kind":"unless","body":expr}` |
| `StaticPolicy` | Template body with no slots |
| `LinkedPolicy` | Template ID, link ID, and slot values in the full policy set |

Individual policy and template JSON objects do not contain IDs.
Their containing maps store IDs.
A linked policy's individual JSON contains its instantiated body.
That body alone does not retain the template link.
Persist the full policy set to retain the link.
Each slot value in `templateLinks.values` uses `{"__entity":uid}`.
The `uid` object contains `type` and `id` fields.
Annotation keys and values retain their native semantics.
An empty annotation can normalize to a null annotation value.

## Scope constraints

| PST constraint | EST scope object |
|---|---|
| `Any` | `{"op":"All"}` |
| `Eq(Entity(uid))` | `{"op":"==","entity":uid}` |
| `Eq(Slot(slot))` | `{"op":"==","slot":slot}` |
| `In(Entity(uid))` | `{"op":"in","entity":uid}` |
| `In(Slot(slot))` | `{"op":"in","slot":slot}` |
| `Is(type)` | `{"op":"is","entity_type":type}` |
| `IsIn(type, Entity(uid))` | `{"op":"is","entity_type":type,"in":{"entity":uid}}` |
| `IsIn(type, Slot(slot))` | `{"op":"is","entity_type":type,"in":{"slot":slot}}` |
| Action `In(uids)` | `{"op":"in","entities":[uids...]}` |

An entity UID is `{"type":"Namespace::Type","id":"identifier"}`.
A slot is `"?principal"` or `"?resource"`.
Action scopes do not support slots or `is` constraints.
An empty action set remains an empty set.

## Expressions

Each expression object has one operator key.
The operator value contains its arguments.
Names, strings, and attribute keys use JSON strings.
Integer literals retain signed 64-bit values.
If Go decodes expressions into generic maps, use `json.Decoder.UseNumber()`.
A floating-point decoder can change integers greater than 2⁵³.

| PST expression | EST expression |
|---|---|
| `Literal` | `{"Value":value}`; entity values use `{"__entity":uid}` |
| `Var` | `{"Var":"principal"}`, `action`, `resource`, or `context` |
| `Slot` | `{"Slot":"?principal"}` or `?resource` |
| `UnaryOp::Not` | `{"!":{"arg":expr}}` |
| `UnaryOp::Neg` | `{"neg":{"arg":expr}}` |
| `UnaryOp::IsEmpty` | `{"isEmpty":{"arg":expr}}` |
| Built-in `BinaryOp` | `{"operator":{"left":expr,"right":expr}}` |
| Extension unary operator | `{"function":[expr]}` |
| Extension binary operator | `{"function":[left,right]}` |
| `GetAttr` | `{".":{"left":expr,"attr":"name"}}` |
| `HasAttr` | `{"has":{"left":expr,"attr":"name"}}`; nested paths use an `attr` array |
| `Like` | `{"like":{"left":expr,"pattern":[elements...]}}` |
| `Is` | `{"is":{"left":expr,"entity_type":"Type"}}`; optional `in` contains its expression |
| `IfThenElse` | `{"if-then-else":{"if":expr,"then":expr,"else":expr}}` |
| `Set` | `{"Set":[expressions...]}` |
| `Record` | `{"Record":{"key":expr,...}}` |
| `Unknown` | `{"unknown":[{"Value":"name"}]}` |
| `ResidualError` | `{"error":[]}` |

Built-in binary operator keys are `==`, `!=`, `<`, `<=`, `>`, `>=`, `&&`, `||`, `+`, `-`, and `*`.
They also include `in`, `contains`, `containsAll`, `containsAny`, `getTag`, and `hasTag`.
Extension constructors use `decimal`, `ip`, `datetime`, and `duration`.
Extension methods use their Cedar names.
For a method, the receiver is the first argument.
For example, `ip.isInRange(range)` maps to `{"isInRange":[ip,range]}`.
The same rule covers decimal comparison, IP tests, date conversion, offsets, and duration operations.

A `Like` pattern uses `"Wildcard"` for `*`.
Literal characters use `{"Literal":"text"}`.
Cedar can group adjacent literal characters in the EST.
The PST stores each literal character separately.
Both forms retain the same pattern semantics.

The build enables decimal, IP, datetime, and TPE forms.
It does not enable variadic IP methods or tolerant parser error nodes.
Those feature-specific forms are outside this build's mapping.

## Residual expressions

`ResidualError` can occur inside an unresolved expression.
Its presence does not prove that the whole policy errors.
Native short-circuit evaluation can skip that expression.
Ordinary Cedar display text cannot faithfully serialize it.
Use the versioned residual export and native import APIs.
They require complete projection equality with native partial evaluation replay.
They then reconstruct the replayed native PST, including residual error nodes.
The version 1 wrapper retains this shared EST mapping.

Cedar exports `Unknown` through the EST `unknown` function form.
Cedar 4.13.0's EST-to-PST conversion does not import that form.
Ordinary policy parsing does not accept it as an extension function.
This is an inspection mapping, not an ordinary policy construction path.
TPE request variables do not require PST `Unknown` nodes.

## Verification

`testdata/parity/pst` contains fixtures from direct native Cedar APIs.
The oracle compares ordinary policy and template EST with native PST bodies.
It also verifies full-set PST conversion with native authorization.
Fixtures cover scopes, slots, links, annotations, every main expression form, extensions, and exact integers.
Special expression fixtures record `Unknown`, `ResidualError`, and expression slots.
They check native expression conversion, including forms that ordinary policy parsing rejects.
The residual import tests verify projection equality and native PST reconstruction before replay.
Run `python3 scripts/parity/run.py pst --check` to check the committed fixtures.
