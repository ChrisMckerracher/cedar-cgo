# Change analysis

[Documentation](README.md) · [API](api.md) · [Performance](performance.md#change-analysis)

## Contents

- [Setup](#setup)
- [Compare policies](#compare-policies)
- [Interpret results](#interpret-results)
- [Configure the analyzer](#configure-the-analyzer)
- [Implementation](#implementation)

## Setup

Package `analysis` compares policy sets with Cedar's symbolic compiler,
SymCC. It turns a question into SMT-LIB queries, which the Go host sends to
an external solver.

Use the **cvc5 1.3.1** executable from the
[official release](https://github.com/cvc5/cvc5/releases/tag/cvc5-1.3.1),
the version used by this repository's CI. Pass its path to `solver.CVC5`.
Analysis and authorization use the same linked native library with separate state handles.

```go
analyzer, err := analysis.New(ctx, solver.CVC5("/path/to/cvc5"))
if err != nil {
	return err
}
defer analyzer.Close(ctx)
```

Applications distributing cvc5 should account for its dependencies' licenses;
the default cvc5 build links LGPL-3.0 GMP.

## Compare policies

`NewlyPermitted` finds requests that a policy change would newly allow:

```go
report, err := analyzer.NewlyPermitted(ctx, schema, before, after)
if err != nil {
	return err
}
for _, result := range report.Results {
	if !result.Holds {
		fmt.Println(result.Action, result.Counterexample.Text)
	}
}
```

`Equivalent(ctx, schema, first, second)` checks whether two policy sets
make the same decision for every request described by the schema.

All operations require a schema and strictly valid static policies.
Call `validation.Client.Validate` to establish full-schema validity before analysis.
Native compilation checks strict types only in the analyzed request environments.
See the [complete example](../analysis/example_test.go).

## Check errors and matching

Use matching queries when permit and forbid conditions matter independently of the final decision.
Pass a policy set with exactly one policy to each singleton argument.
Templates are rejected.

| Method | Property |
| --- | --- |
| `NeverErrors(ctx, schema, policy)` | The policy never produces an evaluation error |
| `AlwaysMatches(ctx, schema, policy)` | The policy matches every schema-valid request |
| `NeverMatches(ctx, schema, policy)` | The policy matches no schema-valid requests |
| `MatchesEquivalent(ctx, schema, first, second)` | Both policies match the same requests |
| `MatchesImplies(ctx, schema, first, second)` | A match for the first policy implies a match for the second |
| `MatchesDisjoint(ctx, schema, first, second)` | No request matches both policies |
| `Disjoint(ctx, schema, first, second)` | No request is allowed by both policy sets |

`Disjoint` accepts complete policy sets.
Matching queries use the original permit or forbid effects.
For example, two forbid policies can deny every request and still match different requests.
An evaluation error also differs from an ordinary nonmatch.
`NeverErrors` checks native symbolic error behavior directly.

Every method returns the same `Report` structure.
Matching and error counterexamples also contain `FirstEvaluation` and, for pairwise queries, `SecondEvaluation`.
Each `PolicyEvaluation` contains a `Matched` flag and native policy evaluation errors.
The concrete authorizer confirms these observations before the result crosses the Go boundary.

```go
report, err := analyzer.NeverErrors(ctx, schema, policy)
if err != nil {
    return err
}
for _, result := range report.Results {
    if result.Counterexample != nil {
        fmt.Println(result.Counterexample.FirstEvaluation.Errors)
    }
}
```

To check always-allow behavior, compare a policy set with an unconditional permit using `Equivalent`.
To check always-deny behavior, compare it with an empty policy set.

## Interpret results

A `Report` contains one `Result` per request environment: a principal type,
action, and resource type allowed by the schema.

| Field or method | Meaning |
|---|---|
| `Report.Holds()` | The property holds in every returned environment |
| `Result.Holds` | The property holds in this environment |
| `Result.Counterexample` | A concrete request demonstrating a failed property |
| `Counterexample.Request` | Request, context, and entities for reproduction |
| `Counterexample.Text` | Human-readable Cedar description |
| `Counterexample.First`, `Second` | Decisions in the caller's policy-set argument order |
| `Counterexample.FirstEvaluation`, `SecondEvaluation` | Concrete singleton matching and errors for matching or error queries |

For `NewlyPermitted`, **holds means the change permits nothing new**.
A counterexample has `First == request.Deny` and `Second == request.Allow`.
For `Equivalent`, a counterexample has different decisions.
For `Disjoint`, both policy sets allow the counterexample.

Check the Go error before using the report. A zero-value report has no
results, so its `Holds()` method returns true vacuously.

Every counterexample is re-evaluated with Cedar's concrete authorizer inside
the module before being returned. Solver-generated values may be extreme,
such as a `Long` of 2^63−1 or a datetime before 1970. A successful property
result depends on SymCC's encoding and the solver's `unsat` answer; see
[Verification](verification.md#independent-fixtures).

## Reuse compiled policy sets

`Analyzer.OpenCompiled(ctx, schema, selection)` creates a reusable `CompiledSession`.
The constructor context controls the whole session lifetime.
Pass nil to select all schema request environments.
Pass an explicit list to select particular environments.
An empty list selects none.
Duplicate and unknown environments fail.
`Environments()` returns a copy of the native selection.

```go
session, err := analyzer.OpenCompiled(ctx, schema, nil)
if err != nil {
    return err
}
defer session.Close()
first, err := session.Compile(ctx, before)
if err != nil {
    return err
}
second, err := session.Compile(ctx, after)
if err != nil {
    return err
}
report, err := session.Equivalent(ctx, first, second)
if err != nil {
    return err
}
fmt.Println(report.Holds())
```

`Compile` creates native compiled sets once for every selected environment.
With an empty selection, it checks policy syntax and rejects templates, but does not check policy types.
An empty report's `Holds()` result does not establish full-schema policy validity.
The native session retains the original policies for concrete counterexample replay.
`Equivalent`, `Implies`, and `Disjoint` reuse those sets and the same solver transport.
Their `Report` and `Counterexample` types match the stateless API.
`Implies(first, second)` checks whether every request allowed by the first set is also allowed by the second.

Handles belong to one session.
`Release(ctx, handle)` removes a handle's native data.
Foreign, zero, and released handles fail before native execution.
Native handle IDs increase and are never reused within a session.
Each session supports 128 active handles.
The analyzer's source, response, and solver-output limits still apply.

Calls use an exclusive gate.
A canceled caller that waits for the gate leaves the active call and solver unchanged.
The analyzer timeout starts after the caller acquires the gate.
An active cancellation or timeout closes the solver and invalidates the entire session.
A solver failure, native library fault, or malformed response also invalidates it.
Create a new session after these failures.
Ordinary input or compilation errors preserve the session.

`Close` closes solver transport, waits for native execution, and releases session resources.
`Analyzer.Close` also closes its compiled sessions.
Custom solver transports must unblock active reads and writes when `Close` runs.
Stateless calls continue to create their own instances and solver transports.

The [ownership design](compiled-analysis-design.md) records the API scope before implementation.
Raw symbolic terms, custom assertions, and custom symbolic environments remain native internals.
Their upstream contracts need additional validation and concrete replay rules before public exposure.

## Configure the analyzer

`Analyzer` is safe for concurrent use. Each stateless call creates and closes
its own module instance and solver session. A compiled session retains both
resources until the session closes.

| Option | Default |
|---|---|
| `WithTimeout` | 60 s, including solver time |
| `WithMaxSourceBytes` | 64 MiB encoded schema and policies |
| `WithMaxSolverOutput` | 256 MiB read from the solver per call |

`Solver` and `Session` support custom solver integrations. `Command` runs
an executable with explicit arguments and an empty environment. It closes
the process when its session closes or its context expires. The solver remains
a host process; see [Security model](security.md#solver-process).

## Implementation

SymCC 0.7.0 runs in the native Rust library. Explicit state owns compiled sessions.
Go callbacks provide each session's solver transport. No callback persists after its active call.
The vendored pin and existing patch remain checked against the pinned upstream archive.

The native analyzer removes Wasm memory limits and compilation caches.
A deadline closes external solver transport but cannot forcibly stop native CPU work.
Read the [native contract](migration/native-contract.md) and [security model](security.md).
