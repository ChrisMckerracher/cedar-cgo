# Cedar policy analysis for Go developers

[Documentation](README.md) · [API](api.md) · [Performance](performance.md)

## Lesson 1: Configure a solver

Objective: Create an analyzer with a caller-supplied solver.

Package `analysis` compares Cedar policies with SymCC, Cedar's symbolic compiler.
SymCC produces SMT-LIB queries. Go sends these queries to an external solver.

1. Obtain **cvc5 1.3.1** from its [official release](https://github.com/cvc5/cvc5/releases/tag/cvc5-1.3.1).
2. Pass its executable path to `solver.CVC5`.
3. Create the analyzer with `analysis.New`.
4. Close the analyzer when its work ends.

Worked example:

```go
analyzer, err := analysis.New(ctx, solver.CVC5("/path/to/cvc5"))
if err != nil {
    return err
}
defer analyzer.Close(ctx)
```

CI uses this cvc5 version. Its default build links LGPL-3.0 GMP.
If you distribute cvc5, account for its dependency licenses.
Analysis and authorization use the same linked native library. They use separate native state handles.

Knowledge check: Which application supplies and owns the solver executable?

## Lesson 2: Compare policy sets

Objective: Find requests affected by a policy change.

1. Supply a schema and strictly valid static policies.
2. Call `validation.Client.Validate` to establish full-schema validity.
3. Call `NewlyPermitted` or `Equivalent`.
4. Check the error before reading the report.

Worked example:

```go
result, err := analyzer.NewlyPermitted(ctx, schema, before, after)
if err != nil {
    return err
}
for _, environment := range result.Results {
    if !environment.Holds {
        fmt.Println(environment.Action, environment.Counterexample.Text)
    }
}
```

`NewlyPermitted` holds when the change permits nothing new.
Its counterexample has `First == request.Deny` and `Second == request.Allow`.
`Equivalent(ctx, schema, first, second)` checks whether both sets always produce the same decision.
Its counterexample has different decisions.

Native compilation checks strict types only in the analyzed request environments.
See the [complete example](../analysis/example_test.go).

Knowledge check: Does a compiled empty selection establish full-schema validity?

## Lesson 3: Check matching and evaluation errors

Objective: Compare policy matching separately from authorization decisions.

1. Use a singleton policy set for each matching or error query argument.
2. Reject templates before running these queries.
3. Inspect concrete evaluation records when a property fails.

| Method | Property |
| --- | --- |
| `NeverErrors(ctx, schema, policy)` | The policy never produces an evaluation error |
| `AlwaysMatches(ctx, schema, policy)` | The policy matches every schema-valid request |
| `NeverMatches(ctx, schema, policy)` | The policy matches no schema-valid request |
| `MatchesEquivalent(ctx, schema, first, second)` | Both policies match the same requests |
| `MatchesImplies(ctx, schema, first, second)` | Matching the first policy implies matching the second |
| `MatchesDisjoint(ctx, schema, first, second)` | No request matches both policies |
| `Disjoint(ctx, schema, first, second)` | No request is allowed by both policy sets |

`Disjoint` accepts complete policy sets.
Matching queries preserve the original permit or forbid effects.
Two forbid policies can deny every request and still match different requests.
An evaluation error differs from an ordinary nonmatch.
`NeverErrors` checks native symbolic error behavior directly.

Worked example:

```go
result, err := analyzer.NeverErrors(ctx, schema, policy)
if err != nil {
    return err
}
for _, environment := range result.Results {
    if environment.Counterexample != nil {
        fmt.Println(environment.Counterexample.FirstEvaluation.Errors)
    }
}
```

Matching and error counterexamples contain `FirstEvaluation`.
Pairwise queries also contain `SecondEvaluation`.
Each `report.PolicyEvaluation` contains a `Matched` flag and native policy evaluation errors.
The concrete authorizer confirms these observations before Go returns the result.

To check always-allow behavior, compare against an unconditional permit with `Equivalent`.
To check always-deny behavior, compare against an empty policy set.

Knowledge check: Can two policies produce identical decisions but match different requests?

## Lesson 4: Read reports and replay counterexamples

Objective: Interpret result records without losing their qualifications.

All queries return `report.Report` from `analysis/report`.
A report contains one result per schema request environment.
Each environment identifies a principal type, an action, and a resource type.

| Record or method | Meaning |
| --- | --- |
| `report.Report.Holds()` | The property holds in every returned environment |
| `report.Result.Holds` | The property holds in this environment |
| `report.Result.Counterexample` | A concrete request that demonstrates a failed property |
| `report.Counterexample.Request` | Request, context, and entities for reproduction |
| `report.Counterexample.Text` | Cedar text that describes the request |
| `report.Counterexample.First`, `Second` | Decisions in the caller's policy-set argument order |
| `report.Counterexample.FirstEvaluation`, `SecondEvaluation` | Concrete policy matching and evaluation errors |

1. Check the Go error.
2. Read each environment's `Holds` flag.
3. Replay each counterexample with the supplied request records.

For `Disjoint`, both policy sets allow the counterexample.
A zero-value report contains no results. Its `Holds()` method returns true.
This result does not establish full-schema policy validity.

The native module rechecks every counterexample with Cedar's concrete authorizer.
Solver values can include a `Long` of 2^63−1 or a datetime before 1970.
A successful property result depends on SymCC's encoding and the solver's `unsat` answer.
See [Verification](verification.md#independent-fixtures).

Knowledge check: Which decision belongs to the caller's first policy-set argument?

## Lesson 5: Reuse compiled policy sets

Objective: Retain compiled policies while preserving session ownership.

`Analyzer.OpenCompiled(ctx, schema, selection)` returns `compiled.Session` from `analysis/compiled`.
The constructor context controls the complete session lifetime.
Use `compiled.RequestEnvironment` for explicit selections.
A nil selection includes every schema request environment. An empty selection includes none.
Duplicate and unknown environments fail. `Environments()` returns a copy of the native selection.

1. Open the session.
2. Compile each policy set into a `compiled.PolicySet` handle.
3. Reuse those handles for supported queries.
4. Release unneeded handles.
5. Close the session when its work ends.

Worked example:

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
result, err := session.Equivalent(ctx, first, second)
if err != nil {
    return err
}
fmt.Println(result.Holds())
```

`Compile` creates native compiled sets for each selected environment.
An empty selection checks policy syntax and rejects templates. It does not check policy types.
The session retains original policies for concrete counterexample replay.
`Equivalent`, `Implies`, and `Disjoint` reuse compiled sets and one solver transport.
They return the same `report.Report` and `report.Counterexample` records as stateless queries.
`Implies(first, second)` checks whether every request allowed by the first set is allowed by the second.

Handles belong to one session.
`Release(ctx, handle)` removes the handle's native data.
Foreign, zero, and released handles fail before native execution.
Native handle IDs increase. The session never reuses them.
Each session supports 128 active handles. Configured source, response, and solver-output limits still apply.

An exclusive gate serializes calls.
If a queued caller cancels, the active call and solver continue.
The timeout starts after the caller acquires the gate.
Active cancellation or timeout closes the solver and invalidates the session.
Solver failure, a native library fault, or a malformed response also invalidates it.
Create a new session after these failures. Ordinary input and compilation errors preserve the session.
Use `compiled.ErrClosed` with `errors.Is` to identify closed sessions.

`Close` interrupts solver transport, waits for native execution, and releases resources.
`Analyzer.Close` closes its compiled sessions and cancels pending constructors.
Custom solver transports must unblock active reads and writes when `Close` runs.
Stateless calls create their own native instances and solver transports.

The [ownership design](compiled-analysis-design.md) records the interface scope before implementation.
Raw symbolic terms, custom assertions, and custom symbolic environments remain native internals.
Their upstream contracts need additional validation and concrete replay rules before public exposure.

Knowledge check: Can a compiled handle move between sessions?

## Lesson 6: Set limits and understand cancellation

Objective: Configure analysis limits without weakening resource ownership.

`Analyzer` supports concurrent calls. Compiled sessions serialize their own calls.
Package `analysis/options` supplies configuration functions for both.

| Option | Default |
| --- | --- |
| `options.WithTimeout` | 60 seconds, including solver time |
| `options.WithMaxSourceBytes` | 64 MiB of encoded schema and policies |
| `options.WithMaxSolverOutput` | 256 MiB read from the solver per call |

Worked example:

```go
analyzer, err := analysis.New(ctx, solver.CVC5("/path/to/cvc5"),
    options.WithTimeout(30*time.Second))
```

`solver.Solver` and `solver.Session` support custom solver integrations.
`solver.Command` runs an executable with explicit arguments and an empty environment.
It closes the process when its session closes or its context expires.
The solver remains a host process. See the [Security model](security.md#solver-process).

SymCC 0.7.0 runs in the native Rust library.
Native state owns compiled policy data. Go callbacks connect each active call to its solver transport.
No callback persists after its active call.
A deadline closes external solver transport. It cannot forcibly stop native CPU work.
Read the [native contract](migration/native-contract.md) and [security model](security.md).

Knowledge check: Which resources remain owned until active native CPU work returns?
