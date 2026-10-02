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
the version used by this repository's CI. Pass its path to `analysis.CVC5`.
The analyzer and the authorization runtime each embed their own module.

```go
analyzer, err := analysis.New(ctx, analysis.CVC5("/path/to/cvc5"))
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

Both operations require a schema and strictly valid static policies.
See the [complete example](../analysis/example_test.go).

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

For `NewlyPermitted`, **holds means the change permits nothing new**.
A counterexample has `First == cedar.Deny` and `Second == cedar.Allow`.
For `Equivalent`, a counterexample has different decisions.

Check the Go error before using the report. A zero-value report has no
results, so its `Holds()` method returns true vacuously.

Every counterexample is re-evaluated with Cedar's concrete authorizer inside
the module before being returned. Solver-generated values may be extreme,
such as a `Long` of 2^63−1 or a datetime before 1970. A successful property
result depends on SymCC's encoding and the solver's `unsat` answer; see
[Verification](verification.md#upstream-assurance).

## Configure the analyzer

`Analyzer` is safe for concurrent use. Each call creates and closes its own
module instance and solver session.

| Option | Default |
|---|---|
| `WithTimeout` | 60 s, including solver time |
| `WithMemoryLimit` | 1 GiB linear memory per instance |
| `WithCompilationCache` | No shared cache |
| `WithMaxSourceBytes` | 64 MiB encoded schema and policies |
| `WithMaxSolverOutput` | 256 MiB read from the solver per call |

`Solver` and `Session` support custom solver integrations. `Command` runs
an executable with explicit arguments and an empty environment. It closes
the process when the call ends or the context expires. The solver remains
a host process; see [Security model](security.md#solver-process).

## Implementation

SymCC 0.7.0 is vendored with a small target-specific patch that excludes
its native process-based `LocalSolver` and solver pool from WebAssembly
builds. Its symbolic compiler runs in the guest; the Go host provides
`solver_write` and `solver_read` imports.

[`scripts/vendor-symcc.sh`](../scripts/vendor-symcc.sh) checks the vendored
source against the pinned crates.io archive plus
[`rust/patches`](../rust/patches). The
[maintenance guide](maintenance.md#upgrading-cedar) describes upgrades.
