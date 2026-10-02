# cedar-go-wasm

Cedar's Rust authorization engine, strict validator, and policy-change
analysis for Go. The reference implementation runs as embedded WebAssembly
under [wazero](https://wazero.io/), so authorization ships in a Go binary
and builds with the Go toolchain alone.

We wanted all of Cedar in Go.
[cedar-go](https://github.com/cedar-policy/cedar-go#comparison-to-the-rust-implementation)
lacks feature parity with the Rust reference implementation and
[doesn't appear actively maintained](https://github.com/cedar-policy/cedar-go/commits/main/).
So we run the Rust implementation directly.

The embedded versions are **cedar-policy 4.13.0**,
**cedar-policy-formatter 4.13.0**, and **cedar-policy-symcc 0.7.0**. Authorization and strict validation match the
pinned upstream corpus: **7,523 tests, 60,184 requests, zero mismatches**.
See [verification](docs/verification.md) for the checks and their scope.

[Example](#example) · [Testing](#testing-and-security) · [Performance](#performance) · [Maintenance](#maintenance) · [Documentation](#documentation)

## Install

Requires **Go 1.26 or later**.

```bash
go get github.com/ChrisMckerracher/cedar-go-wasm/cedar
```

```go
import "github.com/ChrisMckerracher/cedar-go-wasm/cedar"
```

The project is pre-v1; the Go API may evolve before a stable release.
The [API guide](docs/api.md) covers parsed policy edits, template management,
on-demand entity loading, request-specific slicing, and policy formatting through
the pinned Rust implementation. Experimental APIs are marked individually.

## Example

Alice can view a photo she owns, and every request must use MFA:

```go
ctx := context.Background()
rt, err := cedar.NewRuntime(ctx)
if err != nil {
	return err
}
defer rt.Close(ctx)

schema := cedar.SchemaFromCedar(`
entity User;
entity Photo { owner: User, private: Bool };
action view appliesTo { principal: User, resource: Photo, context: { mfa: Bool } };
`)
alice := cedar.NewEntityUID("User", "alice")
authorizer, err := rt.NewAuthorizer(ctx, cedar.Config{
	Schema: &schema,
	Policies: cedar.PoliciesFromCedar(`
permit(principal, action == Action::"view", resource)
when { resource.owner == principal || !resource.private };
forbid(principal, action, resource) unless { context.mfa };`),
	Entities: cedar.NewEntities(
		cedar.Entity{UID: alice},
		cedar.Entity{
			UID:   cedar.NewEntityUID("Photo", "beach"),
			Attrs: cedar.Record{"owner": alice, "private": cedar.Bool(true)},
		},
	),
})
if err != nil {
	return err
}
defer authorizer.Close()

response, err := authorizer.Authorize(ctx, cedar.Request{
	Principal: alice,
	Action:    cedar.NewEntityUID("Action", "view"),
	Resource:  cedar.NewEntityUID("Photo", "beach"),
	Context:   cedar.NewContext(cedar.Record{"mfa": cedar.Bool(true)}),
})
if err != nil {
	return err
}
fmt.Println(response.Decision, response.Reasons)
// allow [policy0]
```

Set `mfa` to false and the result is `deny [policy1]`. The
[runnable example](cedar/example_test.go) exercises both outcomes and strict
validation. The [API guide](docs/api.md) covers values, lifecycle, and errors.

Experimental [partial evaluation](docs/partial-evaluation.md) accepts unknown
request and entity data, returns inspectable residual policies, and resumes
authorization when the missing data is available.

Package [`analysis`](docs/analysis.md) also answers whether a change permits
anything new, or whether two policy sets are equivalent. It uses SymCC with
cvc5 and returns concrete counterexamples for changed decisions.

## Testing and security

- **Conformance:** CI compares decisions, deciding policy IDs, evaluation
  error policy IDs, and strict-validation results against Cedar's corpus.
- **Fuzzing:** Go fuzz targets exercise requests, policies, and entities
  across the Go/Wasm interface; CI runs each target for 60 seconds.
- **Fault handling:** tests exercise timeouts, cancellation, memory
  exhaustion, stack overflow, and corrupted instances.
  Concrete authorization errors return `Deny`; partial evaluation errors return
  `Undecided`. Faulted instances are discarded.
- **Sandbox and build checks:** import allowlists, memory and time limits,
  module hashes, and byte-for-byte rebuild checks are part of the design.

Read the [security model](docs/security.md) and
[verification guide](docs/verification.md) for details, including a scoped
SMT proofs of response-word and callback-budget arithmetic.

## Performance

Measured on the same 45-policy workload, with the same Cedar version:

| Operation | Native Rust | Go/Wasm | Go/Wasm cost |
|---|---|---|---|
| Authorization, including request construction/parsing | 127 µs | 1.22–1.24 ms | **9.6–9.8×** |
| Analyze an added binding | 0.79 s | 1.19 s | **1.5×** |
| Analyze a raised device level | 0.19 s | 0.58 s | **3.1×** |

Authorization throughput with 12 callers and 12 instances was about
**5,000 decisions/second**. A warm compilation cache reduced runtime startup
from **3.7 s to 130 ms**. These are workload-specific measurements from
October 1, 2026, on a Ryzen 5 5600X; see [Performance](docs/performance.md)
for methodology, memory costs, and reproduction commands.

## Maintenance

Each release pins one Cedar version, the Rust toolchain, and its dependencies.
Cedar upgrades rebuild both embedded modules and must pass conformance and
analysis tests. CI checks reproducible builds, licenses, and vulnerabilities;
Dependabot proposes updates, and weekly audits check for new advisories.
Release builds publish module checksums and signed provenance.

The [maintenance guide](docs/maintenance.md) documents upgrades, dependency
review, versioning, and release steps.

## Documentation

| Guide | Contents |
|---|---|
| [API](docs/api.md) | Runtime, policies, templates, entity loading/slicing, formatting, and errors |
| [Partial evaluation](docs/partial-evaluation.md) | Experimental TPE, unknown inputs, and residual reauthorization |
| [Change analysis](docs/analysis.md) | Setup, policy comparisons, and counterexamples |
| [Security](docs/security.md) | Sandbox, limits, and failure behavior |
| [Verification](docs/verification.md) | Conformance, fuzzing, and assurance scope |
| [Performance](docs/performance.md) | Benchmarks, ratios, memory, and startup |
| [Maintenance](docs/maintenance.md) | Upgrades, reproducible builds, and releases |
| [Contributing](CONTRIBUTING.md) | Repository layout and development workflow |

## License

Apache License 2.0. See [LICENSE](LICENSE), [NOTICE](NOTICE), and
[third-party licenses](THIRD_PARTY_LICENSES.txt).
