# cedar-cgo

Cedar authorization, strict validation, policy tools, and policy comparison for Go.
The package runs Cedar's pinned Rust reference implementation through cgo.
It uses **Cedar 4.13.0**, **Cedar formatter 4.13.0**, and **SymCC 0.7.0**.

The Go module is `github.com/ChrisMckerracher/cedar-cgo`.
The native migration changes imports, constructors, and resource controls.
For existing applications, see the [migration guide](docs/migration/consumer.md).

## Requirements

Supported targets are Linux amd64 GNU, Linux arm64 GNU, and macOS arm64.
CI tests **Go 1.27.1** on each target.
All builds require cgo and a supported C compiler.
Source builds also require the pinned Rust toolchain in `rust-toolchain.toml`.
Prebuilt consumer bundles do not require Rust.
See [platform requirements and verification status](docs/migration/platforms.md).

Policy comparison requires an external solver. Verification uses **cvc5 1.3.1**.
See [analysis setup](docs/analysis.md).

## Install

### From source

From a source checkout, build the native library before running Go tests:

```bash
CGO_ENABLED=1 scripts/build-native.sh
go test ./...
```

Builds use committed source. Commit source changes before rebuilding verified artifacts.
The command creates an untracked native archive and its generated linker requirements.
It uses existing tools and dependencies.

### With a prebuilt library

Go module downloads do not include native release attachments.
Use a [release](https://github.com/ChrisMckerracher/cedar-cgo/releases) with the `cedar-cgo` module path.
Download the platform's source bundle and the files named by its checksum file.
Verify the complete checksum file and archive attestations before extraction.
See [release verification](docs/maintenance.md#lesson-4-verify-a-downloaded-release) for commands.

After extraction, point your application at the verified source bundle:

```bash
go mod edit -replace=github.com/ChrisMckerracher/cedar-cgo=/absolute/path/cedar-cgo
CGO_ENABLED=1 go get github.com/ChrisMckerracher/cedar-cgo/cedar
```

Keep the replacement directory available for later builds.
Bundles use `linux_amd64`, `linux_arm64`, or `darwin_arm64` platform names.
Older releases retain the `cedar-go-wasm` module path and bundle names.
A Rust static archive still requires the platform's system libraries.

## Example

This policy permits Alice to view one photo.

```go
import (
    "context"
    "fmt"

    "github.com/ChrisMckerracher/cedar-cgo/cedar"
    "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization"
    "github.com/ChrisMckerracher/cedar-cgo/cedar/authorization/request"
    "github.com/ChrisMckerracher/cedar-cgo/cedar/entity/uid"
    "github.com/ChrisMckerracher/cedar-cgo/cedar/policy"
)
```

```go
ctx := context.Background()
rt, err := cedar.NewRuntime(ctx)
if err != nil {
    return err
}
defer rt.Close(ctx)

policies := policy.PoliciesFromCedar(`
permit(principal == User::"alice", action == Action::"view", resource == Photo::"beach");
`)
authorizer, err := rt.NewAuthorizer(ctx, authorization.Config{Policies: policies})
if err != nil {
    return err
}
defer authorizer.Close()

response, err := authorizer.Authorize(ctx, request.Request{
    Principal: uid.NewEntityUID("User", "alice"),
    Action:    uid.NewEntityUID("Action", "view"),
    Resource:  uid.NewEntityUID("Photo", "beach"),
})
if err != nil {
    return err
}
fmt.Println(response.Decision)
// allow
```

If the principal is `User::"bob"`, the result is `deny`.
Reuse the runtime and authorizer across requests. Close authorizers before their runtime.
Check the Go error before using the decision.
Concrete authorization errors return `Deny`. Cedar evaluation diagnostics can accompany `Allow`.
[Runnable examples](cedar/integration/example_test.go) show entity attributes, MFA checks, and explicit strict validation.

## Native execution

Native execution shares the application's process and memory.
Go contexts cannot interrupt native CPU work without a cooperative callback.
Wasm memory limits no longer apply.
Read the [execution contract](docs/migration/native-contract.md) for cancellation, memory, panic, and ownership rules.
See the [security model](docs/security.md) for process isolation and resource controls.

## Performance and verification

These medians compare direct Rust execution with Go/cgo on the same 45-policy Joy workload.
Each workload has five samples, recorded on October 6, 2026, on an AMD Ryzen 5 5600X.

| Operation | Direct Rust | Go/cgo | Go/cgo ÷ Rust |
|---|---:|---:|---:|
| Authorization with request construction and result serialization | 95.694 µs | 135.021 µs | 1.41 |
| Load and close an authorizer | 1.664 ms | 2.018 ms | 1.21 |
| Strict validation with schema and policy parsing | 3.848 ms | 4.341 ms | 1.13 |

The Go path also includes encoding, limits, pooling, cgo calls, and decoding.
These ratios describe this workload and machine.
See [measurement scope and reproduction commands](docs/performance.md) and [raw samples](testdata/performance/rust-cgo/).

The pinned corpus contains **7,523 tests** and **60,184 requests**.
Verification compares decisions, reason IDs, evaluation error IDs, and strict validation results.
Independent fixture programs call pinned Cedar and SymCC directly.
The migration preserves all 25 fuzz targets, saved inputs, property tests, examples, and domain benchmarks.
See the [verification guide](docs/verification.md) for evidence and its limits.

## Documentation

| Guide | Contents |
|---|---|
| [API](docs/api.md) | Domain packages, policy tools, entity operations, and validation |
| [Partial evaluation](docs/partial-evaluation.md) | Unknown inputs, residual policies, and reauthorization |
| [Analysis](docs/analysis.md) | Solver setup, policy comparisons, and counterexamples |
| [Migration](docs/migration/consumer.md) | Import, constructor, and feature-client changes |
| [Maintenance](docs/maintenance.md) | Native builds, dependency checks, and releases |
| [Contributing](CONTRIBUTING.md) | Package responsibilities and development checks |

## License

Apache License 2.0. See [LICENSE](LICENSE), [NOTICE](NOTICE), and [third-party licenses](THIRD_PARTY_LICENSES.txt).
