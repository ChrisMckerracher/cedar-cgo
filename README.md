# cedar-go-wasm

Cedar's pinned Rust implementation runs through cgo for Go consumers.
The package provides authorization, strict validation, policy tools, partial evaluation, and solver-backed analysis.
It uses Cedar 4.13.0, the Cedar formatter 4.13.0, and SymCC 0.7.0.
The module and repository names remain unchanged.

The native migration changes public imports and constructors.
Read the [migration lessons](docs/migration/consumer.md) before updating an existing consumer.
Read the [execution contract](docs/migration/native-contract.md) for cancellation, memory, panic, and ownership rules.

## Supported platforms

Linux amd64 GNU, Linux arm64 GNU, and macOS arm64 are the selected targets.
CI tests Go 1.27.1 on each target.
See the [platform requirements and verification status](docs/migration/platforms.md).

A source build requires Go, cgo, a supported C compiler, and the pinned Rust toolchain.
A prebuilt consumer bundle requires Go, cgo, and a supported C compiler. It does not require Rust.
Analysis also requires an external solver. Verification uses cvc5 1.3.1.

## Lesson 1: Build a source checkout

Objective: Build the native library and authorize a request.

1. Use Go 1.27.1 and the Rust toolchain in `rust-toolchain.toml`.
2. Enable cgo and use the supported platform's C compiler.
3. Commit source changes before building verified artifacts.
4. Build the library from the repository root.

```bash
CGO_ENABLED=1 scripts/build-native.sh
go test ./...
```

The command installs an untracked native archive and its generated linker requirements.
It does not install a new toolchain or dependency.
If a required tool is missing, install it through your approved setup process.

Worked example: [The independent consumer](scripts/consumer/smoke/main.go) runs authorization and real solver analysis.

Knowledge check: Does ordinary `go get` include native release attachments? No. Build the source or use a verified bundle.

## Lesson 2: Install a prebuilt consumer bundle

Objective: Link the exact native files that passed the release checks.

1. Download your platform's source ZIP and checksum file from a [release](https://github.com/ChrisMckerracher/cedar-go-wasm/releases).
2. Verify the ZIP checksum and its build attestation.
3. Extract the verified source bundle to a permanent directory.
4. Set a local module replacement in your consumer project.

```bash
gh attestation verify cedar-go-wasm-linux_amd64-source.zip --repo ChrisMckerracher/cedar-go-wasm
go mod edit -replace=github.com/ChrisMckerracher/cedar-go-wasm=/absolute/path/cedar-go-wasm
CGO_ENABLED=1 go get github.com/ChrisMckerracher/cedar-go-wasm/cedar
```

Use `linux_arm64` or `darwin_arm64` for the other selected platforms.
Verify the complete checksum file as described in [release maintenance](docs/maintenance.md).
Keep the replacement directory available for later builds.

Worked example: CI builds a separate consumer with isolated caches and blocks every Rust command.

Knowledge check: Does a Rust static archive make the Go executable fully static? No. System linker requirements still apply.

## Example

Use the composition package to create domain clients.

```go
ctx := context.Background()
rt, err := cedar.NewRuntime(ctx)
if err != nil {
    return err
}
defer rt.Close(ctx)

policies := policy.PoliciesFromCedar(`permit(principal, action, resource);`)
authorizer, err := rt.NewAuthorizer(ctx, authorization.Config{Policies: policies})
if err != nil {
    return err
}
defer authorizer.Close()

response, err := authorizer.Authorize(ctx, request.Request{
    Principal: uid.NewEntityUID("User", "alice"),
    Action: uid.NewEntityUID("Action", "view"),
    Resource: uid.NewEntityUID("Photo", "beach"),
})
if err != nil {
    return err
}
fmt.Println(response.Decision)
// allow
```

The imports use `/cedar`, `/cedar/authorization`, `/cedar/authorization/request`, `/cedar/entity/uid`, and `/cedar/policy`.
[Runnable examples](cedar/integration/example_test.go) show schema validation and Deny behavior.

## Verification

The pinned corpus contains 7,523 tests and 60,184 requests.
Verification compares decisions, reason IDs, evaluation error IDs, and strict validation results.
Independent fixture programs call pinned Cedar and SymCC directly.
The migration preserves all 25 fuzz targets, saved inputs, property tests, examples, and domain benchmarks.

The [verification guide](docs/verification.md) records evidence and its limits.
The [performance guide](docs/performance.md) separates production measurements from the historical prototype.

## Documentation

Read the [feature guide](docs/api.md), [partial evaluation guide](docs/partial-evaluation.md), and [analysis guide](docs/analysis.md).
Read [contributor setup](CONTRIBUTING.md) for package responsibilities and checks.
Read the [security model](docs/security.md) before selecting process isolation and resource controls.
