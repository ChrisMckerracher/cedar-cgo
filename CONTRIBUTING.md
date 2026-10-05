# Contributing to cedar-go-wasm

Report bugs and propose changes through GitHub issues and pull requests.
Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Contents

- [Repository layout](#repository-layout)
- [Tests](#tests)
- [Guest changes](#guest-changes)
- [Documentation changes](#documentation-changes)
- [Dependencies and releases](#dependencies-and-releases)

## Repository layout

```text
cedar/                 Public authorization and validation package
analysis/              Public policy-comparison package and solver adapter
internal/
  wasmhost/            Shared module compilation, instances, and faults
  wire/                Shared JSON source, UID, and error envelopes
  capbuf/              Bounded diagnostic output
  modules/             Embedding code and untracked generated Wasm outputs
  verification/        Source-linked SMT proof of ABI arithmetic
rust/
  crates/
    abi/               Guest memory exchange and source parsing
    authorizer/        Guest load, authorize, and validate operations
    analysis/          SymCC guest and solver protocol
    native-bench/      Native authorization benchmark
  patches/             Wasm target patch for SymCC
  vendor/              Pinned SymCC source
testdata/joy/          Shared policy, schema, and entity fixtures
docs/                  API, analysis, security, verification, performance, maintenance
scripts/               Rebuild, vendoring, and license-generation scripts
.github/               CI, releases, and dependency-update configuration
```

Tests and benchmarks live beside the package they exercise. The repository
root contains project metadata; Go users import `/cedar` or `/analysis`.

Within `cedar`, `runtime.go` manages module compilation, `config.go` defines
authorizer settings, `pool.go` handles instance lifetime, `authorizer.go`
coordinates calls, `protocol.go` decodes authorization results, and
`validation.go` runs strict validation. Sources, entities, values, contexts,
and errors each have a focused file.

Within `analysis`, `analyzer.go` coordinates comparisons, `options.go`
defines budgets, `host.go` implements the guest's solver imports,
`solver.go` manages native processes, and `report.go` decodes results.
The shared `wasmhost` package separates module setup, instance calls, and
fault reporting.

Keep Cedar decisions inside the Rust engine. Changes to transport,
pooling, or resource handling belong at the corresponding Go seam.

## Tests

### Lesson 1: Build and test a source checkout

Objective: Generate the embedded modules from pinned Rust sources before Go compilation.

1. Use Go 1.26 or later and the Rust toolchain in `rust-toolchain.toml`.
2. If the pinned Rust toolchain is missing, install it with `rustup toolchain install`.
3. From the repository root, build both modules, then run the Go checks:

```bash
scripts/build-wasm.sh
go vet ./...
go test ./...
```

The build generates both `.wasm` files and their `sha256.go` files under `internal/modules/`.
Git ignores these outputs. Repeat the build after changing Rust sources, dependencies, or build settings.

Knowledge check: Can a clean checkout run Go tests before generating the embedded files? No; Go embedding requires those files.

4. To run conformance tests, set `CEDAR_CORPUS_DIR`.
   Use the corpus commit and checksum from both workflows:

```bash
commit=1999ea249229e26cabb398a279fea721854a471d
curl -sSfL -o corpus.tar.gz "https://raw.githubusercontent.com/cedar-policy/cedar-integration-tests/$commit/corpus-tests.tar.gz"
echo "65476adf952c0574d6bf9b317d67d30c9ac462eb1dbf5e4c7b2a35856baf5205  corpus.tar.gz" | sha256sum --check
mkdir -p corpus
tar xzf corpus.tar.gz -C corpus
CEDAR_CORPUS_DIR="$PWD/corpus" go test -run '^TestCorpus$' -v ./cedar
```

5. To run analysis integration tests, use a cvc5 1.3.1 executable from the
[official release](https://github.com/cvc5/cvc5/releases/tag/cvc5-1.3.1):

```bash
CVC5=/path/to/cvc5 go test -v ./analysis
```

Unset variables cause the corresponding integration tests to skip.
6. For a complete verification pass, set both variables:

```bash
CEDAR_CORPUS_DIR="$PWD/corpus" CVC5=/path/to/cvc5 go test -count=1 ./...
```

7. Run fuzz targets for longer when needed. Ordinary tests run their seed inputs:

```bash
go test -run '^$' -fuzz '^FuzzAuthorize$' -fuzztime 5m ./cedar
```

Property tests (`TestProperty*`) run in ordinary tests too; rapid prints the
seed on failure, so reproduce with `go test ./cedar -run TestPropertyX -rapid.seed=N`.

Repeat for every target listed in the CI workflow and verification guide. See
[Verification](docs/verification.md) for coverage and
[Performance](docs/performance.md#reproduce) for benchmarks.

Formatting has a direct native upstream oracle, independent of the guest wrapper:

```bash
scripts/format-parity.sh --check
cargo clippy --manifest-path rust/Cargo.toml --locked --release -p cgw-authorizer --example format_parity -- -D warnings
```

After changing the formatter pin or fixture inputs, run
`scripts/format-parity.sh --write`, review `testdata/parity/format/expected.json`,
and run `go test -run 'TestFormat|ExampleRuntime_FormatPolicies' ./cedar`.
CI checks regenerated fixtures against the committed results.

## Guest changes

### Lesson 2: Validate a guest source change

Objective: Review Rust sources and verify their generated modules without committing build outputs.

1. Use the pinned Rust toolchain and Wasm target from `rust-toolchain.toml`.
2. After editing guest code or its dependencies, generate modules and license notices:

```bash
scripts/build-wasm.sh
scripts/third-party-licenses.sh
```

3. Include source changes, dependency pins, lockfile changes, and updated license notices in the review.
   Leave generated modules and hashes untracked. CI builds them from the reviewed commit.
   CI compares two independent builds and tests the generated modules.

4. From `rust/`, run the Rust checks:

```bash
cargo fmt --all -- --check
cargo clippy --locked --release --target wasm32-wasip1 -p cgw-abi -p cgw-authorizer -p cgw-analysis -- -D warnings
cargo clippy --locked --release -p cgw-native-bench -- -D warnings
cargo deny --all-features check
cargo audit --deny warnings
```

5. From the repository root, run `scripts/vendor-symcc.sh` to verify the vendored source.

Knowledge check: Which generated files belong in the commit? License notices belong in the commit; modules and hash files do not.

The [maintenance guide](docs/maintenance.md) describes tool versions, builds, and Cedar upgrades.

## Documentation changes

Keep the README focused on the purpose, example, measured tradeoffs, and
links to the guides. Put detailed contracts in [API](docs/api.md), execution
assumptions in [Security](docs/security.md), and development procedures in
this file or [Maintenance](docs/maintenance.md).

Keep examples aligned with the executable Go examples. Identify the
workload, versions, and environment for benchmark claims, and state the
scope of verification evidence. Update links and commands when moving files.

## Dependencies and releases

See [dependency review](docs/maintenance.md#dependency-review),
[Cedar upgrades](docs/maintenance.md#upgrading-cedar), and
[releases](docs/maintenance.md#releases). Dependency changes require
maintainer review and must satisfy the repository's license and provenance
policies.
