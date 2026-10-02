# Contributing

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
  modules/             Embedded Wasm artifacts and generated hashes
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

Use Go 1.26 or later. The committed guest modules let Go tests run without
rebuilding Rust:

```bash
go vet ./...
go test ./...
```

The conformance test requires `CEDAR_CORPUS_DIR`. The corpus commit and
checksum must match the pins in both workflows:

```bash
commit=1999ea249229e26cabb398a279fea721854a471d
curl -sSfL -o corpus.tar.gz "https://raw.githubusercontent.com/cedar-policy/cedar-integration-tests/$commit/corpus-tests.tar.gz"
echo "65476adf952c0574d6bf9b317d67d30c9ac462eb1dbf5e4c7b2a35856baf5205  corpus.tar.gz" | sha256sum --check
mkdir -p corpus
tar xzf corpus.tar.gz -C corpus
CEDAR_CORPUS_DIR="$PWD/corpus" go test -run '^TestCorpus$' -v ./cedar
```

Analysis integration tests require a cvc5 1.3.1 executable from the
[official release](https://github.com/cvc5/cvc5/releases/tag/cvc5-1.3.1):

```bash
CVC5=/path/to/cvc5 go test -v ./analysis
```

Unset variables cause the corresponding integration tests to skip. Set
both when running a complete verification pass:

```bash
CEDAR_CORPUS_DIR="$PWD/corpus" CVC5=/path/to/cvc5 go test -count=1 ./...
```

Fuzz seeds run in ordinary tests. To fuzz a target for longer:

```bash
go test -run '^$' -fuzz '^FuzzAuthorize$' -fuzztime 5m ./cedar
```

Repeat with `FuzzPolicies` and `FuzzEntities`. See
[Verification](docs/verification.md) for coverage and
[Performance](docs/performance.md#reproduce) for benchmarks.

## Guest changes

Use the pinned Rust toolchain and Wasm target from `rust-toolchain.toml`.
After editing guest code or its dependencies:

```bash
scripts/build-wasm.sh
scripts/third-party-licenses.sh
```

Include the regenerated modules, hashes, and license notices with the
source changes. CI compares rebuilt bytes with the committed artifacts.

Run the Rust checks from `rust/`:

```bash
cargo fmt --all -- --check
cargo clippy --locked --release --target wasm32-wasip1 -p cgw-abi -p cgw-authorizer -p cgw-analysis -- -D warnings
cargo clippy --locked --release -p cgw-native-bench -- -D warnings
cargo deny --all-features check
cargo audit --deny warnings
```

Run `scripts/vendor-symcc.sh` from the repository root to verify the
vendored source. The [maintenance guide](docs/maintenance.md) describes
tool versions, rebuilds, and Cedar upgrades.

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
