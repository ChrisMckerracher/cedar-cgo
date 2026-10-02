# Contributing

Report bugs and propose changes through GitHub issues and pull requests.
Report vulnerabilities privately, as [SECURITY.md](SECURITY.md) describes.

## Layout

| Path | Contents |
|---|---|
| `*.go` | Package `cedar`: the runtime, the authorizer, validation and the Go types |
| `analysis/` | Package `analysis`: change analysis with SymCC and an external solver |
| `internal/wasmhost/` | wazero setup: hash check, import allowlist, instances, calls |
| `internal/modules/` | The embedded modules and their SHA-256 constants, written by `scripts/build-wasm.sh` |
| `rust/crates/abi/` | Memory exchange shared by both modules |
| `rust/crates/authorizer/` | The authorization module: load, authorize, validate |
| `rust/crates/analysis/` | The analysis module: SymCC over host solver calls |
| `rust/crates/native-bench/` | Native timing baseline; not part of any module |
| `rust/vendor/`, `rust/patches/` | cedar-policy-symcc 0.7.0 and the patch that makes it build for wasm |
| `testdata/joy/` | A 45-policy schema and policy set used by tests and benchmarks |

## Tests

You need Go 1.26 or later.

```bash
go vet ./...
go test ./...
```

The corpus conformance test runs when `CEDAR_CORPUS_DIR` names an extracted
corpus. Use the commit and checksum that `.github/workflows/ci.yml` pins:

```bash
commit=1999ea249229e26cabb398a279fea721854a471d
curl -sSfL -o corpus.tar.gz "https://raw.githubusercontent.com/cedar-policy/cedar-integration-tests/$commit/corpus-tests.tar.gz"
echo "65476adf952c0574d6bf9b317d67d30c9ac462eb1dbf5e4c7b2a35856baf5205  corpus.tar.gz" | sha256sum --check
mkdir corpus && tar xzf corpus.tar.gz -C corpus
CEDAR_CORPUS_DIR="$PWD/corpus" go test -run '^TestCorpus$' -v .
```

The analysis tests run when `CVC5` names a cvc5 1.3.1 executable, from the
[cvc5 release](https://github.com/cvc5/cvc5/releases/tag/cvc5-1.3.1):

```bash
CVC5=/path/to/cvc5 go test -v ./analysis/
```

The fuzz targets run their seeds in `go test`. To fuzz one:

```bash
go test -run '^$' -fuzz '^FuzzAuthorize$' -fuzztime 5m .
```

## Changing the Modules

The Go packages embed prebuilt modules, so users need no Rust toolchain.
After any change under `rust/`, rebuild them and commit the result:

```bash
rustup toolchain install       # installs the version in rust-toolchain.toml
scripts/build-wasm.sh          # rewrites internal/modules/*/*.wasm and sha256.go
scripts/third-party-licenses.sh  # needs cargo-about 0.9.2 with the cli feature
```

CI rebuilds the modules from source and fails if the bytes differ from the
committed ones. It also runs rustfmt, clippy, `cargo deny`, `cargo audit`
and `scripts/vendor-symcc.sh`, which checks the vendored SymCC against
crates.io.

A Dependabot pull request that changes `rust/Cargo.lock` fails that
comparison until someone runs the two scripts above on its branch.

## Dependencies

Each direct dependency, tool, toolchain, binary and GitHub Action must come
from an established organization or have a solid star count. A personal
repository with few stars is not acceptable. Transitive dependencies of an
accepted dependency are acceptable. Download every binary from the
project's official release and pin its SHA-256. Pin GitHub Actions by commit
SHA. Record each new direct dependency in the README's supply-chain table.

Every crate must pass `cargo deny`, whose license allowlist contains only
licenses compatible with Apache-2.0. Do not add code under the LGPL or the
GPL to the modules.

## Upgrading Cedar

Each release embeds exactly one Cedar version. To move to a new one:

1. Set the new `cedar-policy`, `cedar-policy-core` and `cedar-policy-symcc`
   pins in `rust/Cargo.toml`. Use the SymCC version that the Cedar release
   pairs with.
2. In `scripts/vendor-symcc.sh`, set the new SymCC version and the checksum
   from the crates.io index. Update the patch in `rust/patches` so that it
   applies, then run `scripts/vendor-symcc.sh --write`.
3. Run `cargo update --manifest-path rust/Cargo.toml -p cedar-policy`, then
   `scripts/build-wasm.sh` and `scripts/third-party-licenses.sh`.
4. Set `CedarVersion` and `SymCCVersion` in `version.go`.
5. Set the corpus commit and checksum in both workflows and in this file, to
   the corpus that Cedar generated for the new version.
6. Run the corpus and analysis tests. Every mismatch blocks the upgrade.
7. Update the version table in the README.

## Releases

A maintainer tags a commit on `main` whose CI passed, such as `v0.1.0`. The
release workflow rebuilds the modules, checks them against the committed
ones, runs the tests with the corpus, attests build provenance, and
publishes the release.
