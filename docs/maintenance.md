# Maintenance guide for cedar-go-wasm maintainers

[Documentation](README.md) · [Contributing](../CONTRIBUTING.md) · [Security model](security.md)

## Contents

- [Versioning](#versioning)
- [Upgrading Cedar](#upgrading-cedar)
- [Reproducible builds](#reproducible-builds)
- [Dependency review](#dependency-review)
- [Continuous checks](#continuous-checks)
- [Releases](#releases)

## Versioning

Each release embeds exactly one Cedar version. The project uses
`v0.MINOR.PATCH` while the Go interface settles:

- A Cedar upgrade increments MINOR.
- A glue fix with the same Cedar version increments PATCH.
- v1.0.0 will mark a stable Go interface; Cedar upgrades will continue to
  increment MINOR.

| Release | cedar-policy | cedar-policy-symcc | Corpus commit |
|---|---|---|---|
| v0.1.0 (planned) | 4.13.0 | 0.7.0 | `1999ea24` |

`cedar.CedarVersion` and `cedar.SymCCVersion` identify the embedded versions.
A test compares them with `rust/Cargo.lock`. The transport ABI has a separate
version, checked by the host at instantiation.

## Upgrading Cedar

### Lesson 1: Review a Cedar upgrade

Objective: Update pinned sources and validate generated modules before merging an upgrade.

1. Update the exact `cedar-policy`, `cedar-policy-core`, `cedar-policy-formatter`, and
   `cedar-policy-symcc` pins in [`rust/Cargo.toml`](../rust/Cargo.toml).
   Choose the SymCC version paired with that Cedar release. Check its
   minimum supported Rust version and update `rust-toolchain.toml` if
   necessary; CI reads the toolchain pin from that file.
2. Update the version and crates.io checksum in
   [`scripts/vendor-symcc.sh`](../scripts/vendor-symcc.sh), adapt the patch
   in `rust/patches`, and run `scripts/vendor-symcc.sh --write`.
3. Update the lockfile, build the modules, and generate license notices:

   ```bash
   cargo update --manifest-path rust/Cargo.toml -p cedar-policy
   scripts/build-wasm.sh
   scripts/third-party-licenses.sh
   ```

4. Update [`cedar/version.go`](../cedar/version.go).
5. Update the corpus commit and checksum in both workflows and the
   [contributor instructions](../CONTRIBUTING.md#tests). Use the corpus
   generated for the new Cedar version.
6. Run all Go tests with `CEDAR_CORPUS_DIR` and `CVC5` set, fuzz every target
   listed in CI, and run the Rust and dependency checks. Every conformance
   mismatch blocks the upgrade.
7. Update this version table, the README's embedded versions, and the
   [verification results](verification.md). Re-measure performance before
   presenting benchmark numbers as results for the new version.
8. Include dependency pins, lockfile changes, vendored sources, and third-party notices in the same review.
   Leave generated `.wasm` files and hash constants untracked.

Knowledge check: Must an upgrade include generated modules in Git? No; CI builds and validates the reviewed sources.

Review upstream release notes for security fixes, semantic changes, added
imports, and changed resource requirements. Review the SymCC patch against
the new upstream source, keeping it limited to the Wasm target adaptation.

## Reproducible builds

### Lesson 2: Generate and compare modules

Objective: Build identical modules from the same pinned sources in separate Cargo target directories.

1. Use Rust 1.99.0 and the `wasm32-wasip1` target from [`rust-toolchain.toml`](../rust-toolchain.toml).
2. If the pinned toolchain is missing, install it with `rustup toolchain install`.
3. From a source checkout, build modules before Go compilation:

```bash
scripts/build-wasm.sh
go test ./...
```

The build generates modules, hash files, `SHA256SUMS`, and `SOURCE_COMMIT` under `internal/modules/`.
`SOURCE_COMMIT` records the full Git commit identifier.
The files remain untracked. Set `WASM_OUTPUT_DIR` to write a separate artifact directory.

4. To check reproducibility, compare two independent builds:
   Use an empty output directory.

```bash
scripts/check-wasm-reproducibility.sh /tmp/cedar-wasm-artifact
go run ./cmd/verify-wasm-artifact /tmp/cedar-wasm-artifact "$(git rev-parse HEAD)"
```

The check uses fresh Cargo target directories and retains the first artifact after comparison.
The verifier rejects missing files, checksum failures, hash mismatches, and a different source commit.
CI runs this comparison and passes verified artifacts to every Go compilation job.

The build uses Cargo's `--locked` mode, LTO, one codegen unit, disabled incremental compilation, and an 8 MiB Wasm stack.
Path remapping removes checkout, `CARGO_HOME`, and `RUSTUP_HOME` locations from generated modules.
The build verifies vendored SymCC against the pinned source archive and patch.
Runtime hash checks compare embedded bytes with their generated expected values.
Checksums establish integrity against expected values; they do not establish source provenance or reproducibility.

Knowledge check: Can a shared Cargo target directory prove independent compilation? No; each comparison build uses a fresh target directory.

5. After guest or Rust dependency changes, regenerate [`THIRD_PARTY_LICENSES.txt`](../THIRD_PARTY_LICENSES.txt):

```bash
scripts/third-party-licenses.sh
```

That script uses cargo-about 0.9.2 with its `cli` feature.

## Dependency review

Review every direct dependency, tool, toolchain, downloaded binary, and
GitHub Action. Project policy requires an established organization or
substantial community adoption for direct choices. Review purpose,
provenance, licensing, maintenance, and security history; transitive
dependencies remain subject to the automated audits.

| Direct choice | Source and role |
|---|---|
| `cedar-policy`, `cedar-policy-core`, `cedar-policy-formatter`, `cedar-policy-symcc` | Cedar organization; reference engine, formatter, and symbolic compiler |
| `serde`, `serde_json` | serde-rs; serialization |
| `tokio` | tokio-rs; SymCC runtime |
| `miette` | zkat/miette, also used by Cedar; diagnostic rendering |
| `wazero` | tetratelabs/wazero; Go WebAssembly runtime |
| `puddle/v2` | jackc/puddle, the pgx connection pool; instance pooling |
| `pgregory.net/rapid` | Gregory Petrosyan; property-based testing (Go, test-only) |
| Go and Rust | Official toolchain distributions |
| cargo-deny, cargo-about | EmbarkStudios; dependency policy and license notices |
| cargo-audit | RustSec; Rust vulnerability auditing |
| govulncheck | Go team; Go vulnerability auditing |
| cvc5 | Official cvc5 release; analysis tests and supported solver integration |
| `actions/*` | GitHub; CI and release automation |

Pin downloaded binaries by SHA-256 and Actions by commit SHA. Update this
table for new direct choices. Dependabot proposes Go, Cargo, and Action
updates; maintainers review and merge them.
A Rust dependency update requires pinned-source CI builds and regenerated license notices.
Do not commit generated modules or hash files.

[`rust/deny.toml`](../rust/deny.toml) permits Apache-2.0,
Apache-2.0 WITH LLVM-exception, MIT, Unicode-3.0, and Zlib licenses, and
allows crates.io as the registry. The embedded modules must pass that
policy. Solver executable distribution is handled separately by the
application; see [analysis setup](analysis.md#setup).

## Continuous checks

| Check | Purpose |
|---|---|
| Go tests, vet, and formatting | Validate the public packages on Linux, macOS, and Windows |
| Pinned upstream corpus | Detect authorization or validation drift |
| cvc5 analysis tests | Check policy comparisons and counterexamples |
| cvc5 arithmetic proofs | Check response packing, header predicates, and callback budgets/conversions |
| Native feature fixture regeneration | Detect drift in templates, policies, TPE, loading, slicing, and formatting |
| All fuzz targets, 60 s each | Exercise authorization and each new policy/entity boundary |
| rustfmt and clippy | Check the Rust glue |
| Vendored SymCC comparison | Verify release archive plus local patch |
| Two independent Wasm builds | Verify identical outputs from the same pinned sources |
| Artifact integrity and source commit | Reject incomplete, corrupted, or mismatched workflow outputs |
| Clean consumer bundle test | Build and run both public packages without Rust |
| License notice regeneration | Keep notices aligned with the lockfile |
| cargo-deny, cargo-audit, govulncheck | Check policy and vulnerability advisories |

The [CI workflow](../.github/workflows/ci.yml) runs on main-branch pushes,
pull requests, and a weekly schedule, so new advisories can surface even
without source changes. The workflow contains exact tool versions and
download checksums.

## Releases

### Lesson 3: Validate and publish a release

Objective: Publish tested modules from an exact reviewed commit with checksums and build provenance.

1. Complete every applicable local check in [CI](../.github/workflows/ci.yml) against the final candidate before pushing.
   Include the exact repository-wide `gofmt` check. Use `set -euo pipefail` for combined commands.
   A skipped check, missing tool, or failed check blocks publication.
2. Push the reviewed commit and verify successful remote CI for that exact commit on `main`.
3. After CI succeeds, create the release tag for that exact commit.
4. Check the [release workflow](../.github/workflows/release.yml).
   It verifies successful CI for the tagged commit before publication.
   It compares independent builds, verifies the source commit, and tests generated modules with the corpus and cvc5.
   It packages the tested modules into `cedar-go-wasm-source.zip` and checks a clean consumer build without Rust.
   It publishes the tested bytes, `SOURCE_COMMIT`, and `SHA256SUMS`, with GitHub/Sigstore build provenance.

A manual workflow run exercises build, test, packaging, and attestation without publishing a release.

Knowledge check: Does successful CI on another commit permit tagging this commit? No; CI must succeed on the exact release commit.

5. Download the release assets to one directory and verify their checksums:

```bash
sha256sum --check SHA256SUMS
```

6. Verify the module and source-bundle attestations:

```bash
gh attestation verify authorizer.wasm --repo ChrisMckerracher/cedar-go-wasm
gh attestation verify analysis.wasm --repo ChrisMckerracher/cedar-go-wasm
gh attestation verify cedar-go-wasm-source.zip --repo ChrisMckerracher/cedar-go-wasm
```

The source bundle contains the exact source commit, both modules, their generated hash files, and artifact metadata.
Consumers extract it and configure a local Go module replacement as described in [installation](../README.md#install).
Go module proxies and source downloads do not contain release attachments.
Ordinary `go get` without a local replacement cannot build the source-only module.
For source development, clone the repository, run `scripts/build-wasm.sh`, and configure the local replacement.
See [SECURITY.md](../SECURITY.md) for supported versions and vulnerability reporting.

Policy API fixtures are generated by the pinned native Rust API, independently
of the Wasm operation implementation. After policy guest changes, run
`scripts/policies-parity.sh --check`; update intentional expectation changes with
`--write` and review the fixture diff in `testdata/parity/policies/native.json`.
CI regenerates this fixture and compares it byte for byte.
