# Maintenance

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

1. Update the exact `cedar-policy`, `cedar-policy-core`, `cedar-policy-formatter`, and
   `cedar-policy-symcc` pins in [`rust/Cargo.toml`](../rust/Cargo.toml).
   Choose the SymCC version paired with that Cedar release. Check its
   minimum supported Rust version and update `rust-toolchain.toml` if
   necessary; CI reads the toolchain pin from that file.
2. Update the version and crates.io checksum in
   [`scripts/vendor-symcc.sh`](../scripts/vendor-symcc.sh), adapt the patch
   in `rust/patches`, and run `scripts/vendor-symcc.sh --write`.
3. Update the lockfile and rebuild the artifacts:

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
8. Include the rebuilt `.wasm` files, hash constants, lockfile, vendored
   source changes, and third-party notices in the same review.

Review upstream release notes for security fixes, semantic changes, added
imports, and changed resource requirements. Review the SymCC patch against
the new upstream source, keeping it limited to the Wasm target adaptation.

## Reproducible builds

Go applications use the committed embedded modules. Maintainers rebuild
them with Rust 1.99.0 and the `wasm32-wasip1` target specified in
[`rust-toolchain.toml`](../rust-toolchain.toml):

```bash
scripts/build-wasm.sh
git diff --exit-code -- internal/modules
```

Install the pinned toolchain with `rustup toolchain install` when setting up
a development environment that does not already have it.

The build uses Cargo's `--locked` mode, LTO, one codegen unit, and path
remapping for the checkout, `CARGO_HOME`, and `RUSTUP_HOME`. CI requires the
rebuilt modules to match the committed bytes. Runtime hash checks then
verify that the embedded artifact matches its expected checksum.

After intentional guest or Rust dependency changes, rebuild and include
the new artifacts rather than expecting the old hashes to pass. Regenerate
[`THIRD_PARTY_LICENSES.txt`](../THIRD_PARTY_LICENSES.txt) with:

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
| Go and Rust | Official toolchain distributions |
| cargo-deny, cargo-about | EmbarkStudios; dependency policy and license notices |
| cargo-audit | RustSec; Rust vulnerability auditing |
| govulncheck | Go team; Go vulnerability auditing |
| cvc5 | Official cvc5 release; analysis tests and supported solver integration |
| `actions/*` | GitHub; CI and release automation |

Pin downloaded binaries by SHA-256 and Actions by commit SHA. Update this
table for new direct choices. Dependabot proposes Go, Cargo, and Action
updates; maintainers review and merge them. A Rust dependency update also
requires rebuilt modules and regenerated license notices.

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
| Byte-identical Wasm rebuild | Verify committed artifacts against source |
| License notice regeneration | Keep notices aligned with the lockfile |
| cargo-deny, cargo-audit, govulncheck | Check policy and vulnerability advisories |

The [CI workflow](../.github/workflows/ci.yml) runs on main-branch pushes,
pull requests, and a weekly schedule, so new advisories can surface even
without source changes. The workflow contains exact tool versions and
download checksums.

## Releases

A maintainer tags a reviewed commit on `main` after CI passes. The
[release workflow](../.github/workflows/release.yml) rebuilds and compares
the modules, runs Go tests with the corpus, produces checksums, attests
build provenance through GitHub/Sigstore, and publishes the artifacts.
A manual workflow run exercises the build without publishing a release.

Verify a downloaded module's attestation with:

```bash
gh attestation verify authorizer.wasm --repo ChrisMckerracher/cedar-go-wasm
```

Apply the same command to `analysis.wasm`, and compare both files with the
release's `SHA256SUMS`. See [SECURITY.md](../SECURITY.md) for supported
versions and vulnerability reporting.

Policy API fixtures are generated by the pinned native Rust API, independently
of the Wasm operation implementation. After policy guest changes, run
`scripts/policies-parity.sh --check`; update intentional expectation changes with
`--write` and review the fixture diff in `testdata/parity/policies/native.json`.
CI regenerates this fixture and compares it byte for byte.
