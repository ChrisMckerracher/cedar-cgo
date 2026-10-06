# Native maintenance lessons for Cedar Go maintainers

## Versioning

The migration changes public import paths, constructors, feature methods, and resource controls.
It requires a breaking pre-v1 release. The module and repository names remain unchanged.
Cedar, the formatter, and SymCC remain pinned together through the workspace dependency graph.

## Lesson 1: Update pinned Cedar dependencies

Objective: Preserve semantics and verification when the upstream version changes.

1. Update the workspace Cedar and formatter pins together.
2. Review SymCC compatibility and verify its registry checksum.
3. Update the corpus pin and checksum for the selected Cedar version.
4. Build native libraries and run complete verification.
5. Review each intentional fixture change before updating its expected output.
6. Regenerate notices from the final locked graph.

```bash
scripts/build-native.sh
scripts/third-party-licenses.sh
scripts/check-rust.sh
```

Worked example: A patch that changes schema diagnostics requires fixture review and Go diagnostic checks.

Knowledge check: Can a fixture check silently regenerate expected output? No. Check commands must leave expectations unchanged.

Use one command for all 18 independent fixture checks:

```bash
python3 scripts/parity/run.py --check
python3 scripts/parity/run.py partial --update
```

Default execution compares committed expectations. Only `--update` writes them.
Formatting retains its oracle assertions. Template and batched checks also run their Go comparisons.

## Lesson 2: Verify native build identity

Objective: Bind each library to its source, target, header, and build inputs.

1. Use the pinned Rust toolchain and native unwind profile.
2. Commit source changes and remove untracked source files.
3. Build with locked dependencies and source-path remapping.
4. Compare two independent Cargo output directories.
5. Verify the exact artifact against the source header and target.

```bash
scripts/check-native-reproducibility.sh /tmp/native-artifact x86_64-unknown-linux-gnu
go run ./cmd/verify-native-artifact /tmp/native-artifact "$(git rev-parse HEAD)" \
    x86_64-unknown-linux-gnu internal/native/include/cedar.h
```

The artifact contains the archive, header, linker source, manifest, source commit, and checksums.
The manifest binds ABI 2, Cedar versions, Rust toolchain, native profile, and unwind behavior.
Rust reports system linker requirements through `--print=native-static-libs`.

Worked example: A header hash mismatch fails before Go links the library.

Knowledge check: Does matching a target label prove the archive architecture? No. The verifier also inspects object headers.

## Lesson 3: Publish a verified native release

Objective: Publish only files from successful verification of the exact main commit.

1. Run all applicable local CI checks against the final candidate.
2. Include the exact repository-wide formatting check.
3. Push the candidate and require all remote CI jobs to succeed.
4. Merge the candidate and verify CI again for the exact main commit.
5. Tag only that verified main commit.

```bash
set -euo pipefail
test -z "$(gofmt -l .)" || { gofmt -l .; exit 1; }
scripts/release/check-ci.sh ChrisMckerracher/cedar-go-wasm "$(git rev-parse HEAD)"
```

The release workflow downloads the exact tested target archives from main CI.
It packages each target's consumer source bundle and runs an independent consumer again.
The consumer enables cgo, uses isolated caches, and blocks Rust commands.
It exercises native authorization and real solver-backed analysis.

The gate rejects the wrong source, branch, event, status, conclusion, or job set.
A missing, skipped, failed, incomplete, duplicate, or unexpected job fails the gate.
Source identity, checksums, and build provenance cover the published files.

Worked example: `SHA256SUMS-linux_amd64` identifies the Linux amd64 source ZIP, native ZIP, source commit, and notices.

Knowledge check: Can a successful PR run replace successful main CI for a release tag? No.

## Lesson 4: Verify a downloaded release

Objective: Verify provenance and checksums before extraction.

1. Download the selected platform's source ZIP, native ZIP, source record, notices, and checksum file.
2. Keep every file named by the selected checksum file in one directory.
3. Verify the complete checksum file without skipping absent files.
4. Verify each archive's build attestation.
5. Extract only after verification succeeds.

```bash
sha256sum --check SHA256SUMS-linux_amd64
gh attestation verify cedar-go-wasm-linux_amd64-source.zip --repo ChrisMckerracher/cedar-go-wasm
gh attestation verify cedar-go-wasm-linux_amd64-native.zip --repo ChrisMckerracher/cedar-go-wasm
```

Use `linux_arm64` or `darwin_arm64` for the other supported targets.
The source bundle includes the exact native library, matching header, generated linker requirements, and notices.
Go module downloads do not include release attachments.

Worked example: A missing source record fails complete checksum verification.

Knowledge check: Does a checksum establish trusted provenance by itself? No. Verify the build attestation too.

## Audits

Weekly CI retains Go advisory checks, Rust advisories, dependency policy, license generation, and independent fixture checks.
Use approved pinned maintenance tools. A missing tool does not count as a successful check.
Historical Wasm maintenance evidence remains in [the archived record](history/wasm-maintenance.md).
