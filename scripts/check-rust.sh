#!/usr/bin/env bash
# Check native code and independent pinned fixtures without updating expectations.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo"
scripts/vendor-symcc.sh
cargo fmt --manifest-path rust/Cargo.toml --all -- --check
cargo clippy --manifest-path rust/Cargo.toml --locked --profile native --workspace --all-targets -- -D warnings
cargo test --manifest-path rust/Cargo.toml --locked --profile native --workspace --all-targets
for check in slicing-fixtures policies-parity partial-fixtures format-parity validation-depth-parity expression-parity literal-parity applicability-parity diagnostics-parity schema-parity entity-store-parity utility-parity queries-parity pst-parity source-token-parity analysis-queries-parity; do
 scripts/"$check".sh --check
done
scripts/check-template-parity.sh
scripts/check-batched-parity.sh
(cd rust && cargo deny --all-features check && cargo audit --deny warnings)
scripts/third-party-licenses.sh
git diff --exit-code -- THIRD_PARTY_LICENSES.txt
