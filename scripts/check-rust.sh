#!/usr/bin/env bash
# Check native code and independent pinned fixtures without updating expectations.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo"
cargo fmt --manifest-path rust/Cargo.toml --all -- --check
cargo clippy --manifest-path rust/Cargo.toml --locked --profile native --workspace --all-targets -- -D warnings
cargo test --manifest-path rust/Cargo.toml --locked --profile native --workspace --all-targets
python3 -m unittest discover -s scripts/parity -p 'test_*.py'
python3 scripts/parity/run.py --check
(cd rust && cargo deny --all-features check && cargo audit --deny warnings)
scripts/third-party-licenses.sh
git diff --exit-code -- THIRD_PARTY_LICENSES.txt
