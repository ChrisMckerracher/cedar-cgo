#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo/rust"
cargo run --locked --release -p cgw-verification --bin format_parity -- "${1:---check}"
