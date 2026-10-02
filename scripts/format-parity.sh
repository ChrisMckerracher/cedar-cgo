#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo/rust"
cargo run --locked --release -p cgw-authorizer --example format_parity -- "${1:---check}"
