#!/usr/bin/env python3
"""Hash the source, inputs, and controls used by migration measurements."""
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
files = {root / name for name in ["go.mod", "go.sum", "rust/Cargo.toml", "rust/Cargo.lock", "internal/native/include/cedar.h"]}
for directory in ["cedar", "analysis", "internal"]:
    for path in (root / directory).rglob("*.go"):
        if not path.name.endswith("_test.go") or "verification/performance" in str(path):
            files.add(path)
for path in (root / "rust/crates").rglob("*"):
    if path.is_file() and (path.suffix == ".rs" or path.name == "Cargo.toml"):
        files.add(path)
for directory in ["testdata/joy", "scripts/performance"]:
    files.update(path for path in (root / directory).rglob("*") if path.is_file() and path.suffix != ".pyc")
files.add(root / "scripts/measure-native-performance.sh")
entries = {
    str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
    for path in sorted(files) if path.is_file()
}
digest = hashlib.sha256(json.dumps(entries, sort_keys=True).encode()).hexdigest()
if len(sys.argv) == 3:
    pathlib.Path(sys.argv[2]).write_text(json.dumps({"digest": digest, "files": entries}, indent=2) + "\n")
print(digest)
