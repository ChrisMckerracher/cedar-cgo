#!/usr/bin/env python3
"""Build a temporary Wasm consumer from the controlled native benchmark inputs."""
import pathlib
import re
import sys

repo, baseline, output = map(pathlib.Path, sys.argv[1:])
output.mkdir(parents=True, exist_ok=True)
module = "github.com/ChrisMckerracher/cedar-cgo"
manifest = (baseline / "go.mod").read_text()
baseline_module = re.search(r"^module (\S+)$", manifest, re.MULTILINE).group(1)
manifest = manifest.replace(f"module {baseline_module}", "module example.invalid/cedar-migration-wasm-performance", 1)
manifest += f"\nrequire {baseline_module} v0.0.0\nreplace {baseline_module} => {baseline}\n"
(output / "go.mod").write_text(manifest)
(output / "go.sum").write_bytes((baseline / "go.sum").read_bytes())
packages = ["authorization", "request", "entity", "uid", "policy", "schema", "batched"]
for name in ["authorization_test.go", "callback_test.go", "analysis_test.go"]:
    source = (repo / "internal/verification/performance" / name).read_text()
    for package in packages:
        source = re.sub(rf'\n\s*"{re.escape(module)}/cedar/[^"\n]*\b{package}"', "", source)
        source = re.sub(rf"\b{package}\.", "cedar.", source)
    if f'"{module}/cedar"' not in source:
        source = source.replace("import (", f'import (\n "{module}/cedar"', 1)
    source = source.replace(f'\n\t"{module}/analysis/solver"', "")
    source = re.sub(r"\bsolver\.", "analysis.", source)
    source = source.replace(", cedar.WithMaxConcurrentCalls(2)", "")
    source = source.replace(".Batched().AuthorizeBatched", ".AuthorizeBatched")
    source = source.replace(module, baseline_module)
    (output / name).write_text(source)
