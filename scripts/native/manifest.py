"""Bind native artifacts to their source, target, header, and build inputs."""

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from native_linker import link_source

TARGETS = {
    "x86_64-unknown-linux-gnu": "linux_amd64",
    "aarch64-unknown-linux-gnu": "linux_arm64",
    "aarch64-apple-darwin": "darwin_arm64",
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def generate(directory, commit, target, toolchain):
    platform = TARGETS[target]
    output = Path(directory)
    matches = re.findall(r"native-static-libs: (.+)", (output / "build.log").read_text())
    if not matches:
        raise ValueError("Rust did not report native linker requirements")
    flags = matches[-1].split()
    library_digest = sha((output / "libcgw_native.a").read_bytes())
    (output / "link_flags.go").write_bytes(link_source(platform, flags, library_digest))
    files = ("libcgw_native.a", "cedar.h", "link_flags.go")
    manifest = {
        "abi": 2, "source_commit": commit, "target": target, "platform": platform,
        "cedar": "4.13.0", "symcc": "0.7.0", "toolchain": toolchain,
        "profile": "native", "panic": "unwind", "native_static_libs": flags,
        "files": {name: sha((output / name).read_bytes()) for name in files},
    }
    (output / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    (output / "SOURCE_COMMIT").write_text(commit + "\n")
    names = sorted((*files, "manifest.json", "SOURCE_COMMIT"))
    (output / "SHA256SUMS").write_text("".join(
        f"{sha((output / name).read_bytes())}  {name}\n" for name in names
    ))


if __name__ == "__main__":
    generate(*sys.argv[1:])
