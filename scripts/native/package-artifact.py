#!/usr/bin/env python3
"""Package the verified target artifact without changing its files."""

import json
import subprocess
import sys
import zipfile
from pathlib import Path


def package(directory, destination):
    repo = Path(__file__).resolve().parents[2]
    artifact = Path(directory).resolve()
    manifest = json.loads((artifact / "manifest.json").read_text())
    subprocess.run(["go", "run", "./cmd/verify-native-artifact", str(artifact),
                    manifest["source_commit"], manifest["target"],
                    str(repo / "internal/native/include/cedar.h")], cwd=repo, check=True)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(artifact.iterdir()):
            entry = zipfile.ZipInfo(path.name, (1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, path.read_bytes())


if __name__ == "__main__":
    package(*sys.argv[1:])
