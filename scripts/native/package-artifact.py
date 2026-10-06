#!/usr/bin/env python3
"""Package the verified target artifact without changing its files."""

import json
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from artifact_verifier import HEADER, run


def package(directory, destination):
    artifact = Path(directory).resolve()
    manifest = json.loads((artifact / "manifest.json").read_text())
    run(artifact, manifest["source_commit"], manifest["target"], HEADER)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(artifact.iterdir()):
            entry = zipfile.ZipInfo(path.name, (1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, path.read_bytes())


if __name__ == "__main__":
    package(*sys.argv[1:])
