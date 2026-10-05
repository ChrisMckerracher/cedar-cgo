#!/usr/bin/env python3
"""Package the checked source commit with its validated embedded modules."""

import copy
import io
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

from consumer.bundle import METADATA, MODULES, ROOT, checksums, read_bundle


def package(artifact, commit, output):
    repo = Path(__file__).resolve().parent.parent
    artifact = Path(artifact).resolve()
    output = Path(output).resolve()
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    if head != commit:
        raise ValueError("package source commit does not match HEAD")
    subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=repo, check=True)
    subprocess.run(
        ["go", "run", "./cmd/verify-wasm-artifact", str(artifact), commit],
        cwd=repo, check=True,
    )
    archive = subprocess.check_output(["git", "archive", "--format=zip", "HEAD"], cwd=repo)
    with zipfile.ZipFile(io.BytesIO(archive)) as source:
        entries = {entry.filename: copy.copy(entry) for entry in source.infolist()}
        files = {entry.filename: source.read(entry) for entry in source.infolist() if not entry.is_dir()}
    if (METADATA | set(MODULES)) & set(files):
        raise ValueError("generated modules and bundle metadata must be absent from the source commit")
    files["SOURCE_SHA256SUMS"] = checksums(files)
    for name in MODULES:
        files[name] = (artifact / name.removeprefix("internal/modules/")).read_bytes()
    files["SHA256SUMS"] = checksums({name: files[name] for name in MODULES})
    files["SOURCE_COMMIT"] = (commit + "\n").encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for name in sorted(set(files) | set(entries)):
            entry = entries.get(name)
            if entry is None:
                entry = zipfile.ZipInfo(name, next(iter(entries.values())).date_time)
                entry.create_system = 3
                entry.external_attr = (stat.S_IFREG | 0o644) << 16
                entry.compress_type = zipfile.ZIP_DEFLATED
            entry.filename = ROOT + name
            bundle.writestr(entry, files.get(name, b""))
    read_bundle(output, commit)
    print(f"Consumer source bundle: {output}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit("usage: package-consumer.py ARTIFACT_DIR SOURCE_COMMIT OUTPUT_ZIP")
    try:
        package(*sys.argv[1:])
    except (OSError, ValueError, subprocess.CalledProcessError, zipfile.BadZipFile) as error:
        sys.exit(f"consumer package failed: {error}")
