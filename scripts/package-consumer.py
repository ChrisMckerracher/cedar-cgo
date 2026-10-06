#!/usr/bin/env python3
"""Package the checked source commit with its validated native library."""

import copy
import io
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

from consumer.bundle import METADATA, ROOT, checksums, read_bundle
from consumer.native import ARTIFACT_FILES, generated_names
from native.source import committed_source
from artifact_verifier import HEADER, run
import json


def package(artifact, commit, output):
    repo = Path(__file__).resolve().parent.parent
    artifact = Path(artifact).resolve()
    output = Path(output).resolve()
    commit = committed_source(repo, commit)
    manifest = json.loads((artifact / "manifest.json").read_text())
    platform, target = manifest["platform"], manifest["target"]
    native = generated_names(platform)
    run(artifact, commit, target, HEADER)
    archive = subprocess.check_output(["git", "archive", "--format=zip", commit], cwd=repo)
    with zipfile.ZipFile(io.BytesIO(archive)) as source:
        entries = {entry.filename: copy.copy(entry) for entry in source.infolist()}
        files = {entry.filename: source.read(entry) for entry in source.infolist() if not entry.is_dir()}
    if (METADATA | set(native)) & set(files):
        raise ValueError("generated native files and bundle metadata must be absent from the source commit")
    files["SOURCE_SHA256SUMS"] = checksums(files)
    prefix = f"internal/native/lib/{platform}/"
    for name in ARTIFACT_FILES:
        if name == "link_flags.go":
            continue
        files[prefix + name] = (artifact / name).read_bytes()
    files["internal/native/link_flags.go"] = (artifact / "link_flags.go").read_bytes()
    files["SHA256SUMS"] = checksums({name: files[name] for name in native})
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
    read_bundle(output, commit, target)
    print(f"Consumer source bundle: {output}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit("usage: package-consumer.py ARTIFACT_DIR SOURCE_COMMIT OUTPUT_ZIP")
    try:
        package(*sys.argv[1:])
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError, zipfile.BadZipFile) as error:
        sys.exit(f"consumer package failed: {error}")
