"""Validate source bundles before extracting files for consumer compilation."""

import hashlib
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath

ROOT = "cedar-go-wasm/"
MODULES = tuple(
    f"internal/modules/{name}/{file}"
    for name in ("analysis", "authorizer")
    for file in (f"{name}.wasm", "sha256.go")
)
METADATA = {"SOURCE_COMMIT", "SHA256SUMS", "SOURCE_SHA256SUMS"}


def checksums(files):
    return "".join(
        f"{hashlib.sha256(files[name]).hexdigest()}  {name}\n"
        for name in sorted(files)
    ).encode()


def verify_manifest(data, files, required):
    if not required:
        raise ValueError("source manifest is empty")
    expected = checksums({name: files[name] for name in required})
    if data != expected:
        raise ValueError("bundle checksums or manifest paths do not match")


def read_bundle(path, expected_commit):
    if not re.fullmatch(r"[0-9a-f]{40}", expected_commit):
        raise ValueError("source commit must contain 40 lowercase hexadecimal characters")
    files = {}
    seen = set()
    with zipfile.ZipFile(path) as archive:
        for entry in archive.infolist():
            name = entry.filename
            parsed = PurePosixPath(name)
            mode = stat.S_IFMT(entry.external_attr >> 16)
            if (
                not name.startswith(ROOT)
                or "\\" in name
                or any(part in (".", "..") for part in parsed.parts)
                or parsed.as_posix() != name.rstrip("/")
                or mode not in (0, stat.S_IFREG, stat.S_IFDIR)
                or name in seen
            ):
                raise ValueError(f"unsafe or duplicate bundle entry: {name}")
            seen.add(name)
            if not entry.is_dir():
                files[name[len(ROOT):]] = archive.read(entry)
    for name in METADATA | set(MODULES) | {"go.mod", "go.sum"}:
        if name not in files:
            raise ValueError(f"missing bundle file: {name}")
    if files["SOURCE_COMMIT"] != (expected_commit + "\n").encode():
        raise ValueError("bundle source commit does not match")
    verify_manifest(files["SHA256SUMS"], files, set(MODULES))
    source = set(files) - METADATA - set(MODULES)
    verify_manifest(files["SOURCE_SHA256SUMS"], files, source)
    return files


def extract_bundle(path, expected_commit, destination):
    files = read_bundle(path, expected_commit)
    with zipfile.ZipFile(path) as archive:
        modes = {entry.filename[len(ROOT):]: (entry.external_attr >> 16) & 0o777 for entry in archive.infolist()}
    root = Path(destination) / ROOT
    for name, data in files.items():
        output = root / name
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(data)
        if modes[name]:
            output.chmod(modes[name])
    return root
