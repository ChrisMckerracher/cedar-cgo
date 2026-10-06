"""Stage native files for the trusted Go artifact verifier."""

import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from artifact_verifier import HEADER, run, targets
ARTIFACT_FILES = ("SOURCE_COMMIT", "cedar.h", "libcgw_native.a", "link_flags.go", "manifest.json", "SHA256SUMS")


def generated_names(platform):
    return tuple(f"internal/native/lib/{platform}/{name}" for name in ARTIFACT_FILES if name != "link_flags.go") + ("internal/native/link_flags.go",)


def verify_native(files, commit, expected_target=None):
    manifests = [name for name in files if re.fullmatch(r"internal/native/lib/[^/]+/manifest.json", name)]
    if len(manifests) != 1:
        raise ValueError("bundle requires exactly one native platform artifact")
    prefix = manifests[0].removesuffix("manifest.json")
    platform = prefix.split("/")[-2]
    platforms = targets()
    target = expected_target or next((target for target, name in platforms.items() if name == platform), "unsupported")
    if platforms.get(target) != platform:
        raise ValueError("native artifact path does not match target")
    names = generated_names(platform)
    if any(name.startswith("internal/native/lib/") and name not in names for name in files):
        raise ValueError("unexpected native artifact file")
    if files.get("internal/native/include/cedar.h") != HEADER.read_bytes():
        raise ValueError("bundle header does not match trusted source header")
    with tempfile.TemporaryDirectory(prefix="cedar-native-artifact-") as directory:
        for name in ARTIFACT_FILES:
            source = "internal/native/link_flags.go" if name == "link_flags.go" else prefix + name
            if source not in files:
                raise ValueError(f"missing bundle file: {source}")
            (Path(directory) / name).write_bytes(files[source])
        run(directory, commit, target, HEADER)
    return names
