"""Build a native archive fixture for source-bundle rejection tests."""
import json
from native import ARTIFACT_FILES, generated_names, link_source, sha


def native_fixture(commit, header):
    body = bytearray(64)
    body[:6] = b"\x7fELF\x02\x01"
    body[18:20] = (62).to_bytes(2, "little")
    member = f"{'test.o/':16}{0:<12}{0:<6}{0:<6}{0o644:<8o}{len(body):<10}`\n".encode()
    artifact = {
        "libcgw_native.a": b"!<arch>\n" + member + body,
        "cedar.h": header,
        "link_flags.go": link_source("linux_amd64", ["-lc"]),
        "SOURCE_COMMIT": (commit + "\n").encode(),
    }
    manifest = {
        "abi": 2, "source_commit": commit, "target": "x86_64-unknown-linux-gnu", "platform": "linux_amd64",
        "cedar": "4.13.0", "symcc": "0.7.0", "toolchain": "1.99.0", "profile": "native", "panic": "unwind",
        "native_static_libs": ["-lc"], "files": {name: sha(artifact[name]) for name in ("libcgw_native.a", "cedar.h", "link_flags.go")},
    }
    artifact["manifest.json"] = json.dumps(manifest).encode()
    artifact["SHA256SUMS"] = "".join(f"{sha(artifact[name])}  {name}\n" for name in sorted(artifact)).encode()
    result = {f"internal/native/lib/linux_amd64/{name}": artifact[name] for name in ARTIFACT_FILES if name != "link_flags.go"}
    result["internal/native/link_flags.go"] = artifact["link_flags.go"]
    assert set(result) == set(generated_names("linux_amd64"))
    return result

import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from bundle import ROOT, checksums

COMMIT = "a" * 40
NATIVE_FILES = generated_names("linux_amd64")


class BundleCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        source = {"go.mod": b"module example.com/test\n", "go.sum": b"", "cedar/source.go": b"package cedar\n", "internal/native/include/cedar.h": b"native ABI 2 header\n"}
        native = native_fixture(COMMIT, source["internal/native/include/cedar.h"])
        self.files = source | native | {
            "SOURCE_SHA256SUMS": checksums(source), "SHA256SUMS": checksums(native),
            "SOURCE_COMMIT": (COMMIT + "\n").encode(),
        }

    def extract(self, files, extra=None, expected=COMMIT, target=None):
        archive = self.directory / "bundle.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            for name, data in files.items():
                entry = zipfile.ZipInfo(ROOT + name)
                entry.create_system = 3
                entry.external_attr = (stat.S_IFREG | (0o755 if name.endswith(".sh") else 0o644)) << 16
                bundle.writestr(entry, data)
            if extra:
                bundle.writestr(*extra)
        command = [sys.executable, str(Path(__file__).with_name("extract.py")), str(archive), expected, str(self.directory / "out")]
        if target:
            command.append(target)
        return subprocess.run(
            command,
            capture_output=True, text=True,
        )

