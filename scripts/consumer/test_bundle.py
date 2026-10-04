"""Test malformed bundle rejection through the extraction command."""

import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from bundle import MODULES, ROOT, checksums

COMMIT = "a" * 40


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        source = {"go.mod": b"module example.com/test\n", "go.sum": b"", "cedar/source.go": b"package cedar\n"}
        self.files = source | {"SOURCE_SHA256SUMS": checksums(source)}
        modules = {}
        for path in MODULES:
            modules[path] = b"\x00asm\x01\x00\x00\x00" if path.endswith(".wasm") else b"package example\n"
        self.files.update(modules)
        self.files["SHA256SUMS"] = checksums(modules)
        self.files["SOURCE_COMMIT"] = (COMMIT + "\n").encode()

    def extract(self, files, extra=None, expected=COMMIT):
        archive = self.directory / "bundle.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            for name, data in files.items():
                entry = zipfile.ZipInfo(ROOT + name)
                entry.create_system = 3
                entry.external_attr = (stat.S_IFREG | (0o755 if name.endswith(".sh") else 0o644)) << 16
                bundle.writestr(entry, data)
            if extra:
                bundle.writestr(*extra)
        return subprocess.run(
            [sys.executable, str(Path(__file__).with_name("extract.py")), str(archive), expected, str(self.directory / "out")],
            capture_output=True, text=True,
        )

    def test_complete_bundle_extracts(self):
        self.files["scripts/build.sh"] = b"#!/bin/sh\n"
        source = {name: data for name, data in self.files.items() if name not in MODULES and name not in ("SOURCE_COMMIT", "SHA256SUMS", "SOURCE_SHA256SUMS")}
        self.files["SOURCE_SHA256SUMS"] = checksums(source)
        result = self.extract(self.files)
        self.assertEqual(result.returncode, 0, result.stderr)
        for name, data in self.files.items():
            self.assertEqual((self.directory / "out" / ROOT / name).read_bytes(), data)
        self.assertEqual((self.directory / "out" / ROOT / "scripts/build.sh").stat().st_mode & 0o777, 0o755)

    def test_malformed_bundles_fail_before_extraction(self):
        cases = [
            ("module checksum", self.files | {MODULES[0]: b"changed"}),
            ("source checksum", self.files | {"cedar/source.go": b"changed"}),
            ("source commit", self.files | {"SOURCE_COMMIT": b"b" * 40 + b"\n"}),
            ("source manifest", self.files | {"SOURCE_SHA256SUMS": b""}),
            ("module manifest", self.files | {"SHA256SUMS": b""}),
            ("missing module", {name: data for name, data in self.files.items() if name != MODULES[0]}),
            ("missing source", {name: data for name, data in self.files.items() if name != "cedar/source.go"}),
            ("extra source", self.files | {"extra.go": b"package extra\n"}),
        ]
        for name, files in cases:
            with self.subTest(name=name):
                result = self.extract(files)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.directory / "out").exists())

    def test_unsafe_members_fail_before_extraction(self):
        link = zipfile.ZipInfo(ROOT + "link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        cases = [
            (ROOT + "../outside", b"outside"),
            ("/outside", b"outside"),
            (ROOT + "cedar/../../outside", b"outside"),
            (ROOT + "cedar\\outside", b"outside"),
            (ROOT + "go.mod", b"duplicate"),
            (link, b"../../outside"),
        ]
        for entry in cases:
            with self.subTest(entry=str(entry[0])):
                result = self.extract(self.files, extra=entry)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.directory / "out").exists())
                self.assertFalse((self.directory / "outside").exists())

    def test_expected_commit_is_full_lowercase_hexadecimal(self):
        for commit in ("a" * 39, "z" * 40, "A" * 40):
            with self.subTest(commit=commit):
                result = self.extract(self.files, expected=commit)
                self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
