"""Test malformed bundle rejection through the extraction command."""

import stat
import unittest
import zipfile
from pathlib import Path

from bundle import ROOT, checksums
from fixture import BundleCase, COMMIT, NATIVE_FILES



class BundleTests(BundleCase):
    def test_complete_bundle_extracts(self):
        self.files["scripts/build.sh"] = b"#!/bin/sh\n"
        source = {name: data for name, data in self.files.items() if name not in NATIVE_FILES and name not in ("SOURCE_COMMIT", "SHA256SUMS", "SOURCE_SHA256SUMS")}
        self.files["SOURCE_SHA256SUMS"] = checksums(source)
        result = self.extract(self.files)
        self.assertEqual(result.returncode, 0, result.stderr)
        for name, data in self.files.items():
            self.assertEqual((self.directory / "out" / ROOT / name).read_bytes(), data)
        self.assertEqual((self.directory / "out" / ROOT / "scripts/build.sh").stat().st_mode & 0o777, 0o755)

    def test_malformed_bundles_fail_before_extraction(self):
        cases = [
            ("native checksum", self.files | {NATIVE_FILES[0]: b"changed"}),
            ("source checksum", self.files | {"cedar/source.go": b"changed"}),
            ("source commit", self.files | {"SOURCE_COMMIT": b"b" * 40 + b"\n"}),
            ("source manifest", self.files | {"SOURCE_SHA256SUMS": b""}),
            ("native manifest", self.files | {"SHA256SUMS": b""}),
            ("missing native file", {name: data for name, data in self.files.items() if name != NATIVE_FILES[0]}),
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
