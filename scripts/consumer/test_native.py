"""Reject native identity changes before source-bundle extraction."""
import json
import unittest
from bundle import checksums
from fixture import BundleCase, NATIVE_FILES, link_source, sha
from native import ARTIFACT_FILES


class NativeBundleTests(BundleCase):
    def test_consumer_rejects_an_artifact_for_another_native_target(self):
        result = self.extract(self.files, target="aarch64-unknown-linux-gnu")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.directory / "out").exists())

    def test_artifact_platform_path_matches_expected_target(self):
        files = {name.replace("internal/native/lib/linux_amd64/", "internal/native/lib/linux_arm64/"): data for name, data in self.files.items()}
        from native import generated_names
        files["SHA256SUMS"] = checksums({name: files[name] for name in generated_names("linux_arm64")})
        result = self.extract(files, target="x86_64-unknown-linux-gnu")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.directory / "out").exists())

    def test_native_identity_changes_fail_before_extraction(self):
        prefix = "internal/native/lib/linux_amd64/"
        coff = (0x8664).to_bytes(2, "little") + bytes(18)
        member = f"{'foreign.o/':<16}{0:<12}{0:<6}{0:<6}{0o644:<8o}{len(coff):<10}`\n".encode() + coff
        mutations = {
            "ABI": lambda m, f: m.update(abi=1),
            "target": lambda m, f: m.update(target="aarch64-unknown-linux-gnu"),
            "source": lambda m, f: m.update(source_commit="b" * 40),
            "panic": lambda m, f: m.update(panic="abort"),
            "Cedar": lambda m, f: m.update(cedar="0.0.0"),
            "toolchain": lambda m, f: m.update(toolchain="1.0.0"),
            "unknown field": lambda m, f: m.update(untrusted=True),
            "linker injection": lambda m, f: m.update(native_static_libs=["-L/tmp/untrusted"]),
            "header": lambda m, f: f.update({prefix + "cedar.h": b"wrong header"}),
            "archive": lambda m, f: f.update({prefix + "libcgw_native.a": b"not an archive"}),
            "stale archive digest": lambda m, f: f.update({prefix + "libcgw_native.a": f[prefix + "libcgw_native.a"][:-1] + b"\x01"}),
            "mixed COFF": lambda m, f: f.update({prefix + "libcgw_native.a": f[prefix + "libcgw_native.a"] + member}),
            "object target": lambda m, f: f.update({prefix + "libcgw_native.a": f[prefix + "libcgw_native.a"][:86] + (183).to_bytes(2, "little") + f[prefix + "libcgw_native.a"][88:]}),
            "generated linker source": lambda m, f: f.update({"internal/native/link_flags.go": b"package native\nfunc init() {}\n"}),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                files = self.files.copy()
                manifest = json.loads(files[prefix + "manifest.json"])
                mutate(manifest, files)
                if name in ("archive", "mixed COFF", "object target"):
                    files["internal/native/link_flags.go"] = link_source(
                        manifest["platform"], manifest["native_static_libs"], sha(files[prefix + "libcgw_native.a"]),
                    )
                manifest["files"] = {entry: sha(files["internal/native/link_flags.go" if entry == "link_flags.go" else prefix + entry]) for entry in ("cedar.h", "libcgw_native.a", "link_flags.go")}
                files[prefix + "manifest.json"] = json.dumps(manifest).encode()
                files[prefix + "SHA256SUMS"] = checksums({entry: files["internal/native/link_flags.go" if entry == "link_flags.go" else prefix + entry] for entry in ARTIFACT_FILES if entry != "SHA256SUMS"})
                files["SHA256SUMS"] = checksums({entry: files[entry] for entry in NATIVE_FILES})
                result = self.extract(files)
                self.assertNotEqual(result.returncode, 0)
                expected_errors = {
                    "archive": "native library is not an archive",
                    "mixed COFF": "native archive object target does not match",
                    "object target": "native archive object target does not match",
                    "stale archive digest": "generated linker source does not match",
                }
                if name in expected_errors:
                    self.assertIn(expected_errors[name], result.stderr)
                self.assertFalse((self.directory / "out").exists())

    def test_native_artifact_rejects_extra_files_and_duplicate_metadata(self):
        prefix = "internal/native/lib/linux_amd64/"
        for files in [
            self.files | {prefix + "other.a": b"extra"},
            self.files | {prefix + "manifest.json": b'{"abi":2,"abi":2}'},
            self.files | {"internal/native/lib/linux_arm64/manifest.json": b"{}"},
        ]:
            with self.subTest(files=sorted(set(files) - set(self.files))):
                result = self.extract(files)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.directory / "out").exists())

    def test_matching_untrusted_headers_fail_before_extraction(self):
        prefix = "internal/native/lib/linux_amd64/"
        files = self.files | {prefix + "cedar.h": b"untrusted header", "internal/native/include/cedar.h": b"untrusted header"}
        manifest = json.loads(files[prefix + "manifest.json"])
        manifest["files"]["cedar.h"] = sha(files[prefix + "cedar.h"])
        files[prefix + "manifest.json"] = json.dumps(manifest).encode()
        files[prefix + "SHA256SUMS"] = checksums({entry: files["internal/native/link_flags.go" if entry == "link_flags.go" else prefix + entry] for entry in ARTIFACT_FILES if entry != "SHA256SUMS"})
        files["SHA256SUMS"] = checksums({entry: files[entry] for entry in NATIVE_FILES})
        source = {name: data for name, data in files.items() if name not in NATIVE_FILES and name not in ("SOURCE_COMMIT", "SHA256SUMS", "SOURCE_SHA256SUMS")}
        files["SOURCE_SHA256SUMS"] = checksums(source)
        result = self.extract(files)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("trusted source header", result.stderr)
        self.assertFalse((self.directory / "out").exists())


if __name__ == "__main__":
    unittest.main()
