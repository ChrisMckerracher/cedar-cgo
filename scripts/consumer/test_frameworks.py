"""Check verified macOS framework records before extracting a consumer bundle."""

import json
import unittest

from bundle import checksums
from fixture import BundleCase, COMMIT, NATIVE_FILES, TARGETS, native_fixture
from native import ARTIFACT_FILES, generated_names

DARWIN = "aarch64-apple-darwin"
FLAGS = ["-liconv", "-framework", "CoreFoundation", "-lSystem", "-lc", "-lm", "-framework", "CoreFoundation", "-lc"]


class FrameworkBundleTests(BundleCase):
    def platform_bundle(self, target, flags):
        files = {name: data for name, data in self.files.items() if name not in NATIVE_FILES}
        native = native_fixture(COMMIT, files["internal/native/include/cedar.h"], target, flags)
        files.update(native)
        files["SHA256SUMS"] = checksums(native)
        return files

    def test_mac_framework_bundle_preserves_order_and_repeated_flags(self):
        files = self.platform_bundle(DARWIN, FLAGS)
        result = self.extract(files, target=DARWIN)
        self.assertEqual(result.returncode, 0, result.stderr)
        source = (self.directory / "out/cedar-go-wasm/internal/native/link_flags.go").read_text()
        self.assertIn("-lcgw_native " + " ".join(FLAGS) + "\n", source)
        self.assertIn("//go:build darwin && arm64 && cgo\n", source)

    def test_framework_errors_reach_linker_validation_before_extraction(self):
        cases = [
            ("x86_64-unknown-linux-gnu", ["-framework", "CoreFoundation"], "native frameworks require darwin_arm64"),
            ("aarch64-unknown-linux-gnu", ["-framework", "CoreFoundation"], "native frameworks require darwin_arm64"),
            (DARWIN, ["-lc", "-framework"], "native framework has no name"),
            (DARWIN, ["-framework", "../CoreFoundation"], "invalid native framework name"),
            (DARWIN, ["-framework", "CoreFoundation\nimport unsafe"], "invalid native framework name"),
            (DARWIN, ["-framework", "-lSystem"], "invalid native framework name"),
            (DARWIN, ["-framework", "-framework", "CoreFoundation"], "invalid native framework name"),
            (DARWIN, ["-framework", "CoreFoundation", "Foundation"], "invalid native linker requirement: Foundation"),
            (DARWIN, ["-framework", ""], "invalid native framework name"),
        ]
        for target, flags, expected in cases:
            with self.subTest(target=target, flags=flags):
                files = self.platform_bundle(target, ["-lc"])
                platform = TARGETS[target]
                prefix = f"internal/native/lib/{platform}/"
                manifest = json.loads(files[prefix + "manifest.json"])
                manifest["native_static_libs"] = flags
                files[prefix + "manifest.json"] = json.dumps(manifest).encode()
                artifact = {name: files["internal/native/link_flags.go" if name == "link_flags.go" else prefix + name] for name in ARTIFACT_FILES if name != "SHA256SUMS"}
                files[prefix + "SHA256SUMS"] = checksums(artifact)
                files["SHA256SUMS"] = checksums({name: files[name] for name in generated_names(platform)})
                result = self.extract(files, target=target)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)
                self.assertFalse((self.directory / "out").exists())


if __name__ == "__main__":
    unittest.main()
