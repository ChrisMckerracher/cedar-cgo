"""Check manifest generation from the linker flags reported by Rust."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from fixture import COMMIT, native_fixture
from native import ARTIFACT_FILES, TARGETS, verify_native
from test_frameworks import DARWIN, FLAGS

path = Path(__file__).resolve().parents[1] / "native/manifest.py"
spec = importlib.util.spec_from_file_location("native_manifest_generator", path)
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)


class NativeManifestGenerationTests(unittest.TestCase):
    def generate(self, target, flags):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        output = Path(directory.name)
        platform = TARGETS[target]
        prefix = f"internal/native/lib/{platform}/"
        fixture = native_fixture(COMMIT, b"native ABI 2 header\n", target)
        for name in ("libcgw_native.a", "cedar.h"):
            (output / name).write_bytes(fixture[prefix + name])
        (output / "build.log").write_text("note: native-static-libs: " + " ".join(flags) + "\n")
        generator.generate(str(output), COMMIT, target, "1.99.0")
        return output

    def test_rust_macos_linker_record_generates_a_verified_artifact(self):
        output = self.generate(DARWIN, FLAGS)
        manifest = json.loads((output / "manifest.json").read_bytes())
        self.assertEqual(manifest["native_static_libs"], FLAGS)
        source = (output / "link_flags.go").read_text()
        self.assertIn("-lcgw_native " + " ".join(FLAGS) + "\n", source)
        files = {f"internal/native/lib/darwin_arm64/{name}": (output / name).read_bytes() for name in ARTIFACT_FILES if name != "link_flags.go"}
        files["internal/native/link_flags.go"] = (output / "link_flags.go").read_bytes()
        files["internal/native/include/cedar.h"] = (output / "cedar.h").read_bytes()
        verify_native(files, COMMIT, DARWIN)

    def test_rust_linker_record_rejects_unsafe_framework_tokens(self):
        cases = [
            ("x86_64-unknown-linux-gnu", ["-framework", "CoreFoundation"], "native frameworks require darwin_arm64"),
            (DARWIN, ["-framework"], "native framework has no name"),
            (DARWIN, ["-framework", "../CoreFoundation"], "invalid native framework name"),
            (DARWIN, ["-framework", "-lSystem"], "invalid native framework name"),
            (DARWIN, ["-framework", "CoreFoundation", "Foundation"], "invalid native linker requirement: Foundation"),
        ]
        for target, flags, expected in cases:
            with self.subTest(target=target, flags=flags):
                with self.assertRaisesRegex(ValueError, expected):
                    self.generate(target, flags)


if __name__ == "__main__":
    unittest.main()
