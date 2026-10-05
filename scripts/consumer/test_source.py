"""Check commit-bound source guards in disposable Git repositories."""

import importlib.util
import io
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

path = Path(__file__).resolve().parents[1] / "native/source.py"
spec = importlib.util.spec_from_file_location("committed_source", path)
source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source)


class CommittedSourceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repository = Path(temporary.name)
        self.git("init", "--quiet")
        self.git("config", "user.name", "Source fixture")
        self.git("config", "user.email", "source-fixture@example.invalid")
        self.original = b"pub fn fixture() {}\n"
        (self.repository / "lib.rs").write_bytes(self.original)
        (self.repository / ".gitignore").write_text("target/\n")
        self.git("add", "lib.rs", ".gitignore")
        self.git("commit", "--quiet", "-m", "Source fixture")
        self.commit = self.git("rev-parse", "HEAD").strip()

    def git(self, *arguments):
        return subprocess.check_output(
            ["git", *arguments], cwd=self.repository, text=True,
            stderr=subprocess.PIPE,
        )

    def test_clean_committed_source_allows_ignored_build_outputs(self):
        target = self.repository / "target"
        target.mkdir()
        (target / "library.a").write_bytes(b"generated")
        self.assertEqual(source.committed_source(self.repository), self.commit)
        self.assertEqual(source.committed_source(self.repository, self.commit), self.commit)

    def test_dirty_tracked_source_is_rejected_before_and_after_staging(self):
        (self.repository / "lib.rs").write_text("pub fn changed() {}\n")
        for staged in (False, True):
            with self.subTest(staged=staged):
                if staged:
                    self.git("add", "lib.rs")
                with self.assertRaisesRegex(ValueError, "committed source"):
                    source.committed_source(self.repository)

    def test_untracked_build_script_is_rejected(self):
        (self.repository / "build.rs").write_text("fn main() {}\n")
        with self.assertRaisesRegex(ValueError, "untracked files"):
            source.committed_source(self.repository)

    def test_wrong_expected_commit_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "does not match HEAD"):
            source.committed_source(self.repository, "b" * 40)

    def test_verified_commit_archive_keeps_source_after_caller_edits(self):
        commit = source.committed_source(self.repository)
        (self.repository / "lib.rs").write_text("pub fn later_edit() {}\n")
        archive = subprocess.check_output(
            ["git", "archive", commit], cwd=self.repository,
        )
        with tarfile.open(fileobj=io.BytesIO(archive)) as snapshot:
            self.assertEqual(snapshot.extractfile("lib.rs").read(), self.original)


if __name__ == "__main__":
    unittest.main()
