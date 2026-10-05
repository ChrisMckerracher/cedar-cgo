"""Check release source identity before artifact download."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_jobs import jobs


class CommitGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        directory = Path(self.temporary.name)
        executable = directory / "gh"
        executable.write_text(
            '#!/usr/bin/env python3\nimport os, sys\n'
            'print(os.environ["MOCK_JOBS"] if "jobs?" in " ".join(sys.argv) else os.environ["MOCK_RUN"])\n'
        )
        executable.chmod(0o755)
        self.repo = Path(__file__).resolve().parents[2]
        self.commit = "a" * 40
        self.environment = os.environ | {
            "PATH": str(directory) + os.pathsep + os.environ["PATH"],
            "MOCK_JOBS": "\n".join(name + "\tcompleted\tsuccess" for name in sorted(jobs.EXPECTED)),
        }

    def run_gate(self, record):
        return subprocess.run(
            ["bash", "scripts/release/check-ci.sh", "owner/repository", self.commit],
            cwd=self.repo, env=self.environment | {"MOCK_RUN": record},
            text=True, capture_output=True, check=False,
        )

    def test_exact_successful_main_commit(self):
        result = self.run_gate(f"42\t{self.commit}\tmain\tpush\tcompleted\tsuccess")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "42")

    def test_wrong_source_branch_event_and_incomplete_results(self):
        valid = ["42", self.commit, "main", "push", "completed", "success"]
        for field, replacement in [(1, "b" * 40), (2, "feature"), (3, "pull_request"),
                                   (4, "in_progress"), (5, "failure"), (5, "skipped")]:
            with self.subTest(field=field, replacement=replacement):
                record = valid.copy()
                record[field] = replacement
                result = self.run_gate("\t".join(record))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
        self.assertNotEqual(self.run_gate("").returncode, 0)


if __name__ == "__main__":
    unittest.main()
