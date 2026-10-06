"""Exercise the exact-release CI job gate."""

import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("verify_jobs", Path(__file__).with_name("verify-jobs.py"))
jobs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jobs)


class JobGateTests(unittest.TestCase):
    def setUp(self):
        self.rows = [name + "\tcompleted\tsuccess" for name in sorted(jobs.EXPECTED)]

    def test_complete_run(self):
        jobs.verify(self.rows)

    def test_latest_patch_on_all_three_platforms(self):
        expected = {f"Go tests ({platform}, Go 1.27.1)" for platform in ("linux_amd64", "linux_arm64", "darwin_arm64")}
        self.assertEqual({name for name in jobs.EXPECTED if name.startswith("Go tests")}, expected)
        for version in ("1.26.x", "1.27.x", "1.27.0"):
            with self.subTest(version=version):
                rows = [row.replace("Go 1.27.1", f"Go {version}") for row in self.rows]
                with self.assertRaises(ValueError):
                    jobs.verify(rows)

    def test_missing_duplicate_skipped_failed_and_active_jobs(self):
        cases = [self.rows[:-1], self.rows + self.rows[:1], [],
                 self.rows + ["unknown\tcompleted\tsuccess"]]
        for status, conclusion in (("completed", "skipped"), ("completed", "failure"),
                                   ("in_progress", "success"), ("completed", "cancelled")):
            cases.append(self.rows[:-1] + [self.rows[-1].split("\t")[0] + f"\t{status}\t{conclusion}"])
        for rows in cases:
            with self.subTest(rows=rows):
                with self.assertRaises(ValueError):
                    jobs.verify(rows)


if __name__ == "__main__":
    unittest.main()
