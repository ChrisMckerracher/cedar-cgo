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
