"""Preserve read-only defaults, independent commands, and explicit update behavior."""

import contextlib
import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import run


class ParityRunnerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repository = Path(temporary.name)
        (self.repository / "rust").mkdir()
        self.expected = self.repository / "expected.json"
        self.expected.write_bytes(b"expected\n")
        self.case = {"bin": "independent_oracle", "expected": "expected.json"}

    def test_invalid_arguments_fail_before_running_an_oracle(self):
        for arguments in (["--write"], ["unknown"], ["--update", "--check"], ["--unknown"]):
            with self.subTest(arguments=arguments), patch.object(run, "run_case") as execute:
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    run.main(arguments)
                execute.assert_not_called()

    def test_default_and_explicit_check_preserve_expectations(self):
        for arguments in (["partial"], ["partial", "--check"]):
            with self.subTest(arguments=arguments), patch.object(run, "run_case") as execute:
                self.assertEqual(run.main(arguments), 0)
                execute.assert_called_once_with("partial", run.CASES["partial"], False)
        with patch.object(run.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"different\n")):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaisesRegex(ValueError, "fixtures differ"):
                run.run_case("test", self.case, repository=self.repository)
        self.assertEqual(self.expected.read_bytes(), b"expected\n")

    def test_only_explicit_update_writes_successful_output(self):
        with patch.object(run.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"new\n")):
            run.run_case("test", self.case, update=True, repository=self.repository)
        self.assertEqual(self.expected.read_bytes(), b"new\n")
        with patch.object(run.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "cargo")):
            with self.assertRaises(subprocess.CalledProcessError):
                run.run_case("test", self.case, update=True, repository=self.repository)
        self.assertEqual(self.expected.read_bytes(), b"new\n")

    def test_catalog_preserves_all_oracles_and_go_followups(self):
        self.assertEqual(len(run.CASES), 18)
        self.assertEqual(len({case["bin"] for case in run.CASES.values()}), 18)
        for name in ("templates", "batched"):
            with self.subTest(name=name), patch.object(run.subprocess, "run") as execute:
                execute.return_value = subprocess.CompletedProcess([], 0, b"expected\n")
                case = run.CASES[name] | {"expected": "expected.json"}
                if "input" in case:
                    source = self.repository / case["input"]
                    source.parent.mkdir(parents=True)
                    source.write_bytes(b"input")
                run.run_case(name, case, repository=self.repository)
                calls = execute.call_args_list
                self.assertIn(case["bin"], calls[0].args[0])
                self.assertEqual(calls[1].args[0], ["go", "test", "-count=1", "-run", *case["go"]])

    def test_catalog_paths_exist_in_the_repository(self):
        for name, case in run.CASES.items():
            paths = [case[key] for key in ("input", "expected") if key in case] + case.get("args", [])
            for path in paths:
                with self.subTest(name=name, path=path):
                    self.assertTrue((run.REPOSITORY / path).is_file())

    def test_formatter_retains_internal_assertions_in_both_modes(self):
        for update, option in ((False, "--check"), (True, "--write")):
            with self.subTest(update=update), patch.object(run.subprocess, "run") as execute:
                run.run_case("format", run.CASES["format"], update, self.repository)
                self.assertEqual(execute.call_args.args[0][-2:], ["--", option])

    def test_solver_requirement_fails_before_any_oracle_runs(self):
        with patch.dict(run.os.environ, {}, clear=True), patch.object(run, "run_case") as execute:
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                run.main([])
            execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
