"""Preserve the exact fuzz inventory, target locations, and minimum duration."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import run


class FuzzInventoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repository = Path(temporary.name)
        for target, package in run.TARGETS.items():
            path = self.repository / package / (target + "_test.go")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"func {target}(f *testing.F) {{}}\n")

    def test_exact_inventory_contains_25_targets(self):
        self.assertEqual(len(run.TARGETS), 25)
        self.assertEqual(run.discover(), run.TARGETS)
        self.assertEqual(run.discover(self.repository), run.TARGETS)

    def test_missing_extra_moved_and_duplicate_targets_fail(self):
        target = "FuzzAuthorize"
        source = self.repository / run.TARGETS[target] / (target + "_test.go")
        original = source.read_text()
        source.unlink()
        with self.assertRaisesRegex(ValueError, "inventory differs"):
            run.discover(self.repository)
        source.write_text(original + "func FuzzUnexpected(f *testing.F) {}\n")
        with self.assertRaisesRegex(ValueError, "inventory differs"):
            run.discover(self.repository)
        source.write_text(original)
        moved = self.repository / "cedar/moved/target_test.go"
        moved.parent.mkdir()
        source.rename(moved)
        with self.assertRaisesRegex(ValueError, "inventory differs"):
            run.discover(self.repository)
        source.write_text(original)
        with self.assertRaisesRegex(ValueError, "duplicate fuzz target"):
            run.discover(self.repository)

    def test_invalid_durations_and_options_fail_before_execution(self):
        arguments = [["--seconds", value] for value in ("59", "-1", "nan", "inf", "bad", "0.5m")]
        arguments += [["--workers", "0"], ["--unknown"]]
        for options in arguments:
            with self.subTest(options=options), patch.object(run.subprocess, "run") as execute:
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    run.main(options)
                execute.assert_not_called()

    def test_environment_inputs_preserve_duration_and_workers(self):
        for environment in ({"FUZZTIME": "1m", "FUZZWORKERS": "2"},
                            {"FUZZ_SECONDS": "60", "FUZZ_WORKERS": "2"}):
            with self.subTest(environment=environment), patch.dict(run.os.environ, environment, clear=True):
                with patch.object(run, "discover", return_value={"FuzzAuthorize": "cedar/integration"}):
                    with patch.object(run.subprocess, "run") as execute:
                        self.assertEqual(run.main([]), 0)
                        command = execute.call_args.args[0]
                        self.assertEqual(command[command.index("-fuzztime") + 1], "60s")
                        self.assertEqual(command[command.index("-parallel") + 1], "2")

    def test_list_checks_inventory_without_running_fuzz_targets(self):
        with patch.object(run.subprocess, "run") as execute:
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(run.main(["--list"]), 0)
            self.assertEqual(len(output.getvalue().splitlines()), 25)
            execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
