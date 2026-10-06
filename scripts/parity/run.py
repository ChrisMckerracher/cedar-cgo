#!/usr/bin/env python3
"""Compare independent Cedar fixtures, or update them with explicit authorization."""

import argparse
import contextlib
import difflib
import json
import os
import subprocess
import sys
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[2]
CASES = json.loads(Path(__file__).with_name("cases.json").read_text())


def run_case(name, case, update=False, repository=REPOSITORY):
    command = ["cargo", "run", "--manifest-path", str(repository / "rust/Cargo.toml"),
               "--locked", "--release", "-p", "cgw-verification", "--bin", case["bin"]]
    if case.get("offline"):
        command.append("--offline")
    arguments = [str(repository / path) for path in case.get("args", [])]
    if case.get("managed"):
        arguments.append("--write" if update else "--check")
    if arguments:
        command.extend(["--", *arguments])
    source = (repository / case["input"]).open("rb") if "input" in case else contextlib.nullcontext(None)
    with source as stdin:
        result = subprocess.run(command, cwd=repository / "rust", stdin=stdin, stdout=subprocess.PIPE, check=True)
    if not case.get("managed"):
        expected = repository / case["expected"]
        if update:
            expected.write_bytes(result.stdout)
        elif expected.read_bytes() != result.stdout:
            diff = difflib.unified_diff(expected.read_text().splitlines(True), result.stdout.decode().splitlines(True),
                                        fromfile=str(expected), tofile=f"{name} oracle")
            sys.stderr.writelines(diff)
            raise ValueError(f"{name} fixtures differ")
    if "go" in case:
        pattern, package = case["go"]
        subprocess.run(["go", "test", "-count=1", "-run", pattern, package], cwd=repository, check=True)


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", nargs="*", help="Case names; omit them to run all cases.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Compare committed expectations (default).")
    mode.add_argument("--update", action="store_true", help="Replace expectations after a successful oracle run.")
    options = parser.parse_args(arguments)
    names = options.cases or list(CASES)
    if any(name not in CASES for name in names):
        parser.error("unknown case; choices: " + ", ".join(CASES))
    if any(CASES[name].get("solver") for name in names) and not os.environ.get("CVC5"):
        parser.error("set CVC5 to the pinned cvc5 executable")
    try:
        for name in names:
            run_case(name, CASES[name], options.update)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
