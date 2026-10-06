#!/usr/bin/env python3
"""Discover the exact preserved fuzz inventory and run every target for at least 60 seconds."""

import argparse
import json
import math
import os
import re
import subprocess
import sys
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[2]
TARGETS = json.loads(Path(__file__).with_name("targets.json").read_text())


def discover(repository=REPOSITORY):
    found = {}
    for source in sorted((repository / "cedar").rglob("*_test.go")):
        for target in re.findall(r"^func (Fuzz\w+)\(", source.read_text(), re.MULTILINE):
            if target in found:
                raise ValueError(f"duplicate fuzz target: {target}")
            found[target] = source.parent.relative_to(repository).as_posix()
    if found != TARGETS:
        missing = sorted(set(TARGETS.items()) - set(found.items()))
        unexpected = sorted(set(found.items()) - set(TARGETS.items()))
        raise ValueError(f"fuzz inventory differs; missing={missing}, unexpected={unexpected}")
    return found


def duration(value):
    try:
        units = {"s": 1, "m": 60, "h": 3600}
        suffix = value[-1:] if value[-1:] in units else ""
        seconds = float(value[:-1] if suffix else value) * units.get(suffix, 1)
    except ValueError as error:
        raise argparse.ArgumentTypeError("fuzz duration must contain seconds") from error
    if not math.isfinite(seconds) or seconds < 60:
        raise argparse.ArgumentTypeError("every fuzz target requires at least 60 seconds")
    return seconds


def workers(value):
    count = int(value)
    if count < 1:
        raise argparse.ArgumentTypeError("fuzz worker count must be positive")
    return count


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=duration, default=os.environ.get("FUZZTIME", os.environ.get("FUZZ_SECONDS", "60")))
    parser.add_argument("--workers", type=workers, default=os.environ.get("FUZZWORKERS", os.environ.get("FUZZ_WORKERS", "4")))
    parser.add_argument("--list", action="store_true", help="Check the inventory without running fuzz targets.")
    options = parser.parse_args(arguments)
    try:
        found = discover()
        for target, package in sorted(found.items()):
            if options.list:
                print(f"{package} {target}")
            else:
                subprocess.run(["go", "test", "-run", "^$", "-fuzz", "^" + target + "$",
                                "-fuzztime", f"{options.seconds:g}s", "-parallel", str(options.workers),
                                "./" + package], cwd=REPOSITORY, check=True)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
