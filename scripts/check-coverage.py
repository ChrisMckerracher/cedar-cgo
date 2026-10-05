#!/usr/bin/env python3
"""Require at least the pinned pre-migration statement coverage."""

import sys
from pathlib import Path

# Measurements from a7083b5, Go 1.27.1, with cvc5 1.3.1.
MINIMUM = {"cedar": (1423, 1579), "analysis": (474, 544), "artifact": (48, 55)}


def coverage(profile):
    blocks = {}
    for line in Path(profile).read_text().splitlines()[1:]:
        location, statements, hits = line.rsplit(" ", 2)
        count, hit = int(statements), int(hits) > 0
        previous = blocks.get(location, (count, False))
        blocks[location] = (count, hit or previous[1])
    groups = {name: [0, 0] for name in MINIMUM}
    for location, (count, hit) in blocks.items():
        if "/cedar/" in location or "/internal/execution/" in location:
            group = "cedar"
        elif "/analysis/" in location:
            group = "analysis"
        elif "/internal/artifact/" in location:
            group = "artifact"
        else:
            continue
        groups[group][0] += count
        groups[group][1] += count if hit else 0
    return groups


def check(profile):
    failed = False
    for name, (total, covered) in coverage(profile).items():
        percent = 100 * covered / total if total else 0
        baseline_covered, baseline_total = MINIMUM[name]
        minimum = 100 * baseline_covered / baseline_total
        print(f"{name}: {covered}/{total} statements, {percent:.2f}% (minimum {minimum:.2f}%)")
        if total == 0 or covered * baseline_total < baseline_covered * total:
            failed = True
    if failed:
        raise SystemExit("Statement coverage fell below the pinned migration baseline")


if __name__ == "__main__":
    check(sys.argv[1])
