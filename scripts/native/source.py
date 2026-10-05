"""Require committed source before generating commit-bound native artifacts."""

import re
import subprocess
import sys


def committed_source(repository, expected_commit=None):
    head = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repository, text=True,
    ).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ValueError("source commit must contain 40 lowercase hexadecimal characters")
    if expected_commit is not None and head != expected_commit:
        raise ValueError("expected source commit does not match HEAD")
    status = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all"], cwd=repository,
    )
    if status:
        raise ValueError("verified native artifacts require committed source without untracked files")
    return head


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        sys.exit("usage: source.py REPOSITORY [EXPECTED_COMMIT]")
    try:
        print(committed_source(*sys.argv[1:]))
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit(f"source verification failed: {error}")
