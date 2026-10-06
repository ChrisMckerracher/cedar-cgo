"""Reject incomplete, skipped, failed, or unexpected CI job sets."""

import sys
from pathlib import Path

EXPECTED = {
    "Cedar corpus conformance and coverage",
    "Analysis and native arithmetic proofs",
    "Fuzz every preserved target for 60 seconds",
    "Go advisory check",
    "Rust, independent parity, licenses, and advisories",
}
for platform in ("linux_amd64", "linux_arm64", "darwin_arm64"):
    EXPECTED.add(f"Native artifact ({platform})")
    EXPECTED.add(f"Go tests ({platform}, Go 1.27.1)")


def verify(rows):
    names = []
    for row in rows:
        fields = row.rstrip("\n").split("\t")
        if len(fields) != 3 or fields[1:] != ["completed", "success"]:
            raise ValueError("CI contains an unsuccessful or incomplete job")
        names.append(fields[0])
    if len(names) != len(set(names)) or set(names) != EXPECTED:
        raise ValueError("CI job set is missing, duplicated, or unexpected")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).read_text().splitlines())
