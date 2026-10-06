#!/usr/bin/env python3
"""Summarize all five raw Rust and production Go/cgo samples."""
import json
import pathlib
import re
import statistics
import sys


def rust_sample(path, workload, iterations):
    sample = json.loads(path.read_text())
    assert sample["workload"] == workload
    assert sample["iterations"] == iterations
    assert sample["expected_decision"] == "allow"
    assert sample["expected_reasons"] == ["policy1"]
    assert sample["policies"] == 45 and sample["entities"] == 10
    assert sample["elapsed_ns"] > 0
    return sample["ns_per_op"]


def go_sample(path, benchmark, iterations):
    source = path.read_text()
    assert source.rstrip().endswith("PASS")
    pattern = rf"^BenchmarkRustCgo{benchmark}-2\s+(\d+)\s+([\d.]+) ns/op\b"
    matches = re.findall(pattern, source, re.MULTILINE)
    assert len(matches) == 1, path
    count, timing = matches[0]
    assert int(count) == iterations, path
    assert float(timing) > 0, path
    return float(timing)


def describe(samples):
    return {
        "samples_ns_per_op": samples,
        "median_ns_per_op": statistics.median(samples),
        "minimum_ns_per_op": min(samples),
        "maximum_ns_per_op": max(samples),
    }


def summarize(directory):
    results = {}
    for workload, benchmark, iterations in [
        ("authorize", "Authorize", 20000),
        ("load", "Load", 500),
        ("validate", "Validate", 200),
    ]:
        rust = describe([
            rust_sample(directory / f"rust-{workload}-{sample}.json", workload, iterations)
            for sample in range(1, 6)
        ])
        go = describe([
            go_sample(directory / f"go-{workload}-{sample}.txt", benchmark, iterations)
            for sample in range(1, 6)
        ])
        results[workload] = {
            "iterations": iterations,
            "rust": rust,
            "go_cgo": go,
            "go_over_rust": go["median_ns_per_op"] / rust["median_ns_per_op"],
        }
    results["parsed_request_decision"] = describe([
        rust_sample(directory / f"rust-decision-{sample}.json", "decision", 20000)
        for sample in range(1, 6)
    ])
    (directory / "summary.json").write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    summarize(pathlib.Path(sys.argv[1]))
