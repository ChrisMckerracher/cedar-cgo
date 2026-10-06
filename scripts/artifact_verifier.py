"""Run the artifact policy from trusted repository source without Rust or cgo."""

import atexit
import functools
import json
import os
import subprocess
import tempfile
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
HEADER = REPOSITORY / "internal/native/include/cedar.h"


@functools.cache
def executable():
    directory = tempfile.TemporaryDirectory(prefix="cedar-artifact-verifier-")
    atexit.register(directory.cleanup)
    binary = Path(directory.name) / "verify-native-artifact"
    environment = os.environ | {"CGO_ENABLED": "0", "GOTOOLCHAIN": "local", "GOWORK": "off", "GOFLAGS": ""}
    subprocess.run(["go", "build", "-buildvcs=false", "-o", str(binary), "./cmd/verify-native-artifact"],
                   cwd=REPOSITORY, env=environment, check=True)
    return binary


def run(*arguments):
    result = subprocess.run([str(executable()), *map(str, arguments)], capture_output=True)
    if result.returncode:
        raise ValueError(result.stderr.decode().strip())
    return result.stdout


def link_source(platform, flags, digest):
    return run("link-source", platform, digest, *flags)


@functools.cache
def targets():
    return json.loads(run("platforms"))
