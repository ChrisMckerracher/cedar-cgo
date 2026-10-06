#!/usr/bin/env python3
"""Extract a complete bundle after checking its commit and file checksums."""

import sys
import subprocess
import zipfile

from bundle import extract_bundle

if len(sys.argv) not in (4, 5):
    sys.exit("usage: extract.py SOURCE_ZIP SOURCE_COMMIT DESTINATION [RUST_TARGET]")
try:
    print(extract_bundle(*sys.argv[1:]))
except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError, zipfile.BadZipFile) as error:
    sys.exit(f"consumer bundle failed: {error}")
