#!/usr/bin/env python3
"""Extract a complete bundle after checking its commit and file checksums."""

import sys
import zipfile

from bundle import extract_bundle

if len(sys.argv) != 4:
    sys.exit("usage: extract.py SOURCE_ZIP SOURCE_COMMIT DESTINATION")
try:
    print(extract_bundle(*sys.argv[1:]))
except (OSError, ValueError, zipfile.BadZipFile) as error:
    sys.exit(f"consumer bundle failed: {error}")
