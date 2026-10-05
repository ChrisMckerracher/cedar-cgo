#!/usr/bin/env python3
"""Record checksums for the exact tested release files."""

import hashlib
import sys
from pathlib import Path

folder = Path(sys.argv[1])
manifest = folder / sys.argv[2]
files = sorted(path for path in folder.iterdir() if not path.name.startswith("SHA256SUMS"))
manifest.write_text("".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in files))
