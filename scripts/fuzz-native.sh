#!/usr/bin/env bash
# Discover every domain fuzz target and preserve the 60-second CI duration.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo"
seconds=${FUZZ_SECONDS:-60}
python3 - "$seconds" <<'PY'
import os
import re
import subprocess
import sys
from pathlib import Path
seconds = sys.argv[1]
found = []
for source in sorted(Path('cedar').rglob('*_test.go')):
    for target in re.findall(r'^func (Fuzz\w+)\(', source.read_text(), re.MULTILINE):
        found.append((str(source.parent), target))
if len(found) < 25 or len({target for _, target in found}) != len(found):
    raise SystemExit('native fuzz targets are missing or duplicated')
for package, target in found:
    subprocess.run(['go', 'test', '-run', '^$', '-fuzz', '^'+target+'$',
                    '-fuzztime', seconds+'s', '-parallel', os.environ.get('FUZZ_WORKERS', '4'), './'+package], check=True)
PY
