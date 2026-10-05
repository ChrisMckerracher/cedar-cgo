#!/usr/bin/env bash
# Fetch pinned solver and corpus data into a task directory.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$1"
directory=$(cd "$1" && pwd)
platform=$(go env GOOS)_$(go env GOARCH)
case "$platform" in
 linux_amd64) asset=cvc5-Linux-x86_64-static; checksum=1a1cda20d2df4938fa4944a69f33ddc9172e319ece0eed0aa09c4d7abede3ed1 ;;
 linux_arm64) asset=cvc5-Linux-arm64-static; checksum=fe2b661834a82fd8830f7a757c340f0e20041fa41e19b038fa02ace0eaf1c6f2 ;;
 darwin_arm64) asset=cvc5-macOS-arm64-static; checksum=a0e7f5b03b1bc4284fbfff7cdfb08c704801701cf7ece83a13f8a505e7581215 ;;
 *) echo "unsupported solver platform: $platform" >&2; exit 1 ;;
esac
curl -sSfL -o "$directory/cvc5.zip" "https://github.com/cvc5/cvc5/releases/download/cvc5-1.3.1/$asset.zip"
python3 - "$directory/cvc5.zip" "$checksum" "$directory" <<'PY'
import hashlib,sys,zipfile
from pathlib import Path
archive = Path(sys.argv[1])
if hashlib.sha256(archive.read_bytes()).hexdigest() != sys.argv[2]:
    raise SystemExit('cvc5 archive checksum does not match')
with zipfile.ZipFile(archive) as bundle:
    bundle.extractall(sys.argv[3])
PY
chmod +x "$directory/$asset/bin/cvc5"
"$directory/$asset/bin/cvc5" --version | head -1
if [[ -n ${GITHUB_ENV:-} ]]; then
 echo "CVC5=$directory/$asset/bin/cvc5" >> "$GITHUB_ENV"
fi
if [[ ${2:-solver} == all ]]; then
 commit=1999ea249229e26cabb398a279fea721854a471d
 curl -sSfL -o "$directory/corpus.tar.gz" "https://raw.githubusercontent.com/cedar-policy/cedar-integration-tests/$commit/corpus-tests.tar.gz"
 python3 - "$directory/corpus.tar.gz" <<'PY'
import hashlib,sys
from pathlib import Path
if hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest() != '65476adf952c0574d6bf9b317d67d30c9ac462eb1dbf5e4c7b2a35856baf5205':
    raise SystemExit('Cedar corpus checksum does not match')
PY
 mkdir -p "$directory/corpus"
 tar xzf "$directory/corpus.tar.gz" -C "$directory/corpus"
 if [[ -n ${GITHUB_ENV:-} ]]; then echo "CEDAR_CORPUS_DIR=$directory/corpus" >> "$GITHUB_ENV"; fi
fi
