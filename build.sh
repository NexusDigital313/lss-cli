#!/usr/bin/env bash
# Build the LSS release: wheel + sdist + checksums into ./dist.
# Run this before you try to `pip install` anything — the wheel does not
# exist in the repo, you produce it here.
#
#   ./build.sh
#
# It builds inside a throwaway virtualenv, so it works on any machine
# (including Homebrew / Debian "externally-managed" Pythons) and never
# touches your global packages.
#
# Output:
#   dist/lss-<version>-py3-none-any.whl   pip install this
#   dist/lss-<version>.tar.gz             or this
#   dist/SHA256SUMS                       verify: (cd dist && shasum -a 256 -c SHA256SUMS)
set -euo pipefail
cd "$(dirname "$0")"

# Find a Python 3.10+ interpreter.
PY=""
for c in "${PYTHON:-}" python3.13 python3.12 python3.11 python3.10 python3; do
  [ -n "$c" ] || continue
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; raise SystemExit(0 if sys.version_info>=(3,10) else 1)' 2>/dev/null; then
    PY="$c"; break
  fi
done
if [ -z "$PY" ]; then
  echo "error: need Python 3.10+. Install it, or run: PYTHON=/path/to/python3.12 ./build.sh" >&2
  exit 1
fi
echo ">> using $("$PY" --version) ($PY)"

echo ">> clean"
rm -rf dist build ./*.egg-info lss.egg-info

echo ">> bootstrap build env"
BUILDENV="$(mktemp -d)"
trap 'rm -rf "$BUILDENV"' EXIT
"$PY" -m venv "$BUILDENV"
"$BUILDENV/bin/pip" install --quiet --upgrade pip build

echo ">> build wheel + sdist"
"$BUILDENV/bin/python" -m build

echo ">> checksums"
( cd dist && shasum -a 256 ./*.whl ./*.tar.gz > SHA256SUMS )

echo
echo "built:"
ls -1 dist
echo
echo "install with:  pip install dist/lss-*.whl"
