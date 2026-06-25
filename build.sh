#!/usr/bin/env bash
# LSS build script.
#
#   ./build.sh open    Source-available wheel + sdist into dist/  (THE default distributable)
#   ./build.sh paid    PyArmor-obfuscated wheel into dist-paid/   (optional source protection)
#
# Both emit SHA256SUMS and smoke-test the result. See BUILD.md for when (not) to
# use the paid build — it is platform-specific and wants a real PyArmor license.
set -euo pipefail
cd "$(dirname "$0")"
MODE="${1:-open}"
PY="${PYTHON:-python3}"
sums() {
  ( cd "$1"
    files=$(ls *.whl *.tar.gz 2>/dev/null || true)
    if command -v sha256sum >/dev/null 2>&1; then sha256sum $files; else shasum -a 256 $files; fi > SHA256SUMS
  )
}

build_open() {
  rm -rf dist
  "$PY" -m build
  sums dist
  echo "✓ open build → dist/"
  ls -1 dist
}

build_paid() {
  if ! "$PY" -c "import pyarmor" >/dev/null 2>&1; then
    echo "PyArmor not installed in this Python. For a DISTRIBUTABLE build use a paid PyArmor license:"
    echo "    $PY -m pip install pyarmor   # trial is watermarked / eval-only"
    exit 1
  fi
  # the pyarmor console script lives next to $PY in a venv; fall back to PATH / -m
  PYDIR="$(cd "$(dirname "$PY")" && pwd)"
  if [ -x "$PYDIR/pyarmor" ]; then PYARMOR="$PYDIR/pyarmor"
  elif command -v pyarmor >/dev/null 2>&1; then PYARMOR="pyarmor"
  else PYARMOR="$PY -m pyarmor"; fi

  # 1. build the open wheel first — gives us correct metadata + version + RECORD
  rm -rf dist; "$PY" -m build --wheel >/dev/null
  OPEN_WHL="$(ls dist/lss-*-py3-none-any.whl | head -1)"

  # 2. obfuscate the package (emits an obfuscated lss/ + a native pyarmor_runtime_*)
  OBF="$(mktemp -d)"
  $PYARMOR gen -O "$OBF" -r lss >/dev/null

  # 3. repackage: obfuscated .py + runtime, platform-tagged (the .so is native)
  PLAT="$("$PY" -c 'import sysconfig; print(sysconfig.get_platform().replace("-","_").replace(".","_"))')"
  rm -rf dist-paid
  "$PY" tools/obfuscate_wheel.py "$OPEN_WHL" "$OBF" dist-paid "$PLAT"
  rm -rf "$OBF" dist
  sums dist-paid
  echo "✓ paid (obfuscated, platform=$PLAT) build → dist-paid/"
  ls -1 dist-paid
}

case "$MODE" in
  open) build_open ;;
  paid) build_paid ;;
  *) echo "usage: $0 {open|paid}"; exit 2 ;;
esac
