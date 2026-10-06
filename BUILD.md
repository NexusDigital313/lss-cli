# Building LSS

Two build targets via `./build.sh`. Both write `SHA256SUMS` and the result is
smoke-tested by CI.

## `./build.sh open` — the distributable (default)

```bash
./build.sh open          # → dist/lss-<ver>-py3-none-any.whl + .tar.gz + SHA256SUMS
```

This is what you ship: a portable, source-available wheel (`py3-none-any`, runs
on any Python 3.10+). It's what the Lemon Squeezy products deliver and what the
`v*.*.*` tag → `release.yml` builds and cosign-signs. **Use this unless you have
a specific reason not to.**

## `./build.sh paid` — optional source obfuscation

```bash
PYTHON=/path/to/venv/python ./build.sh paid    # → dist-paid/lss-<ver>-py3-none-<platform>.whl
```

Runs the package through **PyArmor**, replacing every `lss/*.py` with encrypted
bytecode and bundling a native `pyarmor_runtime` — so a buyer can't read the
source. Two hard constraints:

1. **Platform-specific.** The runtime is a native `.so`, so the wheel is tagged
   for the platform it's built on. **Build it on Linux** (or in CI) to ship to
   Debian/Ubuntu buyers — a macOS-built paid wheel only runs on macOS.
2. **Needs a real PyArmor license** to distribute. The free trial works for
   testing but watermarks the output and is eval-only — don't sell trial builds.
   See https://pyarmor.dashingsoft.com.

### Should you use it?

Probably not yet. LSS is positioned as source-available; obfuscation fights that
and only buys a speed bump (determined RE still wins). The real moat is the
license gate + the $49/yr signed-update channel. Reach for `paid` only if casual
copying becomes a measurable problem — then ship the obfuscated wheel to paying
tiers and keep an open audit-only build.

## Requirements

- Python 3.10+ with `build` (`pip install build`), and `pyarmor` for the paid target.
- Output dirs (`dist/`, `dist-paid/`, `build/`) are gitignored.
