#!/usr/bin/env bash
# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized reproduction, copying, modification, distribution,
# redistribution, publication, reverse engineering, decompilation, or
# disassembly of this file, in whole or in part, via any medium, is
# strictly prohibited without explicit prior written authorization.

# Wire your three Gumroad product URLs into the landing page Buy buttons.
#
# Usage:
#   ./wire-gumroad-urls.sh \
#     https://gumroad.com/l/SOLO_SLUG \
#     https://gumroad.com/l/PRO_SLUG \
#     https://gumroad.com/l/ENT_SLUG
#
# By default, looks for the landing page at the canonical post-reorg path:
#   /home/kali/00-Active-Products/LSS/Landing-Page/lss-landing/index.html
# Override with LSS_LANDING_PATH=<path> in the environment if your repo is
# elsewhere. Backs up the existing index.html as index.html.bak before modifying.

set -euo pipefail

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <SOLO_URL> <PRO_URL> <ENTERPRISE_URL>" >&2
    exit 1
fi

SOLO_URL="$1"
PRO_URL="$2"
ENT_URL="$3"

# Find the landing page. Try the env override first, then the canonical
# post-reorg path, then the legacy pre-reorg path. Fail loudly if none exist.
_CANDIDATES=(
    "${LSS_LANDING_PATH:-}"
    "/home/kali/00-Active-Products/LSS/Landing-Page/lss-landing/index.html"
    "/home/kali/lss-landing/index.html"
)
LANDING=""
for c in "${_CANDIDATES[@]}"; do
    if [ -n "$c" ] && [ -f "$c" ]; then
        LANDING="$c"
        break
    fi
done

if [ -z "$LANDING" ]; then
    echo "landing page not found. Tried:" >&2
    for c in "${_CANDIDATES[@]}"; do
        [ -n "$c" ] && echo "  $c" >&2
    done
    echo "Set LSS_LANDING_PATH=<path/to/index.html> if it lives elsewhere." >&2
    exit 1
fi

cp -a "$LANDING" "${LANDING}.bak"
echo "Backed up to ${LANDING}.bak"

# The three Buy buttons are around lines 454, 471, 486 — all currently href="#"
# We swap them in order: Solo (first href="#" in the pricing block), Pro, Enterprise.
# Using a Python helper for precise control rather than sed regex.
python3 - <<PYEOF
import re
from pathlib import Path

LANDING = Path("$LANDING")
SOLO = "$SOLO_URL"
PRO  = "$PRO_URL"
ENT  = "$ENT_URL"

text = LANDING.read_text()

# Find the three Buy CTAs in order. They look like:
#   <a href="#" class="btn btn-ghost">Buy Solo</a>
#   <a href="#" class="btn btn-primary">Buy Pro</a>
#   <a href="#" class="btn btn-ghost">Buy Enterprise</a>
mapping = [
    (r'<a\s+href="#"\s+class="([^"]*)"\s*>\s*Buy Solo\s*</a>',       SOLO, "Buy Solo"),
    (r'<a\s+href="#"\s+class="([^"]*)"\s*>\s*Buy Pro\s*</a>',        PRO,  "Buy Pro"),
    (r'<a\s+href="#"\s+class="([^"]*)"\s*>\s*Buy Enterprise\s*</a>', ENT,  "Buy Enterprise"),
]

for pattern, url, label in mapping:
    new_anchor = f'<a href="{url}" class="\\\\1" target="_blank" rel="noopener">{label}</a>'
    new_text, n = re.subn(pattern, new_anchor, text, count=1)
    if n != 1:
        raise SystemExit(f"could not find Buy CTA for {label!r} (matches: {n})")
    text = new_text
    print(f"  wired {label} → {url}")

LANDING.write_text(text)
print(f"Wrote {LANDING}")
PYEOF

echo
echo "Done. Open $LANDING in a browser to verify."
echo "If anything looks wrong, restore from ${LANDING}.bak"
