# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file,
# via any medium, is strictly prohibited without explicit written authorization.

"""Shared kernel-module state helpers.

filesystem.py, kernel.py, and misc.py each need to answer "is this module
actually disabled?". They used to carry their own copies, which is how the
same ordering defect ended up in two of them independently — a config-only
check reported a still-loaded module as disabled. One implementation now.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

MODPROBE_D = "/etc/modprobe.d"


def module_is_loaded(mod: str) -> bool:
    """True if `mod` is currently loaded, matching the module name EXACTLY.

    A substring test would misclassify a prefix module: checking `hfs` while
    `hfsplus` is loaded would (wrongly) report `hfs` as present."""
    try:
        result = subprocess.run(["lsmod"], capture_output=True, text=True)
    except FileNotFoundError:
        return False
    for line in result.stdout.splitlines()[1:]:  # skip the "Module ..." header
        parts = line.split()
        if parts and parts[0] == mod:
            return True
    return False


def module_blacklisted(mod: str) -> bool:
    """True if an UNCOMMENTED modprobe.d directive disables exactly `mod`.

    Reads the files directly and token-matches so that a `blacklist hfsplus`
    line does not satisfy a check for `hfs`, and a commented-out example line
    is ignored."""
    d = Path(MODPROBE_D)
    if not d.is_dir():
        return False
    for conf in d.glob("*"):
        try:
            text = conf.read_text()
        except OSError:
            continue
        for line in text.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            toks = s.split()
            if len(toks) >= 2 and toks[0] == "blacklist" and toks[1] == mod:
                return True
            if (len(toks) >= 3 and toks[0] == "install" and toks[1] == mod
                    and toks[2] in ("/bin/true", "/bin/false")):
                return True
    return False


def module_install_nulled(mod: str) -> bool:
    """True if modprobe resolves `mod` to an install-null stub."""
    try:
        result = subprocess.run(
            ["modprobe", "-n", "--show-depends", mod],
            capture_output=True, text=True,
        )
    except FileNotFoundError:
        return False
    for line in result.stdout.splitlines():
        toks = line.split()
        if len(toks) >= 2 and toks[0] == "install" and toks[1] in ("/bin/true", "/bin/false"):
            return True
    return False


def module_is_disabled(mod: str) -> bool:
    """True if `mod` is genuinely disabled — config says so AND it is not loaded.

    The loaded check runs FIRST and is decisive. A module that is nulled in
    modprobe.d but still resident in the running kernel is NOT disabled: it
    is doing exactly what it did before. Checking config first (as the old
    per-file copies did) meant `_disable_module`'s post-fix verification
    reported success whenever `rmmod` had failed — e.g. cramfs or hfsplus
    with a filesystem still mounted, or sctp held open by a running service —
    hiding a vulnerable module that was still active.
    """
    if module_is_loaded(mod):
        return False
    return module_install_nulled(mod) or module_blacklisted(mod)
