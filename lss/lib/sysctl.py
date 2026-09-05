# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file, 
# via any medium, is strictly prohibited without explicit written authorization.

"""Shared sysctl helpers for control fixes."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from lss.lib import journal
from lss.lib.registry import RollbackEntry

# sysctl.d files are applied in lexicographic filename order and the LAST
# setting for a key wins. Stock Debian/Ubuntu ship /etc/sysctl.d/99-sysctl.conf
# (a symlink to /etc/sysctl.conf); an 80-* file loses to it, so hardened params
# silently revert at boot while the immediate `sysctl -w` made the audit pass.
# A 99-zzz- prefix sorts after 99-sysctl.conf ('z' > 's'), so LSS wins.
SYSCTL_CONF_DIR = "/etc/sysctl.d"

# Written by installs predating the per-key split. Never written now, but a
# host upgraded from one still has it on disk, so per-key names must outsort
# it (see _conf_path_for). Kept as a named constant so the ordering test can
# assert against the real thing rather than a copy of the string.
LEGACY_SYSCTL_CONF = f"{SYSCTL_CONF_DIR}/99-zzz-lss.conf"


def _conf_path_for(key: str) -> str:
    """Per-key LSS drop-in path, e.g. net.ipv4.ip_forward -> 99-zzzz-lss-netipv4ipforward.conf.

    One key per file means each control's backup/restore/remove on rollback
    can never disturb another control's persisted setting. Mirrors
    sshd.py:_conf_path_for, which fixed the identical shared-file hazard for
    sshd_config in v1.0.2 — sysctl.py had not caught up: it used one shared
    SYSCTL_CONF file, so rolling back the control that happened to create
    that file (`rm -f` in its undo) deleted every other control's persisted
    setting too, and rolling back any other single control restored a stale
    whole-file backup that clobbered whatever was appended after it.

    The prefix is 99-zzzz-, not 99-zzz-, specifically so these sort AFTER a
    LEGACY_SYSCTL_CONF left behind by an older install. '-' (0x2D) sorts
    before '.' (0x2E), so a 99-zzz-lss-<key>.conf would lose to a lingering
    99-zzz-lss.conf and the operator's hardened value would silently revert
    at boot — the exact failure the 99-zzz- prefix was chosen to avoid in
    the first place. No migration needed: the stale file simply loses.
    """
    safe = re.sub(r"[^a-z0-9]", "", key.lower())
    return f"{SYSCTL_CONF_DIR}/99-zzzz-lss-{safe}.conf"


def get_sysctl(key: str) -> str | None:
    """Read a sysctl value. Returns None if the key doesn't exist."""
    try:
        r = subprocess.run(
            ["sysctl", "-n", key],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            return r.stdout.strip()
    except FileNotFoundError:
        pass
    return None


def set_sysctl(key: str, value: str) -> RollbackEntry:
    """Set a sysctl value at runtime and persist it in its own /etc/sysctl.d/ file.

    Returns a RollbackEntry that, on rollback:
      - restores this key's own file from backup, or removes it if this
        control created it (safe: no other control ever shares this file), and
      - replays `sysctl -w` with the previous in-memory value.
    """
    old = get_sysctl(key) or ""

    conf_path = _conf_path_for(key)
    p = Path(conf_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    # Snapshot BEFORE any modification.
    bkp = journal.backup_file(conf_path)

    # Apply at runtime.
    subprocess.run(["sysctl", "-w", f"{key}={value}"], capture_output=True, check=True)

    # Persist. One key per file, so no read/replace-line dance needed.
    p.write_text(f"{key} = {value}\n")

    # Build the undo: replay the previous in-memory value if there was one,
    # and if this control was the first to create its file, delete it on
    # rollback — safe now, since this file holds only this control's key.
    undo: list[list[str]] = []
    if old:
        undo.append(["sysctl", "-w", f"{key}={old}"])
    if not bkp:
        undo.append(["rm", "-f", conf_path])

    return RollbackEntry(
        action=f"set {key} = {value}",
        undo=undo,
        path=conf_path,
        backup=bkp,
    )
