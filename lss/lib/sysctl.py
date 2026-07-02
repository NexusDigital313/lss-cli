"""Shared sysctl helpers for control fixes."""

from __future__ import annotations

import subprocess
from pathlib import Path

from lss.lib import journal
from lss.lib.registry import RollbackEntry

# sysctl.d files are applied in lexicographic filename order and the LAST
# setting for a key wins. Stock Debian/Ubuntu ship /etc/sysctl.d/99-sysctl.conf
# (a symlink to /etc/sysctl.conf); an 80-* file loses to it, so hardened params
# silently revert at boot while the immediate `sysctl -w` made the audit pass.
# A 99-zzz- name sorts after 99-sysctl.conf ('z' > 's'), so LSS wins.
SYSCTL_CONF = "/etc/sysctl.d/99-zzz-lss.conf"


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
    """Set a sysctl value at runtime and persist it in /etc/sysctl.d/.

    Returns a RollbackEntry that, on rollback:
      - restores the previous SYSCTL_CONF from backup
        (which may be empty/absent if the file did not exist before), and
      - replays `sysctl -w` with the previous in-memory value.
    """
    old = get_sysctl(key) or ""

    # Snapshot the persisted-rules file BEFORE any modification.
    bkp = journal.backup_file(SYSCTL_CONF)

    # Apply at runtime.
    subprocess.run(["sysctl", "-w", f"{key}={value}"], capture_output=True, check=True)

    # Persist: replace existing line for this key, or append.
    p = Path(SYSCTL_CONF)
    p.parent.mkdir(parents=True, exist_ok=True)
    existing = p.read_text() if p.exists() else ""
    lines = existing.splitlines(keepends=True)
    new_line = f"{key} = {value}\n"
    found = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith(f"{key} ") or stripped.startswith(f"{key}="):
            lines[i] = new_line
            found = True
            break
    if not found:
        if lines and not lines[-1].endswith("\n"):
            lines.append("\n")
        lines.append(new_line)
    p.write_text("".join(lines))

    # Build the undo: replay the previous in-memory value if there was one,
    # and if this control was the first to create the persistence file,
    # delete it on rollback. Mirrors the sshd.py pattern.
    undo: list[list[str]] = []
    if old:
        undo.append(["sysctl", "-w", f"{key}={old}"])
    if not bkp:
        undo.append(["rm", "-f", SYSCTL_CONF])

    return RollbackEntry(
        action=f"set {key} = {value}",
        undo=undo,
        path=SYSCTL_CONF,
        backup=bkp,
    )
