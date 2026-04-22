"""Shared sshd_config helpers for control fixes."""

from __future__ import annotations

import subprocess
from pathlib import Path

from lss.lib import journal
from lss.lib.registry import RollbackEntry

LSS_SSHD_CONF = "/etc/ssh/sshd_config.d/80-lss.conf"
SSHD_CONFIG = "/etc/ssh/sshd_config"
SSHD_CONFIG_D = "/etc/ssh/sshd_config.d"


def get_sshd_setting(key: str) -> str | None:
    """Return the effective sshd setting via `sshd -T`. None if unavailable.

    `sshd -T` resolves Match blocks against the *invoking user* (root by
    default), so the result is the value that would apply to a root login. For
    detecting whether the global default is correct vs only the Match-scoped
    value, see `setting_in_global_scope`.
    """
    try:
        r = subprocess.run(["sshd", "-T"], capture_output=True, text=True)
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) == 2 and parts[0].lower() == key.lower():
                    return parts[1]
    except FileNotFoundError:
        pass
    return None


def setting_in_global_scope(key: str) -> bool | None:
    """Check whether `key` is set in the global (non-Match) section of any
    sshd config file.

    Returns:
        True   — key has a global setting (whatever the value)
        False  — key is only set inside Match blocks (or not set at all)
        None   — sshd config files unreadable / non-existent

    A control that finds the effective value is correct via `get_sshd_setting`
    but `setting_in_global_scope` returns False should warn the operator that
    the value only applies to the matched scope, not all users.
    """
    files: list[Path] = []
    main = Path(SSHD_CONFIG)
    if main.exists():
        files.append(main)
    d = Path(SSHD_CONFIG_D)
    if d.is_dir():
        files.extend(sorted(d.glob("*.conf")))

    if not files:
        return None

    found_global = False
    key_l = key.lower()
    for f in files:
        try:
            in_match = False
            for raw in f.read_text().splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.lower().startswith("match "):
                    in_match = True
                    continue
                if in_match:
                    continue
                first = line.split(None, 1)[0].lower()
                if first == key_l:
                    found_global = True
                    break
            if found_global:
                break
        except OSError:
            continue

    return found_global


def set_sshd_setting(key: str, value: str) -> RollbackEntry:
    """Set an sshd config value via the LSS drop-in file.

    Backs up the drop-in file before modification so rollback can restore the
    previous state byte-for-byte (or remove the file if it didn't exist before).
    """
    p = Path(LSS_SSHD_CONF)
    p.parent.mkdir(parents=True, exist_ok=True)
    bkp = journal.backup_file(str(p))

    existing = p.read_text() if p.exists() else ""
    entry = f"{key} {value}\n"
    lines = existing.splitlines(keepends=True)
    found = False
    for i, line in enumerate(lines):
        if line.strip().lower().startswith(key.lower()):
            lines[i] = entry
            found = True
            break
    if not found:
        if lines and not lines[-1].endswith("\n"):
            lines.append("\n")
        lines.append(entry)
    p.write_text("".join(lines))
    p.chmod(0o600)

    return RollbackEntry(
        action=f"set sshd {key} = {value}",
        path=str(p),
        backup=bkp,
        undo=[] if bkp else [["rm", "-f", str(p)]],
    )
