# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file, 
# via any medium, is strictly prohibited without explicit written authorization.

"""CIS Section 1.1 — Separate partitions and mount options."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from lss.lib import journal
from lss.lib.registry import Control, CheckResult, RollbackEntry, register

FSTAB = "/etc/fstab"


def _sed_pattern_escape(s: str) -> str:
    """Escape literal text for use inside a sed BRE pattern delimited by `|`."""
    return re.sub(r"([.\\^$*\[\]|])", r"\\\1", s)


def _sed_replacement_escape(s: str) -> str:
    """Escape literal text for use as a sed s/// replacement delimited by `|`."""
    return s.replace("\\", "\\\\").replace("|", "\\|").replace("&", "\\&")


def _persist_fstab_options(mountpoint: str, required_opts: list[str]) -> RollbackEntry | None:
    """Add `required_opts` to the existing /etc/fstab entry for `mountpoint`.

    A `mount -o remount` alone is lost on reboot, so hardening would silently
    revert while being reported as fixed. This persists the options to fstab.
    Returns None if there's no fstab entry for the mountpoint (e.g. a
    systemd-managed tmpfs) or the options are already present — we never
    invent a new device line, since a wrong fstab entry can make the box fail
    to boot.

    Several controls can touch the SAME fstab line (e.g. /var/tmp is edited
    by 1.1.10, 1.1.11, and 1.1.12; /home by 1.1.13 and 1.1.14). A whole-file
    backup/restore would let rolling back one of them clobber whatever a
    sibling control (or a run that happened afterward) added to that same
    line since. Instead, the undo is a sed replacement matched against this
    control's own exact new line text, reverting it back to the exact old
    line — surgical regardless of what else touched fstab in between.

    Known limit: if a sibling control edits the same line afterward, this
    control's pattern no longer matches and the sed is a no-op. It exits 0
    either way, so rollback reports success without having changed anything.
    That is deliberate — leaving a sibling's option in place is a far better
    failure than restoring a stale whole-file snapshot over it. fstab is
    still snapshotted below for manual recovery, since a bad fstab can stop
    the host booting; it is just not wired to automatic whole-file restore.
    """
    fstab = Path(FSTAB)
    if not fstab.exists():
        return None
    lines = fstab.read_text().splitlines(keepends=True)
    for i, raw in enumerate(lines):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        fields = s.split()
        if len(fields) < 4 or fields[1] != mountpoint:
            continue
        opts = fields[3].split(",")
        missing = [o for o in required_opts if o not in opts]
        if not missing:
            return None  # already persisted
        fields[3] = ",".join(opts + missing)
        eol = "\n" if raw.endswith("\n") else ""
        old_text = raw[:-1] if raw.endswith("\n") else raw
        new_line = " ".join(fields) + eol
        new_text = new_line[:-1] if new_line.endswith("\n") else new_line
        # Snapshot for manual recovery only — deliberately NOT paired with a
        # `path`, so rollback never whole-file restores it over a sibling's edit.
        bkp = journal.backup_file(str(fstab))
        lines[i] = new_line
        fstab.write_text("".join(lines))
        sed_expr = (
            f"s|^{_sed_pattern_escape(new_text)}$|{_sed_replacement_escape(old_text)}|"
        )
        return RollbackEntry(
            action=f"added {','.join(missing)} to {mountpoint} in /etc/fstab",
            undo=[["sed", "-i", sed_expr, str(fstab)]],
            backup=bkp,
        )
    return None


def _is_separate_mount(path: str) -> bool:
    """Check if a path is a separate mount point."""
    try:
        r = subprocess.run(["findmnt", "-n", path], capture_output=True, text=True)
    except FileNotFoundError:
        # findmnt absent — can't confirm a separate mount. Treat as "not
        # separate" so callers degrade to a warn (never a false pass).
        return False
    return r.returncode == 0 and path in r.stdout


def _get_mount_options(path: str) -> set[str]:
    try:
        r = subprocess.run(["findmnt", "-n", "-o", "OPTIONS", path], capture_output=True, text=True)
    except FileNotFoundError:
        return set()
    if r.returncode == 0 and r.stdout.strip():
        return set(r.stdout.strip().split(","))
    return set()


# ---- Separate partition checks ----

_PARTITION_CHECKS = [
    ("1.1.2", "Ensure /tmp is configured", "/tmp"),
    ("1.1.3", "Ensure /var is configured", "/var"),
    ("1.1.4", "Ensure /var/tmp is configured", "/var/tmp"),
    ("1.1.5", "Ensure /var/log is configured", "/var/log"),
    ("1.1.6", "Ensure /var/log/audit is configured", "/var/log/audit"),
    ("1.1.7", "Ensure /home is configured", "/home"),
]

for _id, _title, _path in _PARTITION_CHECKS:
    path = _path

    def _make_check(p):
        def check():
            if _is_separate_mount(p):
                return CheckResult("pass")
            return CheckResult("warn", f"{p} is not a separate partition")
        return check

    register(Control(
        id=_id,
        title=_title,
        section="filesystem",
        check=_make_check(path),
        fix=None,  # Requires repartitioning — cannot auto-fix
    ))


# ---- Mount option checks ----

_MOUNT_OPTION_CHECKS = [
    ("1.1.10", "Ensure noexec option set on /var/tmp", "/var/tmp", ["noexec", "nosuid", "nodev"]),
    ("1.1.11", "Ensure nodev option set on /var/tmp", "/var/tmp", ["nodev"]),
    ("1.1.12", "Ensure nosuid option set on /var/tmp", "/var/tmp", ["nosuid"]),
    ("1.1.13", "Ensure nodev option set on /home", "/home", ["nodev"]),
    ("1.1.14", "Ensure nosuid option set on /home", "/home", ["nosuid"]),
]

for _id, _title, _path, _opts in _MOUNT_OPTION_CHECKS:
    path, opts = _path, _opts

    def _make_check(p, required_opts):
        def check():
            if not _is_separate_mount(p):
                return CheckResult("warn", f"{p} is not a separate mount")
            current = _get_mount_options(p)
            missing = [o for o in required_opts if o not in current]
            if not missing:
                return CheckResult("pass")
            return CheckResult("fail", f"{p} missing: {','.join(missing)}")
        return check

    def _make_fix(p, required_opts):
        def fix():
            if not _is_separate_mount(p):
                return []
            current = _get_mount_options(p)
            # Capture the previous option set so rollback can restore exactly
            # what was there before — don't strip unrelated mount flags like
            # relatime, errors=continue, etc.
            previous_opts = ",".join(sorted(current)) if current else "defaults"
            merged = current.union(required_opts)
            opt_str = ",".join(sorted(merged))
            subprocess.run(
                ["mount", "-o", f"remount,{opt_str}", p],
                capture_output=True, check=True,
            )
            entries = [RollbackEntry(
                action=f"remounted {p} with {','.join(required_opts)} (preserved existing options)",
                undo=[["mount", "-o", f"remount,{previous_opts}", p]],
            )]
            # Persist to fstab so the option survives a reboot. If there's no
            # fstab entry (systemd-managed mount), the runtime remount still
            # applied; the control will simply show failing again after reboot,
            # which is honest — better than claiming a persistent fix.
            persisted = _persist_fstab_options(p, required_opts)
            if persisted is not None:
                entries.append(persisted)
            return entries
        return fix

    register(Control(
        id=_id,
        title=_title,
        section="filesystem",
        check=_make_check(path, opts),
        fix=_make_fix(path, opts),
    ))