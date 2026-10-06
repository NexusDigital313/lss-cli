# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file, 
# via any medium, is strictly prohibited without explicit written authorization.

"""CIS Sections 1.1 / 1.4 / 6.1 — Filesystem permissions and mount options."""

from __future__ import annotations

import subprocess
from pathlib import Path

from lss.lib import fsscan, journal
from lss.lib.registry import Control, CheckResult, RollbackEntry, register
from lss.lib.sysctl import set_sysctl


# ---- CIS 1.4.1: Ensure core dumps are restricted ----

LIMITS_CONF = "/etc/security/limits.conf"
LIMITS_D = "/etc/security/limits.d"


def _hard_core_entries(text: str) -> list[str]:
    """Values of `* hard core` / `* - core` lines, in file order.

    Only the "*" domain applies to every user; a user/group domain such as
    `ftp hard core 0` covers that account alone, so it does not count."""
    vals = []
    for line in text.splitlines():
        parts = line.split("#", 1)[0].split()
        if (len(parts) >= 4 and parts[0] == "*" and parts[2] == "core"
                and parts[1] in ("hard", "-")):
            vals.append(parts[3])
    return vals


def _effective_hard_core() -> tuple[str | None, str]:
    """pam_limits' effective `*` hard core value and any read problem.

    pam_limits reads limits.conf, then limits.d/*.conf in C-locale order; a
    later entry for the same domain overrides an earlier one."""
    files = [Path(LIMITS_CONF)]
    problem = ""
    try:
        files += sorted(Path(LIMITS_D).glob("*.conf"), key=lambda q: q.name)
    except OSError as e:
        problem = f"cannot list {LIMITS_D}: {e}"
    value = None
    for p in files:
        try:
            content = p.read_text()
        except FileNotFoundError:
            continue
        except OSError as e:
            problem = f"cannot read {p}: {e}"
            continue
        for v in _hard_core_entries(content):
            value = v
    return value, problem


def _check_core_dumps() -> CheckResult:
    value, problem = _effective_hard_core()
    limits_ok = value == "0"

    # Check sysctl
    try:
        r = subprocess.run(["sysctl", "-n", "fs.suid_dumpable"], capture_output=True, text=True)
        suid_dumpable = r.stdout.strip()
    except FileNotFoundError:
        suid_dumpable = "unknown"

    if limits_ok and suid_dumpable == "0":
        # A limits file we could not read may override the 0: never a pass.
        return CheckResult("warn", f"cannot verify: {problem}") if problem else CheckResult("pass")

    issues = []
    if not limits_ok:
        issues.append("no effective '* hard core 0' in limits.conf/limits.d"
                      + (f" (effective value {value})" if value is not None else ""))
    if problem:
        issues.append(problem)
    if suid_dumpable != "0":
        issues.append(f"fs.suid_dumpable={suid_dumpable}")
    return CheckResult("fail", "; ".join(issues))


def _fix_core_dumps() -> list[RollbackEntry]:
    entries = []

    # Set limits — back up if the file already exists, otherwise undo by rm
    conf = Path(LIMITS_D) / "80-lss.conf"
    if not conf.exists() or _hard_core_entries(conf.read_text()) != ["0"]:
        bkp = journal.backup_file(str(conf))
        conf.write_text("* hard core 0\n")
        entries.append(RollbackEntry(
            action="set hard core 0 in limits",
            path=str(conf),
            backup=bkp,
            undo=[] if bkp else [["rm", "-f", str(conf)]],
        ))

    # Set sysctl via the shared helper (handles backup + persistence atomically)
    entries.append(set_sysctl("fs.suid_dumpable", "0"))

    return entries


register(Control(
    id="1.4.1",
    title="Ensure core dumps are restricted",
    section="filesystem",
    check=_check_core_dumps,
    fix=_fix_core_dumps,
))


# ---- CIS 1.1.8: Ensure noexec option set on /dev/shm ----

def _get_mount_options(mountpoint: str) -> set[str]:
    """Get mount options for a given mountpoint."""
    try:
        r = subprocess.run(["findmnt", "-n", "-o", "OPTIONS", mountpoint],
                           capture_output=True, text=True)
        if r.returncode == 0:
            return set(r.stdout.strip().split(","))
    except FileNotFoundError:
        pass
    return set()


def _check_shm_noexec() -> CheckResult:
    opts = _get_mount_options("/dev/shm")
    if not opts:
        return CheckResult("warn", "/dev/shm not found as mountpoint")
    missing = []
    for opt in ["noexec", "nosuid", "nodev"]:
        if opt not in opts:
            missing.append(opt)
    if not missing:
        return CheckResult("pass")
    return CheckResult("fail", f"/dev/shm missing: {','.join(missing)}")


def _fix_shm_noexec() -> list[RollbackEntry]:
    entries: list[RollbackEntry] = []

    # Capture current mount options so we can restore them faithfully
    current = _get_mount_options("/dev/shm")
    previous_opts = ",".join(sorted(current)) if current else "defaults"
    merged = current.union({"noexec", "nosuid", "nodev"})
    opt_str = ",".join(sorted(merged))

    subprocess.run(
        ["mount", "-o", f"remount,{opt_str}", "/dev/shm"],
        capture_output=True, check=True,
    )
    entries.append(RollbackEntry(
        action="remounted /dev/shm with noexec,nosuid,nodev (preserved existing options)",
        undo=[["mount", "-o", f"remount,{previous_opts}", "/dev/shm"]],
    ))

    # Persist in /etc/fstab if not already present
    fstab = Path("/etc/fstab")
    text = fstab.read_text() if fstab.exists() else ""
    if "/dev/shm" not in text:
        bkp = journal.backup_file(str(fstab))
        # Guarantee a newline separator. If the existing fstab does not end in
        # one, a bare append concatenates our line onto the last entry —
        # corrupting that mount line and potentially making the box fail to
        # boot. This is the exact class of bug LSS exists to prevent.
        sep = "" if (not text or text.endswith("\n")) else "\n"
        fstab.write_text(text + sep + "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0\n")
        entries.append(RollbackEntry(
            action="added /dev/shm noexec,nosuid,nodev to fstab",
            path=str(fstab),
            backup=bkp,
        ))

    return entries


register(Control(
    id="1.1.8",
    title="Ensure noexec option set on /dev/shm partition",
    section="filesystem",
    check=_check_shm_noexec,
    fix=_fix_shm_noexec,
))


# ---- CIS 1.1.9: Ensure noexec option set on /tmp ----

def _check_tmp_noexec() -> CheckResult:
    opts = _get_mount_options("/tmp")
    if not opts:
        return CheckResult("warn", "/tmp is not a separate mount")
    missing = []
    for opt in ["noexec", "nosuid", "nodev"]:
        if opt not in opts:
            missing.append(opt)
    if not missing:
        return CheckResult("pass")
    return CheckResult("fail", f"/tmp missing: {','.join(missing)}")


def _fix_tmp_noexec() -> list[RollbackEntry]:
    current = _get_mount_options("/tmp")
    previous_opts = ",".join(sorted(current)) if current else "defaults"
    merged = current.union({"noexec", "nosuid", "nodev"})
    opt_str = ",".join(sorted(merged))
    subprocess.run(
        ["mount", "-o", f"remount,{opt_str}", "/tmp"],
        capture_output=True, check=True,
    )
    return [RollbackEntry(
        action="remounted /tmp with noexec,nosuid,nodev (preserved existing options)",
        undo=[["mount", "-o", f"remount,{previous_opts}", "/tmp"]],
    )]


register(Control(
    id="1.1.9",
    title="Ensure noexec option set on /tmp partition",
    section="filesystem",
    check=_check_tmp_noexec,
    fix=_fix_tmp_noexec,
))


# ---- CIS 6.1.9-6.1.12: whole-system find scans ----

def _scan_result(predicate: list[str], status: str, label: str) -> CheckResult:
    """Run `predicate` on every local mount (not just /, which -xdev pins
    to the root filesystem) and grade the result. An incomplete scan never
    passes: with no findings it warns with what was not covered."""
    try:
        found, note = fsscan.find_all(predicate)
    except FileNotFoundError:
        return CheckResult("warn", "cannot verify: 'find' not available")
    except OSError as e:
        return CheckResult("warn", f"scan failed: {e}")
    if not found:
        return CheckResult("warn", note) if note else CheckResult("pass")
    count = len(found)
    sample = found[0] if count == 1 else f"{found[0]} (+{count-1} more)"
    detail = f"{count} {label}: {sample}"
    return CheckResult(status, f"{detail} ({note})" if note else detail)


# ---- CIS 6.1.9: Ensure no world-writable files exist ----

def _check_world_writable() -> CheckResult:
    return _scan_result(["-type", "f", "-perm", "-0002"], "fail", "world-writable file(s)")


def _fix_world_writable() -> list[RollbackEntry]:
    """Strip the world-write bit from every regular file that has it.

    Uses `find -xdev` so we never cross filesystems (network mounts, bind
    mounts, container overlays). Records each file's original mode so
    rollback restores it exactly — we are not forcing a blanket 0644.
    """
    try:
        found, _note = fsscan.find_all(["-type", "f", "-perm", "-0002"])
    except FileNotFoundError:
        return []
    entries: list[RollbackEntry] = []
    import os as _os, stat as _stat
    for fp in found:
        if not fp:
            continue
        try:
            st = _os.stat(fp, follow_symlinks=False)
        except (OSError, PermissionError):
            continue
        if not _stat.S_ISREG(st.st_mode):
            continue
        prev = _stat.S_IMODE(st.st_mode)
        if not (prev & 0o002):
            continue
        new = prev & ~0o002
        try:
            _os.chmod(fp, new)
        except (OSError, PermissionError):
            continue
        entries.append(RollbackEntry(
            action=f"stripped world-write from {fp} ({oct(prev)} -> {oct(new)})",
            undo=[["chmod", oct(prev)[2:].zfill(4), fp]],
        ))
    return entries


register(Control(
    id="6.1.9",
    title="Ensure no world-writable files exist",
    section="filesystem",
    level=1,
    check=_check_world_writable,
    fix=_fix_world_writable,
))


# ---- CIS 6.1.10: Ensure no unowned files or directories exist ----

def _check_unowned() -> CheckResult:
    return _scan_result(["-nouser"], "warn", "unowned file(s)")


register(Control(
    id="6.1.10",
    title="Ensure no unowned files or directories exist",
    section="filesystem",
    level=1,
    check=_check_unowned,
    fix=None,  # Audit-only — requires human review
))


# ---- CIS 6.1.11: Ensure no ungrouped files or directories exist ----

def _check_ungrouped() -> CheckResult:
    return _scan_result(["-nogroup"], "warn", "ungrouped file(s)")


register(Control(
    id="6.1.11",
    title="Ensure no ungrouped files or directories exist",
    section="filesystem",
    level=1,
    check=_check_ungrouped,
    fix=None,  # Audit-only
))


# ---- CIS 6.1.12: Ensure sticky bit is set on world-writable directories ----

def _check_sticky_bit() -> CheckResult:
    return _scan_result(["-type", "d", "-perm", "-0002", "!", "-perm", "-1000"], "fail", "world-writable dir(s) without sticky bit")


def _fix_sticky_bit() -> list[RollbackEntry]:
    found, _note = fsscan.find_all(["-type", "d", "-perm", "-0002", "!", "-perm", "-1000"])
    entries = []
    for d in found:
        if d:
            subprocess.run(["chmod", "a+t", d], capture_output=True)
            entries.append(RollbackEntry(
                action=f"set sticky bit on {d}",
                undo=[["chmod", "o-t", d]],
            ))
    return entries


register(Control(
    id="6.1.12",
    title="Ensure sticky bit is set on all world-writable directories",
    section="filesystem",
    check=_check_sticky_bit,
    fix=_fix_sticky_bit,
))
