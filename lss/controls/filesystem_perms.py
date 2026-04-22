"""CIS Sections 1.1 / 1.4 / 6.1 — Filesystem permissions and mount options."""

from __future__ import annotations

import subprocess
from pathlib import Path

from lss.lib import journal
from lss.lib.registry import Control, CheckResult, RollbackEntry, register
from lss.lib.sysctl import set_sysctl


# ---- CIS 1.4.1: Ensure core dumps are restricted ----

def _check_core_dumps() -> CheckResult:
    # Check limits.conf
    limits_ok = False
    for p in [Path("/etc/security/limits.conf")] + list(Path("/etc/security/limits.d/").glob("*.conf")):
        if p.exists():
            for line in p.read_text().splitlines():
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                if "core" in line and "0" in line:
                    limits_ok = True
                    break

    # Check sysctl
    try:
        r = subprocess.run(["sysctl", "-n", "fs.suid_dumpable"], capture_output=True, text=True)
        suid_dumpable = r.stdout.strip()
    except FileNotFoundError:
        suid_dumpable = "unknown"

    if limits_ok and suid_dumpable == "0":
        return CheckResult("pass")

    issues = []
    if not limits_ok:
        issues.append("no 'hard core 0' in limits.conf")
    if suid_dumpable != "0":
        issues.append(f"fs.suid_dumpable={suid_dumpable}")
    return CheckResult("fail", "; ".join(issues))


def _fix_core_dumps() -> list[RollbackEntry]:
    entries = []

    # Set limits — back up if the file already exists, otherwise undo by rm
    conf = Path("/etc/security/limits.d/80-lss.conf")
    if not conf.exists() or "hard core 0" not in conf.read_text():
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
        fstab.write_text(text + "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0\n")
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


# ---- CIS 6.1.9: Ensure no world-writable files exist ----

def _check_world_writable() -> CheckResult:
    try:
        r = subprocess.run(
            ["find", "/", "-xdev", "-type", "f", "-perm", "-0002",
             "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"],
            capture_output=True, text=True, timeout=30,
        )
        files = [f for f in r.stdout.strip().splitlines() if f]
        if not files:
            return CheckResult("pass")
        count = len(files)
        sample = files[0] if count == 1 else f"{files[0]} (+{count-1} more)"
        return CheckResult("fail", f"{count} world-writable file(s): {sample}")
    except subprocess.TimeoutExpired:
        return CheckResult("warn", "scan timed out")


register(Control(
    id="6.1.9",
    title="Ensure no world-writable files exist",
    section="filesystem",
    level=1,
    check=_check_world_writable,
    fix=None,  # No auto-fix — too risky to chmod unknown files
))


# ---- CIS 6.1.10: Ensure no unowned files or directories exist ----

def _check_unowned() -> CheckResult:
    try:
        r = subprocess.run(
            ["find", "/", "-xdev", "-nouser",
             "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"],
            capture_output=True, text=True, timeout=30,
        )
        files = [f for f in r.stdout.strip().splitlines() if f]
        if not files:
            return CheckResult("pass")
        count = len(files)
        sample = files[0] if count == 1 else f"{files[0]} (+{count-1} more)"
        return CheckResult("warn", f"{count} unowned file(s): {sample}")
    except subprocess.TimeoutExpired:
        return CheckResult("warn", "scan timed out")


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
    try:
        r = subprocess.run(
            ["find", "/", "-xdev", "-nogroup",
             "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"],
            capture_output=True, text=True, timeout=30,
        )
        files = [f for f in r.stdout.strip().splitlines() if f]
        if not files:
            return CheckResult("pass")
        count = len(files)
        sample = files[0] if count == 1 else f"{files[0]} (+{count-1} more)"
        return CheckResult("warn", f"{count} ungrouped file(s): {sample}")
    except subprocess.TimeoutExpired:
        return CheckResult("warn", "scan timed out")


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
    try:
        r = subprocess.run(
            ["find", "/", "-xdev", "-type", "d", "-perm", "-0002",
             "!", "-perm", "-1000",
             "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"],
            capture_output=True, text=True, timeout=30,
        )
        dirs = [d for d in r.stdout.strip().splitlines() if d]
        if not dirs:
            return CheckResult("pass")
        count = len(dirs)
        sample = dirs[0] if count == 1 else f"{dirs[0]} (+{count-1} more)"
        return CheckResult("fail", f"{count} world-writable dir(s) without sticky bit: {sample}")
    except subprocess.TimeoutExpired:
        return CheckResult("warn", "scan timed out")


def _fix_sticky_bit() -> list[RollbackEntry]:
    r = subprocess.run(
        ["find", "/", "-xdev", "-type", "d", "-perm", "-0002",
         "!", "-perm", "-1000",
         "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"],
        capture_output=True, text=True, timeout=30,
    )
    entries = []
    for d in r.stdout.strip().splitlines():
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