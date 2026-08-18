# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file, 
# via any medium, is strictly prohibited without explicit written authorization.

"""CIS Section 6.1 — System file permissions."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from lss.lib.registry import Control, CheckResult, RollbackEntry, register


def _check_file_perms(path: str, expected_mode: int, expected_uid: int = 0, expected_gid: int = 0) -> CheckResult:
    """Check that a file has the expected permissions and ownership."""
    p = Path(path)
    if not p.exists():
        return CheckResult("warn", f"{path} not found")
    try:
        st = p.stat()
    except OSError as e:
        return CheckResult("warn", f"cannot stat {path}: {e}")
    issues = []
    actual_mode = stat.S_IMODE(st.st_mode)
    # Check if actual mode is stricter than or equal to expected
    if actual_mode & ~expected_mode:
        issues.append(f"mode={oct(actual_mode)}, expected: {oct(expected_mode)} or stricter")
    if st.st_uid != expected_uid:
        issues.append(f"uid={st.st_uid}, expected: {expected_uid}")
    if st.st_gid != expected_gid:
        issues.append(f"gid={st.st_gid}, expected: {expected_gid}")
    if issues:
        return CheckResult("fail", "; ".join(issues))
    return CheckResult("pass")


def _fix_file_perms(path: str, mode: int, uid: int = 0, gid: int = 0) -> list[RollbackEntry]:
    """Set file permissions and ownership."""
    p = Path(path)
    if not p.exists():
        return []
    st = p.stat()
    old_mode_str = f"{stat.S_IMODE(st.st_mode):04o}"
    old_uid = st.st_uid
    old_gid = st.st_gid

    os.chmod(path, mode)
    os.chown(path, uid, gid)

    return [RollbackEntry(
        action=f"set {path} to {mode:04o} {uid}:{gid}",
        undo=[
            ["chmod", old_mode_str, path],
            ["chown", f"{old_uid}:{old_gid}", path],
        ],
        path=path,
    )]


# System file permission specs:
# (control_id, title, path, mode, uid, gid)
_FILE_PERMS = [
    ("6.1.1", "Ensure permissions on /etc/passwd are configured",
     "/etc/passwd", 0o644, 0, 0),
    ("6.1.2", "Ensure permissions on /etc/passwd- are configured",
     "/etc/passwd-", 0o644, 0, 0),
    ("6.1.3", "Ensure permissions on /etc/group are configured",
     "/etc/group", 0o644, 0, 0),
    ("6.1.4", "Ensure permissions on /etc/group- are configured",
     "/etc/group-", 0o644, 0, 0),
    ("6.1.5", "Ensure permissions on /etc/shadow are configured",
     "/etc/shadow", 0o640, 0, 42),  # gid 42 = shadow on Debian
    ("6.1.6", "Ensure permissions on /etc/shadow- are configured",
     "/etc/shadow-", 0o640, 0, 42),
    ("6.1.7", "Ensure permissions on /etc/gshadow are configured",
     "/etc/gshadow", 0o640, 0, 42),
    ("6.1.8", "Ensure permissions on /etc/gshadow- are configured",
     "/etc/gshadow-", 0o640, 0, 42),
]


def _get_shadow_gid() -> int:
    """Get the GID of the shadow group (varies by distro)."""
    import grp
    try:
        return grp.getgrnam("shadow").gr_gid
    except KeyError:
        return 0


for _id, _title, _path, _mode, _uid, _gid in _FILE_PERMS:
    path, mode, uid = _path, _mode, _uid

    def _make_check(p, m, u, g):
        def check():
            # Resolve shadow GID at runtime
            actual_gid = _get_shadow_gid() if g == 42 else g
            return _check_file_perms(p, m, u, actual_gid)
        return check

    def _make_fix(p, m, u, g):
        def fix():
            actual_gid = _get_shadow_gid() if g == 42 else g
            return _fix_file_perms(p, m, u, actual_gid)
        return fix

    register(Control(
        id=_id,
        title=_title,
        section="filesystem",
        check=_make_check(_path, _mode, _uid, _gid),
        fix=_make_fix(_path, _mode, _uid, _gid),
    ))


# ---- CIS 6.1.13: Ensure SUID/SGID files are reviewed ----

def _check_suid_sgid() -> CheckResult:
    """Audit-only: report count of SUID/SGID binaries."""
    import subprocess
    try:
        r = subprocess.run(
            ["find", "/", "-xdev", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")",
             "-type", "f",
             "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"],
            capture_output=True, text=True, timeout=120,
        )
        files = [f for f in r.stdout.strip().splitlines() if f]
        count = len(files)
        if count <= 30:
            return CheckResult("pass", f"{count} SUID/SGID binaries found")
        return CheckResult("warn", f"{count} SUID/SGID binaries — review recommended")
    except subprocess.TimeoutExpired:
        return CheckResult("warn", "scan timed out")
    except FileNotFoundError:
        return CheckResult("warn", "find not available — cannot scan for SUID/SGID files")
    except OSError as e:
        return CheckResult("warn", f"SUID/SGID scan failed: {e}")


register(Control(
    id="6.1.13",
    title="Audit SUID and SGID executables",
    section="filesystem",
    level=1,
    check=_check_suid_sgid,
    fix=None,  # Audit-only
))