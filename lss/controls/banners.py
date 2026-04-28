"""CIS Section 1.7 — Warning banners."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from lss.lib import journal
from lss.lib.registry import Control, CheckResult, RollbackEntry, register

BANNER_TEXT = "Authorized uses only. All activity may be monitored and reported.\n"

# Check that banner doesn't contain OS info leaks
_OS_LEAK_PATTERNS = [r"\\m", r"\\r", r"\\s", r"\\v", r"\\S", r"Ubuntu", r"Debian", r"Kali"]


def _has_os_info(text: str) -> bool:
    for pat in _OS_LEAK_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            return True
    return False


# ---- CIS 1.7.1: Ensure message of the day is configured properly ----

def _check_motd() -> CheckResult:
    p = Path("/etc/motd")
    if not p.exists():
        return CheckResult("pass", "no /etc/motd")
    text = p.read_text()
    if not text.strip():
        return CheckResult("pass")
    if _has_os_info(text):
        return CheckResult("fail", "/etc/motd contains OS information")
    st = p.stat()
    if stat.S_IMODE(st.st_mode) & ~0o644:
        return CheckResult("fail", f"mode={oct(stat.S_IMODE(st.st_mode))}")
    return CheckResult("pass")


def _fix_motd() -> list[RollbackEntry]:
    p = Path("/etc/motd")
    if p.exists() and _has_os_info(p.read_text()):
        bkp = journal.backup_file(str(p))
        p.write_text(BANNER_TEXT)
        os.chmod(str(p), 0o644)
        return [RollbackEntry(
            action="replaced /etc/motd with clean banner",
            path=str(p),
            backup=bkp,
        )]
    return []


register(Control(
    id="1.7.1",
    title="Ensure message of the day is configured properly",
    section="banners",
    check=_check_motd,
    fix=_fix_motd,
))


# ---- CIS 1.7.2: Ensure local login warning banner is configured ----

def _check_issue() -> CheckResult:
    p = Path("/etc/issue")
    if not p.exists():
        return CheckResult("fail", "/etc/issue not found")
    text = p.read_text()
    if not text.strip():
        return CheckResult("fail", "/etc/issue is empty")
    if _has_os_info(text):
        return CheckResult("fail", "/etc/issue contains OS information")
    st = p.stat()
    if stat.S_IMODE(st.st_mode) & ~0o644:
        return CheckResult("fail", f"mode={oct(stat.S_IMODE(st.st_mode))}")
    return CheckResult("pass")


def _fix_issue() -> list[RollbackEntry]:
    p = Path("/etc/issue")
    bkp = journal.backup_file(str(p))  # "" if file did not exist
    p.write_text(BANNER_TEXT)
    os.chmod(str(p), 0o644)
    # If we created the file (no prior backup), undo by removing it.
    # Otherwise the backup will restore the original on rollback.
    return [RollbackEntry(
        action="set /etc/issue to authorized-use banner",
        path=str(p),
        backup=bkp,
        undo=[] if bkp else [["rm", "-f", str(p)]],
    )]


register(Control(
    id="1.7.2",
    title="Ensure local login warning banner is configured properly",
    section="banners",
    check=_check_issue,
    fix=_fix_issue,
))


# ---- CIS 1.7.3: Ensure remote login warning banner is configured ----

def _check_issue_net() -> CheckResult:
    p = Path("/etc/issue.net")
    if not p.exists():
        return CheckResult("fail", "/etc/issue.net not found")
    text = p.read_text()
    if not text.strip():
        return CheckResult("fail", "/etc/issue.net is empty")
    if _has_os_info(text):
        return CheckResult("fail", "/etc/issue.net contains OS information")
    st = p.stat()
    if stat.S_IMODE(st.st_mode) & ~0o644:
        return CheckResult("fail", f"mode={oct(stat.S_IMODE(st.st_mode))}")
    return CheckResult("pass")


def _fix_issue_net() -> list[RollbackEntry]:
    p = Path("/etc/issue.net")
    bkp = journal.backup_file(str(p))
    p.write_text(BANNER_TEXT)
    os.chmod(str(p), 0o644)
    return [RollbackEntry(
        action="set /etc/issue.net to authorized-use banner",
        path=str(p),
        backup=bkp,
        undo=[] if bkp else [["rm", "-f", str(p)]],
    )]


register(Control(
    id="1.7.3",
    title="Ensure remote login warning banner is configured properly",
    section="banners",
    check=_check_issue_net,
    fix=_fix_issue_net,
))


def _fix_banner_perms(path_str: str) -> list[RollbackEntry]:
    """Set ownership to root:root and mode to 0644 on a banner file.

    Records the pre-change owner/mode so rollback can restore exactly.
    No-ops if the file does not exist.
    """
    p = Path(path_str)
    if not p.exists():
        return []
    st = p.stat()
    prev_uid, prev_gid = st.st_uid, st.st_gid
    prev_mode = stat.S_IMODE(st.st_mode)
    os.chown(path_str, 0, 0)
    os.chmod(path_str, 0o644)
    return [RollbackEntry(
        action=f"set {path_str} to root:root 0644",
        undo=[
            ["chown", f"{prev_uid}:{prev_gid}", path_str],
            ["chmod", oct(prev_mode)[2:].zfill(4), path_str],
        ],
    )]


# ---- CIS 1.7.4: Ensure permissions on /etc/motd are configured ----

def _check_motd_perms() -> CheckResult:
    p = Path("/etc/motd")
    if not p.exists():
        return CheckResult("pass", "no /etc/motd")
    st = p.stat()
    if st.st_uid != 0 or st.st_gid != 0:
        return CheckResult("fail", f"owner={st.st_uid}:{st.st_gid}, expected: 0:0")
    if stat.S_IMODE(st.st_mode) & ~0o644:
        return CheckResult("fail", f"mode={oct(stat.S_IMODE(st.st_mode))}, expected: 0644 or stricter")
    return CheckResult("pass")


register(Control(
    id="1.7.4",
    title="Ensure permissions on /etc/motd are configured",
    section="banners",
    check=_check_motd_perms,
    fix=lambda: _fix_banner_perms("/etc/motd"),
))


# ---- CIS 1.7.5: Ensure permissions on /etc/issue are configured ----

def _check_issue_perms() -> CheckResult:
    p = Path("/etc/issue")
    if not p.exists():
        return CheckResult("warn", "/etc/issue not found")
    st = p.stat()
    if st.st_uid != 0 or st.st_gid != 0:
        return CheckResult("fail", f"owner={st.st_uid}:{st.st_gid}")
    if stat.S_IMODE(st.st_mode) & ~0o644:
        return CheckResult("fail", f"mode={oct(stat.S_IMODE(st.st_mode))}")
    return CheckResult("pass")


register(Control(
    id="1.7.5",
    title="Ensure permissions on /etc/issue are configured",
    section="banners",
    check=_check_issue_perms,
    fix=lambda: _fix_banner_perms("/etc/issue"),
))


# ---- CIS 1.7.6: Ensure permissions on /etc/issue.net are configured ----

def _check_issue_net_perms() -> CheckResult:
    p = Path("/etc/issue.net")
    if not p.exists():
        return CheckResult("warn", "/etc/issue.net not found")
    st = p.stat()
    if st.st_uid != 0 or st.st_gid != 0:
        return CheckResult("fail", f"owner={st.st_uid}:{st.st_gid}")
    if stat.S_IMODE(st.st_mode) & ~0o644:
        return CheckResult("fail", f"mode={oct(stat.S_IMODE(st.st_mode))}")
    return CheckResult("pass")


register(Control(
    id="1.7.6",
    title="Ensure permissions on /etc/issue.net are configured",
    section="banners",
    check=_check_issue_net_perms,
    fix=lambda: _fix_banner_perms("/etc/issue.net"),
))
