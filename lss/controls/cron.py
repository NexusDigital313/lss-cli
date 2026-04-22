"""CIS Section 5.1 — Cron and at configuration."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

from lss.lib import journal
from lss.lib.registry import Control, CheckResult, RollbackEntry, register


# ---- CIS 5.1.1: Ensure cron daemon is enabled and running ----

def _check_cron_enabled() -> CheckResult:
    r = subprocess.run(["systemctl", "is-enabled", "cron"], capture_output=True, text=True)
    enabled = r.stdout.strip() == "enabled"
    r2 = subprocess.run(["systemctl", "is-active", "cron"], capture_output=True, text=True)
    active = r2.stdout.strip() == "active"
    if enabled and active:
        return CheckResult("pass")
    issues = []
    if not enabled:
        issues.append("not enabled")
    if not active:
        issues.append("not active")
    return CheckResult("fail", f"cron: {', '.join(issues)}")


def _fix_cron_enabled() -> list[RollbackEntry]:
    entries = []
    r = subprocess.run(["systemctl", "enable", "cron"], capture_output=True, text=True)
    if r.returncode == 0:
        entries.append(RollbackEntry(action="enabled cron", undo=[["systemctl", "disable", "cron"]]))
    r = subprocess.run(["systemctl", "start", "cron"], capture_output=True, text=True)
    if r.returncode == 0:
        entries.append(RollbackEntry(action="started cron", undo=[["systemctl", "stop", "cron"]]))
    return entries


register(Control(
    id="5.1.1",
    title="Ensure cron daemon is enabled and running",
    section="cron",
    check=_check_cron_enabled,
    fix=_fix_cron_enabled,
))


# ---- CIS 5.1.2-5.1.7: Ensure permissions on cron files/directories ----

_CRON_PATHS = [
    ("5.1.2", "Ensure permissions on /etc/crontab are configured", "/etc/crontab", 0o600),
    ("5.1.3", "Ensure permissions on /etc/cron.hourly are configured", "/etc/cron.hourly", 0o700),
    ("5.1.4", "Ensure permissions on /etc/cron.daily are configured", "/etc/cron.daily", 0o700),
    ("5.1.5", "Ensure permissions on /etc/cron.weekly are configured", "/etc/cron.weekly", 0o700),
    ("5.1.6", "Ensure permissions on /etc/cron.monthly are configured", "/etc/cron.monthly", 0o700),
    ("5.1.7", "Ensure permissions on /etc/cron.d are configured", "/etc/cron.d", 0o700),
]

for _id, _title, _path, _mode in _CRON_PATHS:
    path, mode = _path, _mode

    def _make_check(p, m):
        def check():
            pp = Path(p)
            if not pp.exists():
                return CheckResult("warn", f"{p} not found")
            st = pp.stat()
            actual = stat.S_IMODE(st.st_mode)
            if actual & ~m:
                return CheckResult("fail", f"mode={oct(actual)}, expected: {oct(m)} or stricter")
            if st.st_uid != 0:
                return CheckResult("fail", f"uid={st.st_uid}, expected: 0")
            if st.st_gid != 0:
                return CheckResult("fail", f"gid={st.st_gid}, expected: 0")
            return CheckResult("pass")
        return check

    def _make_fix(p, m):
        def fix():
            st = Path(p).stat()
            old_mode_str = f"{stat.S_IMODE(st.st_mode):04o}"
            old_uid = st.st_uid
            old_gid = st.st_gid
            os.chmod(p, m)
            os.chown(p, 0, 0)
            return [RollbackEntry(
                action=f"set {p} to {m:04o} root:root",
                undo=[
                    ["chmod", old_mode_str, p],
                    ["chown", f"{old_uid}:{old_gid}", p],
                ],
                path=p,
            )]
        return fix

    register(Control(
        id=_id,
        title=_title,
        section="cron",
        check=_make_check(path, mode),
        fix=_make_fix(path, mode),
    ))


# ---- CIS 5.1.8: Ensure cron is restricted to authorized users ----

def _check_cron_allow() -> CheckResult:
    deny = Path("/etc/cron.deny")
    allow = Path("/etc/cron.allow")
    if deny.exists():
        return CheckResult("fail", "/etc/cron.deny exists — use cron.allow instead")
    if not allow.exists():
        return CheckResult("fail", "/etc/cron.allow does not exist")
    st = allow.stat()
    if stat.S_IMODE(st.st_mode) & ~0o640:
        return CheckResult("fail", f"cron.allow mode={oct(stat.S_IMODE(st.st_mode))}, expected: 0640 or stricter")
    return CheckResult("pass")


def _fix_cron_allow() -> list[RollbackEntry]:
    entries = []
    deny = Path("/etc/cron.deny")
    if deny.exists():
        bkp = journal.backup_file(str(deny))
        deny.unlink()
        entries.append(RollbackEntry(
            action="removed /etc/cron.deny",
            path=str(deny),
            backup=bkp,
        ))

    allow = Path("/etc/cron.allow")
    if not allow.exists():
        allow.write_text("root\n")
        os.chmod(str(allow), 0o640)
        os.chown(str(allow), 0, 0)
        entries.append(RollbackEntry(
            action="created /etc/cron.allow with root only",
            undo=[["rm", "-f", str(allow)]],
            path=str(allow),
        ))
    else:
        os.chmod(str(allow), 0o640)

    return entries


register(Control(
    id="5.1.8",
    title="Ensure cron is restricted to authorized users",
    section="cron",
    check=_check_cron_allow,
    fix=_fix_cron_allow,
))


# ---- CIS 5.1.9: Ensure at is restricted to authorized users ----

def _check_at_allow() -> CheckResult:
    deny = Path("/etc/at.deny")
    allow = Path("/etc/at.allow")
    # If at is not installed, not applicable
    r = subprocess.run(["which", "at"], capture_output=True, text=True)
    if r.returncode != 0:
        return CheckResult("pass", "at not installed")
    if deny.exists():
        return CheckResult("fail", "/etc/at.deny exists — use at.allow instead")
    if not allow.exists():
        return CheckResult("fail", "/etc/at.allow does not exist")
    return CheckResult("pass")


def _fix_at_allow() -> list[RollbackEntry]:
    entries = []
    deny = Path("/etc/at.deny")
    if deny.exists():
        bkp = journal.backup_file(str(deny))
        deny.unlink()
        entries.append(RollbackEntry(
            action="removed /etc/at.deny",
            path=str(deny),
            backup=bkp,
        ))

    allow = Path("/etc/at.allow")
    if not allow.exists():
        allow.write_text("root\n")
        os.chmod(str(allow), 0o640)
        os.chown(str(allow), 0, 0)
        entries.append(RollbackEntry(
            action="created /etc/at.allow with root only",
            undo=[["rm", "-f", str(allow)]],
            path=str(allow),
        ))

    return entries


register(Control(
    id="5.1.9",
    title="Ensure at is restricted to authorized users",
    section="cron",
    check=_check_at_allow,
    fix=_fix_at_allow,
))