# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file, 
# via any medium, is strictly prohibited without explicit written authorization.

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
    try:
        r = subprocess.run(["systemctl", "is-enabled", "cron"], capture_output=True, text=True)
        r2 = subprocess.run(["systemctl", "is-active", "cron"], capture_output=True, text=True)
    except FileNotFoundError:
        return CheckResult("warn", "systemctl not found — cannot verify cron daemon state")
    enabled = r.stdout.strip() == "enabled"
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
            pp = Path(p)
            # harden fixes any non-pass status — including the "warn" this
            # control returns when the path is absent. Guard so a missing cron
            # directory doesn't raise FileNotFoundError from stat() and abort.
            if not pp.exists():
                return []
            st = pp.stat()
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
        # cron.allow already exists — tighten its mode, but RECORD the change
        # so rollback can restore the original permissions. Without an entry the
        # chmod was silently irreversible.
        old_mode = stat.S_IMODE(allow.stat().st_mode)
        if old_mode != 0o640:
            os.chmod(str(allow), 0o640)
            entries.append(RollbackEntry(
                action=f"set /etc/cron.allow mode to 0640 (was {old_mode:04o})",
                undo=[["chmod", f"{old_mode:04o}", str(allow)]],
                path=str(allow),
            ))

    return entries


register(Control(
    id="5.1.8",
    title="Ensure cron is restricted to authorized users",
    section="cron",
    check=_check_cron_allow,
    fix=_fix_cron_allow,
))


# ---- CIS 5.1.9: Ensure at is restricted to authorized users ----

AT_ALLOW = "/etc/at.allow"
AT_DENY = "/etc/at.deny"


def _stat_file(path: str) -> os.stat_result:
    return os.stat(path)


def _at_allowed_gids() -> set[int]:
    """root, plus daemon (Debian's at ships its files root:daemon)."""
    import grp
    gids = {0}
    try:
        gids.add(grp.getgrnam("daemon").gr_gid)
    except KeyError:
        pass
    return gids


def _check_at_allow() -> CheckResult:
    deny = Path(AT_DENY)
    allow = Path(AT_ALLOW)
    # If at is not installed, not applicable
    try:
        r = subprocess.run(["which", "at"], capture_output=True, text=True)
    except FileNotFoundError:
        return CheckResult("warn", "which not found — cannot verify whether at is installed")
    if r.returncode != 0:
        return CheckResult("pass", "at not installed")
    if deny.exists():
        return CheckResult("fail", f"{AT_DENY} exists — use at.allow instead")
    try:
        st = _stat_file(AT_ALLOW)
    except FileNotFoundError:
        return CheckResult("fail", f"{AT_ALLOW} does not exist")
    except OSError as e:
        return CheckResult("warn", f"cannot stat {AT_ALLOW}: {e.strerror or e}")
    # Anyone who can write at.allow can grant themselves `at`.
    issues = []
    if st.st_uid != 0:
        issues.append(f"owner uid={st.st_uid}, expected root")
    if st.st_gid not in _at_allowed_gids():
        issues.append(f"group gid={st.st_gid}, expected root or daemon")
    mode = stat.S_IMODE(st.st_mode)
    if mode & ~0o640:
        issues.append(f"mode={mode:04o}, expected 0640 or stricter")
    if issues:
        return CheckResult("fail", f"{AT_ALLOW}: " + ", ".join(issues))
    return CheckResult("pass")


def _fix_at_allow() -> list[RollbackEntry]:
    entries = []
    deny = Path(AT_DENY)
    if deny.exists():
        bkp = journal.backup_file(str(deny))
        deny.unlink()
        entries.append(RollbackEntry(
            action=f"removed {AT_DENY}",
            path=str(deny),
            backup=bkp,
        ))

    allow = Path(AT_ALLOW)
    if not allow.exists():
        allow.write_text("root\n")
        os.chmod(str(allow), 0o640)
        os.chown(str(allow), 0, 0)
        entries.append(RollbackEntry(
            action=f"created {AT_ALLOW} with root only",
            undo=[["rm", "-f", str(allow)]],
            path=str(allow),
        ))
        return entries

    # at.allow exists — fix ownership and tighten mode, recording the old
    # values so rollback restores them.
    st = _stat_file(AT_ALLOW)
    uid, gid = st.st_uid, st.st_gid
    if uid != 0 or gid not in _at_allowed_gids():
        new_gid = gid if gid in _at_allowed_gids() else 0
        os.chown(str(allow), 0, new_gid)
        entries.append(RollbackEntry(
            action=f"set {AT_ALLOW} owner to 0:{new_gid} (was {uid}:{gid})",
            undo=[["chown", f"{uid}:{gid}", str(allow)]],
            path=str(allow),
        ))
    old_mode = stat.S_IMODE(st.st_mode)
    if old_mode & ~0o640:
        new_mode = old_mode & 0o640
        os.chmod(str(allow), new_mode)
        entries.append(RollbackEntry(
            action=f"set {AT_ALLOW} mode to {new_mode:04o} (was {old_mode:04o})",
            undo=[["chmod", f"{old_mode:04o}", str(allow)]],
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