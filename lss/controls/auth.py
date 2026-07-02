"""CIS Section 5.3 / 5.4 / 6.2 — Authentication, password policy, and access controls."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from lss.lib import journal
from lss.lib.registry import Control, CheckResult, RollbackEntry, register


# ---- CIS 5.3.4: Ensure password minimum length is 14 or more ----

def _get_pam_minlen() -> int | None:
    """Read minlen from pam_pwquality or common-password."""
    # Check pwquality.conf first
    conf = Path("/etc/security/pwquality.conf")
    if conf.exists():
        try:
            conf_lines = conf.read_text().splitlines()
        except OSError:
            conf_lines = []
        for line in conf_lines:
            line = line.strip()
            if line.startswith("minlen"):
                m = re.search(r"minlen\s*=\s*(\d+)", line)
                if m:
                    return int(m.group(1))

    # Fallback: check pam common-password for pam_pwquality.so minlen=
    for pam_path in [
        "/etc/pam.d/common-password",   # Debian/Ubuntu
        "/etc/pam.d/system-auth",       # RHEL
    ]:
        p = Path(pam_path)
        if p.exists():
            try:
                pam_lines = p.read_text().splitlines()
            except OSError:
                pam_lines = []
            for line in pam_lines:
                if "pam_pwquality" in line or "pam_cracklib" in line:
                    m = re.search(r"minlen=(\d+)", line)
                    if m:
                        return int(m.group(1))

    return None


def _check_password_minlen() -> CheckResult:
    minlen = _get_pam_minlen()
    if minlen is None:
        return CheckResult("warn", "could not determine minlen — pwquality may not be configured")
    if minlen >= 14:
        return CheckResult("pass")
    return CheckResult("fail", f"minlen={minlen}, recommended: ≥ 14")


def _fix_password_minlen() -> list[RollbackEntry]:
    conf = Path("/etc/security/pwquality.conf")
    bkp = journal.backup_file(str(conf))
    if conf.exists():
        lines = conf.read_text().splitlines(keepends=True)
        found = False
        for i, line in enumerate(lines):
            if re.match(r"^\s*#?\s*minlen\s*=", line):
                lines[i] = "minlen = 14\n"
                found = True
                break
        if not found:
            lines.append("minlen = 14\n")
        conf.write_text("".join(lines))
    else:
        conf.write_text("# Created by LSS\nminlen = 14\n")
    return [RollbackEntry(
        action="set password minlen = 14",
        path=str(conf),
        backup=bkp,
        undo=[] if bkp else [["rm", "-f", str(conf)]],
    )]


register(Control(
    id="5.3.4",
    title="Ensure password minimum length is 14 or more",
    section="auth",
    check=_check_password_minlen,
    fix=_fix_password_minlen,
))


# ---- CIS 5.4.1.1: Ensure password expiration is 365 days or less ----

def _get_login_def(key: str) -> str | None:
    p = Path("/etc/login.defs")
    if not p.exists():
        return None
    try:
        def_lines = p.read_text().splitlines()
    except OSError:
        return None
    for line in def_lines:
        line = line.strip()
        if line.startswith("#") or not line:
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0] == key:
            return parts[1]
    return None


def _set_login_def(key: str, value: str) -> RollbackEntry:
    p = Path("/etc/login.defs")
    bkp = journal.backup_file(str(p))
    text = p.read_text()
    lines = text.splitlines(keepends=True)

    found = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        parts = stripped.split()
        if parts and parts[0] == key:
            lines[i] = f"{key}\t{value}\n"
            found = True
            break

    if not found:
        lines.append(f"{key}\t{value}\n")

    p.write_text("".join(lines))
    return RollbackEntry(
        action=f"set {key} = {value} in login.defs",
        path=str(p),
        backup=bkp,
    )


def _check_pass_max_days() -> CheckResult:
    val = _get_login_def("PASS_MAX_DAYS")
    if val is None:
        return CheckResult("warn", "PASS_MAX_DAYS not set in login.defs")
    try:
        n = int(val)
    except ValueError:
        return CheckResult("fail", f"PASS_MAX_DAYS={val}")
    if n <= 365:
        return CheckResult("pass")
    return CheckResult("fail", f"PASS_MAX_DAYS={n}, recommended: ≤ 365")


def _fix_pass_max_days() -> list[RollbackEntry]:
    return [_set_login_def("PASS_MAX_DAYS", "365")]


register(Control(
    id="5.4.1.1",
    title="Ensure password expiration is 365 days or less",
    section="auth",
    check=_check_pass_max_days,
    fix=_fix_pass_max_days,
))


# ---- CIS 5.4.1.2: Ensure minimum days between password changes is configured ----

def _check_pass_min_days() -> CheckResult:
    val = _get_login_def("PASS_MIN_DAYS")
    if val is None:
        return CheckResult("warn", "PASS_MIN_DAYS not set")
    try:
        n = int(val)
    except ValueError:
        return CheckResult("fail", f"PASS_MIN_DAYS={val}")
    if n >= 1:
        return CheckResult("pass")
    return CheckResult("fail", f"PASS_MIN_DAYS={n}, recommended: ≥ 1")


def _fix_pass_min_days() -> list[RollbackEntry]:
    return [_set_login_def("PASS_MIN_DAYS", "1")]


register(Control(
    id="5.4.1.2",
    title="Ensure minimum days between password changes is configured",
    section="auth",
    check=_check_pass_min_days,
    fix=_fix_pass_min_days,
))


# ---- CIS 5.4.1.3: Ensure password expiration warning days is 7 or more ----

def _check_pass_warn_age() -> CheckResult:
    val = _get_login_def("PASS_WARN_AGE")
    if val is None:
        return CheckResult("warn", "PASS_WARN_AGE not set")
    try:
        n = int(val)
    except ValueError:
        return CheckResult("fail", f"PASS_WARN_AGE={val}")
    if n >= 7:
        return CheckResult("pass")
    return CheckResult("fail", f"PASS_WARN_AGE={n}, recommended: ≥ 7")


def _fix_pass_warn_age() -> list[RollbackEntry]:
    return [_set_login_def("PASS_WARN_AGE", "7")]


register(Control(
    id="5.4.1.3",
    title="Ensure password expiration warning days is 7 or more",
    section="auth",
    check=_check_pass_warn_age,
    fix=_fix_pass_warn_age,
))


# ---- CIS 5.4.4: Ensure default user umask is 027 or more restrictive ----

def _check_umask() -> CheckResult:
    val = _get_login_def("UMASK")
    if val is None:
        return CheckResult("warn", "UMASK not set in login.defs")
    try:
        n = int(val, 8)
    except ValueError:
        return CheckResult("fail", f"UMASK={val}")
    if n >= 0o027:
        return CheckResult("pass")
    return CheckResult("fail", f"UMASK={val}, recommended: 027 or stricter")


def _fix_umask() -> list[RollbackEntry]:
    return [_set_login_def("UMASK", "027")]


register(Control(
    id="5.4.4",
    title="Ensure default user umask is 027 or more restrictive",
    section="auth",
    check=_check_umask,
    fix=_fix_umask,
))


# ---- CIS 5.6: Ensure access to the su command is restricted ----

def _check_su_restricted() -> CheckResult:
    pam_su = Path("/etc/pam.d/su")
    if not pam_su.exists():
        return CheckResult("warn", "/etc/pam.d/su not found")
    try:
        su_lines = pam_su.read_text().splitlines()
    except OSError:
        return CheckResult("warn", "/etc/pam.d/su not readable — cannot verify su restriction")
    for line in su_lines:
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if "pam_wheel.so" in stripped and "required" in stripped:
            return CheckResult("pass")
    return CheckResult(
        "manual",
        "pam_wheel.so not required in /etc/pam.d/su — add by hand: "
        "`auth required pam_wheel.so use_uid group=<admin-group>` "
        "(group is 'sudo' on Debian, 'wheel' on RHEL). Confirm a real admin is "
        "already IN that group first, or you lock everyone out of su.",
    )


def _fix_su_restricted() -> list[RollbackEntry]:
    pam_su = Path("/etc/pam.d/su")
    bkp = journal.backup_file(str(pam_su))
    text = pam_su.read_text()
    lines = text.splitlines(keepends=True)
    found = False
    for i, line in enumerate(lines):
        if "pam_wheel.so" in line:
            lines[i] = "auth required pam_wheel.so use_uid group=sudo\n"
            found = True
            break
    if not found:
        for i, line in enumerate(lines):
            if line.strip().startswith("auth"):
                lines.insert(i + 1, "auth required pam_wheel.so use_uid group=sudo\n")
                found = True
                break
    if found:
        pam_su.write_text("".join(lines))
    return [RollbackEntry(
        action="restricted su to sudo/wheel group via pam_wheel.so",
        path=str(pam_su),
        backup=bkp,
    )]


register(Control(
    id="5.6",
    title="Ensure access to the su command is restricted",
    section="auth",
    check=_check_su_restricted,
    fix=None,  # DEFANGED: hardcoded group=sudo (wrong on RHEL/wheel) + no non-empty-group check can lock everyone out of su. Apply by hand after verifying the admin group.
))


# ---- CIS 6.2.1: Ensure root is the only UID 0 account ----

def _check_uid_zero() -> CheckResult:
    uid0_users = []
    passwd = Path("/etc/passwd")
    if not passwd.exists():
        return CheckResult("warn", "/etc/passwd not found")
    try:
        passwd_lines = passwd.read_text().splitlines()
    except OSError:
        return CheckResult("warn", "/etc/passwd not readable — cannot verify UID 0 accounts")
    for line in passwd_lines:
        parts = line.split(":")
        if len(parts) >= 3 and parts[2] == "0" and parts[0] != "root":
            uid0_users.append(parts[0])
    if not uid0_users:
        return CheckResult("pass")
    return CheckResult("fail", f"non-root UID 0 accounts: {','.join(uid0_users)}")


register(Control(
    id="6.2.1",
    title="Ensure root is the only UID 0 account",
    section="users",
    level=1,
    check=_check_uid_zero,
    fix=None,  # Requires human review — can't auto-remove accounts
))


# ---- CIS 6.2.2: Ensure root GID is 0 ----

def _check_root_gid() -> CheckResult:
    passwd = Path("/etc/passwd")
    if not passwd.exists():
        return CheckResult("warn", "/etc/passwd not found")
    try:
        passwd_lines = passwd.read_text().splitlines()
    except OSError:
        return CheckResult("warn", "/etc/passwd not readable — cannot verify root GID")
    for line in passwd_lines:
        parts = line.split(":")
        if parts[0] == "root":
            if len(parts) < 4:
                return CheckResult("fail", "root entry in /etc/passwd is malformed")
            if parts[3] == "0":
                return CheckResult("pass")
            return CheckResult("fail", f"root GID={parts[3]}, expected: 0")
    return CheckResult("fail", "root account not found in /etc/passwd")


def _fix_root_gid() -> list[RollbackEntry]:
    """Set root's primary GID to 0 via usermod."""
    passwd = Path("/etc/passwd")
    if not passwd.exists():
        return []
    prev_gid = None
    for line in passwd.read_text().splitlines():
        parts = line.split(":")
        if parts and parts[0] == "root" and len(parts) >= 4:
            prev_gid = parts[3]
            break
    if prev_gid == "0" or prev_gid is None:
        return []
    r = subprocess.run(["usermod", "-g", "0", "root"], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"usermod failed: {r.stderr.strip()}")
    return [RollbackEntry(
        action=f"set root GID 0 (was {prev_gid})",
        undo=[["usermod", "-g", prev_gid, "root"]],
    )]


register(Control(
    id="6.2.2",
    title="Ensure root GID is 0",
    section="users",
    check=_check_root_gid,
    fix=_fix_root_gid,
))


# ---- CIS 5.4.1.5: Ensure inactive password lock is 30 days or less ----

def _check_inactive_lock() -> CheckResult:
    try:
        r = subprocess.run(["useradd", "-D"], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            if line.startswith("INACTIVE="):
                val = line.split("=")[1].strip()
                try:
                    n = int(val)
                except ValueError:
                    return CheckResult("fail", f"INACTIVE={val}")
                if 0 < n <= 30:
                    return CheckResult("pass")
                if n == -1:
                    return CheckResult("fail", "INACTIVE=-1 (disabled)")
                return CheckResult("fail", f"INACTIVE={n}, recommended: ≤ 30")
    except FileNotFoundError:
        pass
    return CheckResult("warn", "could not determine INACTIVE setting")


def _fix_inactive_lock() -> list[RollbackEntry]:
    # Capture the CURRENT default so rollback restores exactly what was there.
    # Hardcoding "-1" on undo would DISABLE inactive-lock on rollback even if
    # the box previously had a stricter value (e.g. 15), silently weakening it.
    prev = None
    r = subprocess.run(["useradd", "-D"], capture_output=True, text=True)
    for line in r.stdout.splitlines():
        if line.startswith("INACTIVE="):
            prev = line.split("=", 1)[1].strip()
            break
    undo_val = prev if prev not in (None, "") else "-1"
    subprocess.run(["useradd", "-D", "-f", "30"], capture_output=True, check=True)
    return [RollbackEntry(
        action=f"set default INACTIVE=30 (was {undo_val})",
        undo=[["useradd", "-D", "-f", undo_val]],
    )]


register(Control(
    id="5.4.1.4",
    title="Ensure inactive password lock is 30 days or less",
    section="auth",
    check=_check_inactive_lock,
    fix=_fix_inactive_lock,
))
