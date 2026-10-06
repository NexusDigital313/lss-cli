# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file, 
# via any medium, is strictly prohibited without explicit written authorization.

"""CIS Section 5.3 / 5.4 / 6.2 — Authentication, password policy, and access controls."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from lss.lib import authconf, journal
from lss.lib.registry import Control, CheckResult, RollbackEntry, register


PWQUALITY_CONF = "/etc/security/pwquality.conf"
PWQUALITY_CONF_D = "/etc/security/pwquality.conf.d"
PASSWORD_STACKS = ("/etc/pam.d/common-password", "/etc/pam.d/system-auth", "/etc/pam.d/password-auth")
LOGIN_DEFS = "/etc/login.defs"
SHADOW = "/etc/shadow"
PASSWD = "/etc/passwd"
PAM_SU = "/etc/pam.d/su"
# Places CIS looks for a umask that would override login.defs.
PROFILE_D = "/etc/profile.d"
UMASK_SHELL_FILES = ("/etc/profile", "/etc/bashrc", "/etc/bash.bashrc")
UMASK_PAM_FILES = ("/etc/pam.d/common-session", "/etc/pam.d/common-session-noninteractive",
                   "/etc/pam.d/postlogin")


# ---- CIS 5.3.4: Ensure password minimum length is 14 or more ----

def _check_password_minlen() -> CheckResult:
    # pwquality.conf.d, then pwquality.conf, then the module argument: the
    # last one wins. pam_cracklib reads only its arguments (default 9);
    # pam_pwquality's built-in default is 8. Neither counts unless the module
    # is loaded by an uncommented, enforcing password line.
    try:
        vals, loaded = authconf.pwquality_effective(
            "minlen", Path(PWQUALITY_CONF), Path(PWQUALITY_CONF_D),
            [Path(p) for p in PASSWORD_STACKS])
    except OSError as e:
        return CheckResult("warn", f"could not read pwquality/PAM config: {e}")
    bad = []
    for where, val in vals:
        try:
            ok = val is not None and int(val) >= 14
        except ValueError:
            ok = False
        if not ok:
            bad.append(where + (" (module default 8-9)" if val is None else ""))
    if bad:
        return CheckResult("fail", "; ".join(bad) + ", recommended: minlen ≥ 14")
    if not loaded:
        return CheckResult(
            "manual",
            "minlen is set but pam_pwquality.so is not loaded (uncommented, "
            "required/requisite) in the password PAM stack, so it is NOT enforced. "
            "On Debian/Ubuntu: `sudo apt install libpam-pwquality`; on RHEL: "
            "`authselect enable-feature with-pwquality`.",
        )
    return CheckResult("pass")


def _fix_password_minlen() -> list[RollbackEntry]:
    # pwquality.conf is read after pwquality.conf.d, so this value wins over
    # any drop-in. Only uncommented lines are rewritten.
    conf = Path(PWQUALITY_CONF)
    bkp = journal.backup_file(str(conf))
    if not conf.exists():
        conf.write_text("# Created by LSS\n")
    authconf.set_conf_key(conf, "minlen", "minlen = 14")
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


# ---- CIS 5.4.1.x: password aging ----
#
# login.defs only sets defaults for accounts created later; the aging that
# applies to an existing account is in its /etc/shadow fields. Like the CIS
# audit, every account with a password hash is checked too. The fixers do NOT
# chage existing accounts: shortening max/inactive on an account whose
# password is already old can expire or disable it on the spot (lockout).
# The detail names each violating account and the chage command instead.

def _get_login_def(key: str) -> str | None:
    """Value as shadow-utils reads it (last uncommented occurrence). Raises
    OSError when login.defs exists but cannot be read."""
    p = Path(LOGIN_DEFS)
    if not p.exists():
        return None
    return authconf.login_defs_value(p.read_text(), key)


def _set_login_def(key: str, value: str) -> RollbackEntry:
    p = Path(LOGIN_DEFS)
    bkp = journal.backup_file(str(p))
    authconf.set_conf_key(p, key, f"{key}\t{value}")
    return RollbackEntry(
        action=f"set {key} = {value} in login.defs",
        path=str(p),
        backup=bkp,
    )


def _shadow_violations(idx: int, ok) -> list[str]:
    """Accounts with a password hash whose shadow field `idx` fails `ok(int)`.
    An empty field (no limit) is a violation. Raises OSError if unreadable."""
    bad = []
    for line in Path(SHADOW).read_text().splitlines():
        f = line.split(":")
        if len(f) < 8 or not f[1].startswith("$"):
            continue
        try:
            good = ok(int(f[idx]))
        except ValueError:
            good = False
        if not good:
            bad.append(f"{f[0]}({f[idx] or 'unset'})")
    return bad


def _aging_check(key: str, ok, rec: str, idx: int, chage: str) -> CheckResult:
    try:
        val = _get_login_def(key)
    except OSError as e:
        return CheckResult("warn", f"login.defs not readable: {e}")
    if val is None:
        return CheckResult("warn", f"{key} not set in login.defs")
    try:
        n = int(val)
    except ValueError:
        return CheckResult("fail", f"{key}={val}")
    if not ok(n):
        return CheckResult("fail", f"{key}={n}, recommended: {rec}")
    return _existing_accounts(key, idx, ok, rec, chage)


def _existing_accounts(what: str, idx: int, ok, rec: str, chage: str) -> CheckResult:
    try:
        bad = _shadow_violations(idx, ok)
    except OSError as e:
        return CheckResult("warn", f"{what} default is compliant, but existing accounts "
                                   f"could not be verified ({SHADOW} not readable: {e})")
    if bad:
        return CheckResult(
            "fail",
            f"{what} default is compliant but only applies to new accounts; existing "
            f"accounts ({rec} required): {', '.join(bad)} — fix each with "
            f"`sudo chage {chage} <user>`",
        )
    return CheckResult("pass")


# ---- CIS 5.4.1.1: Ensure password expiration is 365 days or less ----

def _max_ok(n: int) -> bool:
    return 1 <= n <= 365


def _check_pass_max_days() -> CheckResult:
    return _aging_check("PASS_MAX_DAYS", _max_ok, "1-365", 4, "--maxdays 365")


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
    return _aging_check("PASS_MIN_DAYS", lambda n: n >= 1, "≥ 1", 3, "--mindays 1")


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
    return _aging_check("PASS_WARN_AGE", lambda n: n >= 7, "≥ 7", 5, "--warndays 7")


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
#
# Compliant means the mask covers 027 bit for bit: 077 is fine, 070 is not
# (it leaves read/write/execute open to others) although 070 > 027
# numerically. A login shell applies login.defs UMASK (via
# pam_umask/login) and then whatever /etc/profile, /etc/profile.d/*.sh and the
# bashrc files set, so a weaker umask in any of those wins in practice.

_UMASK_RE = re.compile(r"(?:^|[\s;&|(])umask\s+(?:-S\s+)?([^\s;&|)]+)")


def _umask_settings() -> list[tuple[str, str]]:
    """(where, value) for every umask setting CIS looks at. Raises OSError."""
    found: list[tuple[str, str]] = []
    val = _get_login_def("UMASK")
    if val is not None:
        found.append((f"{LOGIN_DEFS} UMASK", val))
    d = Path(PROFILE_D)
    shell = sorted(d.glob("*.sh")) if d.is_dir() else []
    shell += [Path(f) for f in UMASK_SHELL_FILES]
    for f in shell:
        if not f.exists():
            continue
        for line in f.read_text().splitlines():
            code = line.split("#", 1)[0]
            for m in _UMASK_RE.finditer(code):
                found.append((str(f), m.group(1)))
    for f in UMASK_PAM_FILES:
        p = Path(f)
        if not p.exists():
            continue
        for ln in authconf.pam_lines(p.read_text()):
            if ln.module == "pam_umask.so" and ln.arg("umask") is not None:
                found.append((f"pam_umask in {f}", ln.arg("umask")))
    return found


def _check_umask() -> CheckResult:
    try:
        settings = _umask_settings()
    except OSError as e:
        return CheckResult("warn", f"could not read umask configuration: {e}")
    if not settings:
        return CheckResult("warn", "UMASK not set in login.defs or any profile/bashrc file")
    weak = []
    for where, val in settings:
        mask = authconf.parse_umask(val)
        if mask is None or not authconf.umask_ok(mask):
            weak.append(f"{where}: umask {val}")
    if weak:
        return CheckResult("fail", "; ".join(weak) + " — recommended: 027 or stricter "
                                   "(every bit of 027 masked)")
    return CheckResult("pass")


def _fix_umask() -> list[RollbackEntry]:
    # Sets the login.defs default only; a weaker umask in a profile/bashrc
    # file is reported by the check with its file name, for a manual edit.
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
    pam_su = Path(PAM_SU)
    if not pam_su.exists():
        return CheckResult("warn", "/etc/pam.d/su not found")
    try:
        su_lines = pam_su.read_text().splitlines()
    except OSError:
        return CheckResult("warn", "/etc/pam.d/su not readable — cannot verify su restriction")
    # Only an enforcing auth line restricts su: `deny` inverts the test (it
    # lets everyone NOT in the group through), and CIS requires use_uid and an
    # explicit group=. Linux-PAM drops everything after '#'.
    for ln in authconf.pam_lines("\n".join(su_lines)):
        if (ln.type == "auth" and ln.module == "pam_wheel.so"
                and ln.control in ("required", "requisite")
                and "deny" not in ln.args and "use_uid" in ln.args and ln.arg("group")):
            return CheckResult("pass", f"su restricted to group {ln.arg('group')}")
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
    malformed = []
    passwd = Path(PASSWD)
    if not passwd.exists():
        return CheckResult("warn", "/etc/passwd not found")
    try:
        passwd_lines = passwd.read_text().splitlines()
    except OSError:
        return CheckResult("warn", "/etc/passwd not readable — cannot verify UID 0 accounts")
    for line in passwd_lines:
        parts = line.split(":")
        if len(parts) < 3 or parts[0][:1] in ("", "+", "-"):
            continue
        # Compare numerically: the kernel and glibc read "00" or "000" as 0.
        try:
            uid = int(parts[2])
        except ValueError:
            malformed.append(parts[0])
            continue
        if uid == 0 and parts[0] != "root":
            uid0_users.append(parts[0])
    if uid0_users:
        return CheckResult("fail", f"non-root UID 0 accounts: {','.join(uid0_users)}")
    if malformed:
        return CheckResult("warn", f"non-numeric UID in /etc/passwd for: {','.join(malformed)}")
    return CheckResult("pass")


register(Control(
    id="6.2.1",
    title="Ensure root is the only UID 0 account",
    section="users",
    level=1,
    check=_check_uid_zero,
    fix=None,  # Requires human review — can't auto-remove accounts
))


# ---- CIS 6.2.2: Ensure root GID is 0 ----

def _gid_is_zero(gid: str) -> bool:
    try:
        return int(gid) == 0
    except ValueError:
        return False


def _check_root_gid() -> CheckResult:
    passwd = Path(PASSWD)
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
            if _gid_is_zero(parts[3]):
                return CheckResult("pass")
            return CheckResult("fail", f"root GID={parts[3]}, expected: 0")
    return CheckResult("fail", "root account not found in /etc/passwd")


def _fix_root_gid() -> list[RollbackEntry]:
    """Set root's primary GID to 0 via usermod."""
    passwd = Path(PASSWD)
    if not passwd.exists():
        return []
    prev_gid = None
    for line in passwd.read_text().splitlines():
        parts = line.split(":")
        if parts and parts[0] == "root" and len(parts) >= 4:
            prev_gid = parts[3]
            break
    if prev_gid is None or _gid_is_zero(prev_gid):
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
                    return _existing_accounts("INACTIVE", 6, lambda d: 0 <= d <= 30,
                                              "0-30", "--inactive 30")
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
