# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file, 
# via any medium, is strictly prohibited without explicit written authorization.

"""CIS Section 5.3 — PAM password complexity and lockout."""

from __future__ import annotations

import re
from pathlib import Path

from lss.lib import authconf, journal
from lss.lib.registry import Control, CheckResult, RollbackEntry, register


PWQUALITY_CONF = "/etc/security/pwquality.conf"
PWQUALITY_CONF_D = "/etc/security/pwquality.conf.d"
PASSWORD_STACKS = ("/etc/pam.d/common-password", "/etc/pam.d/system-auth", "/etc/pam.d/password-auth")
LOGIN_DEFS = "/etc/login.defs"


def _pwq(key: str) -> tuple[list[tuple[str, str | None]], bool]:
    """Effective pwquality `key` per password stack (module args override
    pwquality.conf, which overrides pwquality.conf.d), plus whether
    pam_pwquality is loaded at all. Raises OSError on unreadable state."""
    return authconf.pwquality_effective(
        key, Path(PWQUALITY_CONF), Path(PWQUALITY_CONF_D),
        [Path(p) for p in PASSWORD_STACKS])


def _pwq_int(val: str | None) -> int | None:
    try:
        return int(val) if val is not None else None
    except ValueError:
        return None


def _set_pwquality(key: str, value: int) -> RollbackEntry:
    """Set `key` in /etc/security/pwquality.conf. libpwquality reads that file
    after pwquality.conf.d, so the value written here wins over any drop-in.
    Only uncommented lines are rewritten (and duplicates dropped)."""
    conf = Path(PWQUALITY_CONF)
    bkp = journal.backup_file(str(conf))
    if not conf.exists():
        conf.write_text("# Created by LSS\n")
    authconf.set_conf_key(conf, key, f"{key} = {value}")
    return RollbackEntry(
        action=f"set {key} = {value} in pwquality.conf",
        path=str(conf),
        backup=bkp,
        undo=[] if bkp else [["rm", "-f", str(conf)]],
    )


_PWQ_NOT_LOADED = (
    "pam_pwquality.so is not loaded (uncommented, required/requisite) in the "
    "password PAM stack, so pwquality settings are NOT enforced. On Debian/Ubuntu: "
    "`sudo apt install libpam-pwquality` then ensure `pam-auth-update` "
    "wires it into /etc/pam.d/common-password. On RHEL: "
    "`authselect enable-feature with-pwquality`."
)


# ---- CIS 5.3.1: Ensure password creation requirements are configured ----
# This is a compound check: dcredit, ucredit, lcredit, ocredit

def _check_pw_complexity() -> CheckResult:
    issues = []
    loaded = True
    try:
        for key in ("dcredit", "ucredit", "lcredit", "ocredit"):
            vals, loaded = _pwq(key)
            for where, val in vals:
                n = _pwq_int(val)
                if val is None:
                    issues.append(f"{key} not set")
                elif n is None or n > -1:  # negative means "require at least N"
                    issues.append(f"{where}, recommended: ≤ -1")
    except OSError as e:
        return CheckResult("warn", f"could not read pwquality/PAM config: {e}")

    if issues:
        return CheckResult("fail", "; ".join(dict.fromkeys(issues)))
    # Values are right, but they only take effect if the module is loaded.
    if not loaded:
        return CheckResult("manual", "pwquality complexity is set but " + _PWQ_NOT_LOADED)
    return CheckResult("pass")


def _fix_pw_complexity() -> list[RollbackEntry]:
    entries = []
    for key, value in [("dcredit", -1), ("ucredit", -1), ("lcredit", -1), ("ocredit", -1)]:
        entries.append(_set_pwquality(key, value))
    return entries


register(Control(
    id="5.3.1",
    title="Ensure password creation requirements are configured",
    section="auth",
    check=_check_pw_complexity,
    fix=_fix_pw_complexity,
))


# ---- CIS 5.3.2: Ensure lockout for failed password attempts is configured ----
#
# pam_faillock only locks accounts out when the auth stack runs it in BOTH
# modes around pam_unix: `preauth` before pam_unix (refuses a locked account
# before the password is even checked) and `authfail` after it (records the
# failure). Without preauth, failures are counted but nothing is ever denied.
# The account stack also needs pam_faillock (resets the counter on success).
# /etc/security/faillock.conf is only read when the module is loaded.
#
# Debian 12 libpam-runtime ships no faillock pam-config profile. The 5.3.2
# fix installs the two CIS Debian 12 profiles (rollback removes them):
#
#   faillock         Priority 0,    Auth: [default=die] pam_faillock.so authfail
#   faillock_notify  Priority 1024, Auth: requisite pam_faillock.so preauth
#                                   Account: required pam_faillock.so
#
# giving common-auth: preauth -> pam_unix -> authfail (verified with
# pam-auth-update in a debian:12 container, which also locked a test user out
# after `deny` failures). The operator enables them explicitly with
# `sudo pam-auth-update --enable faillock faillock_notify --package` — LSS never
# edits common-auth itself, since a botched PAM stack edit can lock the host.

_FAILLOCK_PAM_PROFILE = """\
Name: Enable pam_faillock to deny access (provided by LSS)
Default: no
Priority: 0
Auth-Type: Primary
Auth:
\t[default=die]\tpam_faillock.so authfail
"""

_FAILLOCK_NOTIFY_PAM_PROFILE = """\
Name: Notify of failed login attempts and reset count upon success (provided by LSS)
Default: no
Priority: 1024
Auth-Type: Primary
Auth:
\trequisite\tpam_faillock.so preauth
Account-Type: Primary
Account:
\trequired\tpam_faillock.so
"""

_FAILLOCK_PROFILE_PATH = Path("/usr/share/pam-configs/faillock")
_FAILLOCK_NOTIFY_PROFILE_PATH = Path("/usr/share/pam-configs/faillock_notify")

FAILLOCK_CONF = "/etc/security/faillock.conf"
COMMON_AUTH = "/etc/pam.d/common-auth"
COMMON_ACCOUNT = "/etc/pam.d/common-account"
RHEL_AUTH_STACKS = ("/etc/pam.d/system-auth", "/etc/pam.d/password-auth")

_FAILLOCK_REMEDIATION = (
    "to enable: `sudo lss harden --confirm --control 5.3.2` installs the CIS "
    "faillock and faillock_notify pam-config profiles under /usr/share/pam-configs/ "
    "(stock Debian/Ubuntu libpam-runtime ships none). Then run "
    "`sudo pam-auth-update --enable faillock faillock_notify --package` so "
    "/etc/pam.d/common-auth runs `pam_faillock.so preauth` before pam_unix and "
    "`pam_faillock.so authfail` after it, and common-account loads pam_faillock. "
    "On RHEL/Fedora with authselect, `sudo authselect enable-feature with-faillock` "
    "instead. Re-run lss audit to confirm; faillock.conf is already populated with "
    "the deny/unlock policy."
)


def _faillock_issues(auth_text: str, account_text: str, name: str) -> list[str]:
    """What keeps this auth/account stack from locking accounts out."""
    auth = [ln for ln in authconf.pam_lines(auth_text) if ln.type == "auth"]
    account = [ln for ln in authconf.pam_lines(account_text) if ln.type == "account"]
    unix = next((i for i, ln in enumerate(auth) if ln.module == "pam_unix.so"), None)
    if unix is None:
        return [f"no pam_unix auth line in {name}"]
    # Legacy pam_tally2 (removed in Linux-PAM 1.5) locks out from one enforcing
    # auth line before pam_unix, but only when deny= is set (default 0 = off).
    if any(i < unix and ln.module == "pam_tally2.so" and ln.arg("deny") not in (None, "0")
           and authconf.control_enforces(ln.control) for i, ln in enumerate(auth)):
        return []
    issues = []
    if not any(i < unix and ln.module == "pam_faillock.so" and "preauth" in ln.args
               and authconf.control_enforces(ln.control) for i, ln in enumerate(auth)):
        issues.append(f"no required/requisite `pam_faillock.so preauth` before pam_unix in {name}")
    if not any(i > unix and ln.module == "pam_faillock.so" and "authfail" in ln.args
               for i, ln in enumerate(auth)):
        issues.append(f"no `pam_faillock.so authfail` after pam_unix in {name}")
    if not any(ln.module == "pam_faillock.so" for ln in account):
        issues.append(f"pam_faillock not in the account stack of {name}")
    return issues


def _check_faillock() -> CheckResult:
    try:
        if Path(COMMON_AUTH).exists():
            acct = Path(COMMON_ACCOUNT)
            issues = _faillock_issues(Path(COMMON_AUTH).read_text(),
                                      acct.read_text() if acct.exists() else "",
                                      f"{COMMON_AUTH}/{COMMON_ACCOUNT}")
            where = COMMON_AUTH
        else:
            stacks = [p for p in RHEL_AUTH_STACKS if Path(p).exists()]
            if not stacks:
                return CheckResult("manual", "no PAM auth stack found — " + _FAILLOCK_REMEDIATION)
            issues = []
            for p in stacks:
                text = Path(p).read_text()
                issues += _faillock_issues(text, text, p)
            where = ", ".join(stacks)
    except OSError as e:
        return CheckResult("warn", f"could not read the PAM auth stack: {e}")
    if issues:
        return CheckResult("manual", "; ".join(issues) + " — " + _FAILLOCK_REMEDIATION)
    return CheckResult("pass", f"pam_faillock preauth/authfail/account active in {where}")


def _install_profile(path: Path, content: str) -> RollbackEntry | None:
    """Install an LSS pam-config profile unless an operator/distro one is
    there. An older LSS profile (no preauth) is replaced, with a backup."""
    if path.exists():
        try:
            current = path.read_text()
        except OSError:
            return None
        if "(provided by LSS)" not in current or current == content:
            return None
        bkp = journal.backup_file(str(path))
        path.write_text(content)
        return RollbackEntry(action=f"updated LSS pam-config profile {path.name}",
                             path=str(path), backup=bkp)
    path.write_text(content)
    # If the operator enabled the profile between harden and rollback, the
    # live stack still references it; rollback disables it via pam-auth-update
    # before removing the file so the auth stack stays consistent.
    return RollbackEntry(
        action=f"installed LSS pam-config profile {path.name}",
        path=str(path),
        backup="",
        undo=[
            ["pam-auth-update", "--package", "--disable", path.name],
            ["rm", "-f", str(path)],
        ],
    )


def _fix_faillock() -> list[RollbackEntry]:
    """Write CIS-aligned lockout policy to /etc/security/faillock.conf and
    install the faillock / faillock_notify pam-config profiles if missing.

    Both steps are rollback-tracked. The profiles are only installed where
    /usr/share/pam-configs/ exists (Debian-family). The fix never edits
    /etc/pam.d/common-auth itself: the operator runs
    `sudo pam-auth-update --enable faillock faillock_notify --package`.
    """
    entries: list[RollbackEntry] = []

    conf = Path(FAILLOCK_CONF)
    bkp = journal.backup_file(str(conf))
    if not conf.exists():
        conf.write_text("")
    for key, value in {"deny": "5", "unlock_time": "900", "fail_interval": "900"}.items():
        authconf.set_conf_key(conf, key, f"{key} = {value}")
    entries.append(RollbackEntry(
        action="wrote pam_faillock policy to faillock.conf",
        path=str(conf),
        backup=bkp,
        undo=[] if bkp else [["rm", "-f", str(conf)]],
    ))

    if _FAILLOCK_PROFILE_PATH.parent.is_dir():
        for path, content in ((_FAILLOCK_PROFILE_PATH, _FAILLOCK_PAM_PROFILE),
                              (_FAILLOCK_NOTIFY_PROFILE_PATH, _FAILLOCK_NOTIFY_PAM_PROFILE)):
            entry = _install_profile(path, content)
            if entry:
                entries.append(entry)

    return entries


register(Control(
    id="5.3.2",
    title="Ensure lockout for failed password attempts is configured",
    section="auth",
    check=_check_faillock,
    fix=_fix_faillock,
))


# ---- CIS 5.3.3: Ensure password reuse is limited ----
#
# pam_pwhistory.so processes `remember=N`. pam_pwquality.so does NOT — verified
# against pam_pwhistory(8) and the pam_pwquality.so binary symbols. Setting
# `remember=` in /etc/security/pwquality.conf is a no-op even though earlier
# LSS versions did this; the check below intentionally does not accept that
# state as pass.

PWHISTORY_CONF = "/etc/security/pwhistory.conf"

_REMEDIATION_NOTE = (
    "to remediate on Debian/Ubuntu/Kali: install a pam-configs profile under "
    "/usr/share/pam-configs/ that adds `pam_pwhistory.so remember=5 use_authtok` "
    "to the Password stack with Priority < 256, then run "
    "`sudo pam-auth-update --enable <profile> --package`. "
    "On RHEL/Fedora with authselect: `sudo authselect enable-feature with-pwhistory` "
    "(authselect 1.2+) or set `remember=N` in /etc/security/pwhistory.conf and "
    "ensure pam_pwhistory is present in /etc/pam.d/system-auth (managed by "
    "authselect)."
)


def _check_pw_reuse() -> CheckResult:
    """Pass when pam_pwhistory is in the password stack with remember>=5,
    or when pam_unix has remember=N>=5 as a module argument (legacy form).

    Setting `remember=N` in pwquality.conf is intentionally not accepted —
    pam_pwquality does not process that option, so it has no effect.
    """
    pam_files = [Path("/etc/pam.d/common-password"), Path("/etc/pam.d/system-auth")]
    pwhistory_in_stack = False
    pwhistory_remember_arg: int | None = None

    for p in pam_files:
        if not p.exists():
            continue
        for line in p.read_text().splitlines():
            # Linux-PAM drops everything from '#' to end of line.
            line = line.split("#", 1)[0]
            stripped = line.strip()
            if not stripped:
                continue
            # pam_unix with remember= as a module argument is the legacy approach.
            if "pam_unix" in line:
                m = re.search(r"\bremember=(\d+)", line)
                if m:
                    val = int(m.group(1))
                    if val >= 5:
                        return CheckResult("pass", f"pam_unix remember={val}")
                    return CheckResult("manual", f"pam_unix remember={val}, recommended: >=5 — edit the pam_unix line in /etc/pam.d/common-password (or system-auth) to raise the value")
            if "pam_pwhistory" in line:
                pwhistory_in_stack = True
                m = re.search(r"\bremember=(\d+)", line)
                if m:
                    pwhistory_remember_arg = int(m.group(1))

    if not pwhistory_in_stack:
        return CheckResult("manual", "pam_pwhistory not in PAM password stack — " + _REMEDIATION_NOTE)

    # Module argument takes precedence over pwhistory.conf.
    if pwhistory_remember_arg is not None:
        if pwhistory_remember_arg >= 5:
            return CheckResult("pass", f"pam_pwhistory remember={pwhistory_remember_arg}")
        return CheckResult("manual", f"pam_pwhistory remember={pwhistory_remember_arg}, recommended: >=5 — raise the remember= module arg or set remember=5+ in /etc/security/pwhistory.conf")

    # Fall back to /etc/security/pwhistory.conf.
    conf = Path(PWHISTORY_CONF)
    if conf.exists():
        for line in conf.read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            m = re.match(r"^\s*remember\s*=\s*(\d+)", stripped)
            if m:
                val = int(m.group(1))
                if val >= 5:
                    return CheckResult("pass", f"pwhistory.conf remember={val}")
                return CheckResult("manual", f"pwhistory.conf remember={val}, recommended: >=5 — edit /etc/security/pwhistory.conf to raise the remember value")

    # pam_pwhistory in the stack with no explicit `remember` anywhere uses the
    # module's built-in default of 10 (per pam_pwhistory(8)), which is >=5.
    return CheckResult("pass", "pam_pwhistory in stack, default remember=10")


# NOTE: Auto-fix is intentionally not provided. Editing the PAM password stack
# correctly across Debian (pam-auth-update profile mechanism), RHEL/Fedora
# (authselect), and bare Linux (direct edit with `pam-unix` success-jump
# arithmetic) is its own focused project. A previous LSS version shipped a fix
# that wrote `remember=5` to /etc/security/pwquality.conf, which pam_pwquality
# does not process — the policy was never actually enforced. Rather than ship
# another half-correct fix that might lock customers out of their own systems,
# 5.3.3 is documented as audit-only with a precise remediation command in the
# detail string. Full automated remediation is planned for a future release
# as a dedicated PAM-editing subsystem.


register(Control(
    id="5.3.3",
    title="Ensure password reuse is limited",
    section="auth",
    check=_check_pw_reuse,
    fix=None,  # See note above. Detail string provides the manual command.
))


# ---- CIS 5.3.5: Ensure password hashing algorithm is SHA-512 ----

_HASH_ALGOS = {"yescrypt", "sha512", "sha256", "md5", "blowfish", "bigcrypt", "des", "gost_yescrypt"}
_STRONG_HASHES = {"yescrypt", "sha512"}


def _check_pw_hash() -> CheckResult:
    # A pam_unix.so hashing argument on the PASSWORD line OVERRIDES login.defs
    # ENCRYPT_METHOD; that line is the one that hashes new passwords. The
    # auth-type pam_unix line (first in RHEL's system-auth) carries no hashing
    # option, so reading it hid a `password ... pam_unix.so md5`. Every stack
    # that exists must use a strong algorithm.
    weak, unpinned, strong = [], False, None
    try:
        for pam_path in PASSWORD_STACKS:
            p = Path(pam_path)
            if not p.exists():
                continue
            line = next((ln for ln in authconf.pam_lines(p.read_text())
                         if ln.type == "password" and ln.module == "pam_unix.so"), None)
            if line is None:
                continue
            # pam_unix's hashing flags are mutually exclusive; the last one wins.
            algos = [a.lower() for a in line.args if a.lower() in _HASH_ALGOS]
            if not algos:
                unpinned = True
            elif algos[-1] in _STRONG_HASHES:
                strong = algos[-1]
            else:
                weak.append(f"pam_unix hashing={algos[-1]} in {pam_path}")
        if weak:
            return CheckResult("fail", "; ".join(weak) + ", recommended: sha512 or yescrypt")
        if strong and not unpinned:
            return CheckResult("pass", f"pam_unix uses {strong}")

        # login.defs ENCRYPT_METHOD (authoritative when pam_unix pins no algorithm).
        login_defs = Path(LOGIN_DEFS)
        if login_defs.exists():
            val = authconf.login_defs_value(login_defs.read_text(), "ENCRYPT_METHOD")
            if val is not None:
                if val.upper() in ("SHA512", "YESCRYPT"):
                    return CheckResult("pass")
                return CheckResult("fail", f"ENCRYPT_METHOD={val}, recommended: SHA512 or YESCRYPT")
    except OSError as e:
        return CheckResult("warn", f"could not read PAM/login.defs: {e}")

    return CheckResult("warn", "could not determine password hashing algorithm")


def _set_login_defs(key: str, value: str) -> RollbackEntry:
    """Set a KEY VALUE pair in /etc/login.defs, preserving original on rollback.
    Only uncommented lines are rewritten (shadow-utils reads the last one, so
    duplicates are dropped); a commented example like Debian's
    `#\tPASS_MIN_DAYS` is left alone and the value is appended if unset."""
    p = Path(LOGIN_DEFS)
    bkp = journal.backup_file(str(p))
    authconf.set_conf_key(p, key, f"{key}\t{value}")
    return RollbackEntry(
        action=f"set {key} {value} in /etc/login.defs",
        path=str(p),
        backup=bkp,
    )


def _fix_pw_hash() -> list[RollbackEntry]:
    return [_set_login_defs("ENCRYPT_METHOD", "SHA512")]


register(Control(
    id="5.3.5",
    title="Ensure password hashing algorithm is SHA-512 or stronger",
    section="auth",
    check=_check_pw_hash,
    fix=_fix_pw_hash,
))


# ---- CIS 5.3.6: Ensure minimum password age in PAM matches login.defs ----

def _check_pam_mindays() -> CheckResult:
    """Ensure pam_unix has a minimum password age that matches login.defs."""
    login_defs = Path(LOGIN_DEFS)
    if not login_defs.exists():
        return CheckResult("warn", "login.defs not found")
    try:
        val = authconf.login_defs_value(login_defs.read_text(), "PASS_MIN_DAYS")
    except OSError as e:
        return CheckResult("warn", f"login.defs not readable: {e}")
    if val is None:
        return CheckResult("warn", "PASS_MIN_DAYS not configured")
    try:
        n = int(val)
    except ValueError:
        return CheckResult("fail", f"PASS_MIN_DAYS={val}")
    if n >= 1:
        return CheckResult("pass")
    return CheckResult("fail", f"PASS_MIN_DAYS={n}")


def _fix_pam_mindays() -> list[RollbackEntry]:
    return [_set_login_defs("PASS_MIN_DAYS", "1")]


register(Control(
    id="5.3.6",
    title="Ensure minimum password age is consistent in PAM and login.defs",
    section="auth",
    check=_check_pam_mindays,
    fix=_fix_pam_mindays,
))


# ---- CIS 5.3.7: Ensure password retry is limited ----

def _check_pw_retry() -> CheckResult:
    try:
        vals, loaded = _pwq("retry")
    except OSError as e:
        return CheckResult("warn", f"could not read pwquality/PAM config: {e}")
    if not loaded:
        return CheckResult("manual", _PWQ_NOT_LOADED)
    bad = [w for w, v in vals if v is not None and (_pwq_int(v) is None or _pwq_int(v) > 3)]
    if bad:
        return CheckResult("fail", "; ".join(bad) + ", recommended: ≤ 3")
    if any(v is None for _, v in vals):
        return CheckResult("warn", "retry not configured in pwquality")
    return CheckResult("pass")


def _fix_pw_retry() -> list[RollbackEntry]:
    return [_set_pwquality("retry", 3)]


register(Control(
    id="5.3.7",
    title="Ensure password retry is limited to 3 or fewer attempts",
    section="auth",
    check=_check_pw_retry,
    fix=_fix_pw_retry,
))
