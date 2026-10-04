# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file, 
# via any medium, is strictly prohibited without explicit written authorization.

"""CIS Section 5.3 — PAM password complexity and lockout."""

from __future__ import annotations

import re
from pathlib import Path

from lss.lib import journal
from lss.lib.registry import Control, CheckResult, RollbackEntry, register


def _get_pwquality(key: str) -> int | None:
    """Read a value from /etc/security/pwquality.conf."""
    conf = Path("/etc/security/pwquality.conf")
    if not conf.exists():
        return None
    for line in conf.read_text().splitlines():
        line = line.strip()
        if line.startswith("#") or not line:
            continue
        m = re.match(rf"^\s*{key}\s*=\s*(-?\d+)", line)
        if m:
            return int(m.group(1))
    return None


def _set_pwquality(key: str, value: int) -> RollbackEntry:
    """Set a value in /etc/security/pwquality.conf."""
    conf = Path("/etc/security/pwquality.conf")
    bkp = journal.backup_file(str(conf))

    if conf.exists():
        text = conf.read_text()
        lines = text.splitlines(keepends=True)
        found = False
        for i, line in enumerate(lines):
            if re.match(rf"^\s*#?\s*{key}\s*=", line):
                lines[i] = f"{key} = {value}\n"
                found = True
                break
        if not found:
            lines.append(f"{key} = {value}\n")
        conf.write_text("".join(lines))
    else:
        conf.write_text(f"# Created by LSS\n{key} = {value}\n")

    return RollbackEntry(
        action=f"set {key} = {value} in pwquality.conf",
        path=str(conf),
        backup=bkp,
        undo=[] if bkp else [["rm", "-f", str(conf)]],
    )


# ---- CIS 5.3.1: Ensure password creation requirements are configured ----
# This is a compound check: dcredit, ucredit, lcredit, ocredit

def _pwquality_module_active() -> bool:
    """True if pam_pwquality.so (or legacy pam_cracklib.so) is loaded by an
    UNCOMMENTED line in the password PAM stack. pwquality.conf settings are
    inert unless the module actually references them, so a check that reads only
    the conf file can pass while nothing is enforced."""
    for pam_path in ("/etc/pam.d/common-password", "/etc/pam.d/system-auth", "/etc/pam.d/password-auth"):
        p = Path(pam_path)
        if not p.exists():
            continue
        for line in p.read_text().splitlines():
            s = line.lstrip()
            if s.startswith("#") or not s:
                continue
            if "pam_pwquality.so" in s or "pam_cracklib.so" in s:
                return True
    return False


def _check_pw_complexity() -> CheckResult:
    issues = []
    for key, desc, threshold in [
        ("dcredit", "digit", -1),
        ("ucredit", "uppercase", -1),
        ("lcredit", "lowercase", -1),
        ("ocredit", "special char", -1),
    ]:
        val = _get_pwquality(key)
        if val is None:
            issues.append(f"{key} not set")
        elif val > threshold:  # negative means "require at least N"
            issues.append(f"{key}={val}, recommended: ≤ {threshold}")

    if issues:
        return CheckResult("fail", "; ".join(issues))

    # Values are right, but they only take effect if the module is loaded.
    if not _pwquality_module_active():
        return CheckResult(
            "manual",
            "pwquality.conf complexity is set but pam_pwquality.so is not loaded "
            "in the password PAM stack, so it is NOT enforced. On Debian/Ubuntu: "
            "`sudo apt install libpam-pwquality` then ensure `pam-auth-update` "
            "wires it into /etc/pam.d/common-password. On RHEL: "
            "`authselect enable-feature with-pwquality`.",
        )
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
# pam_faillock (or the legacy pam_tally2) is what enforces account lockout —
# /etc/security/faillock.conf is only read when pam_faillock.so is loaded by
# the PAM auth stack. Writing faillock.conf alone is a no-op if PAM doesn't
# reference the module.
#
# The check below requires an UNCOMMENTED pam_faillock or pam_tally2 line in
# the auth stack before passing. The fix continues to write faillock.conf so
# the policy is applied on hosts where pam_faillock is configured, but the
# check no longer pretends a stand-alone faillock.conf is sufficient.
#
# Debian 12 (and earlier) stock libpam-runtime does NOT ship a faillock
# pam-config profile, despite older docs implying it does — only unix,
# systemd, mkhomedir, and gnome-keyring profiles are present in
# /usr/share/pam-configs/. So `pam-auth-update --enable faillock --package`
# silently no-ops on a stock host. To close that gap without taking on the
# full PAM-stack-edit subsystem (deferred to a future release), the 5.3.2 fix now
# installs an LSS-provided faillock profile at /usr/share/pam-configs/faillock
# (rollback removes it). Operators still explicitly enable it via
# `sudo pam-auth-update --enable faillock --package` — we never auto-edit
# common-auth ourselves, since a botched PAM stack edit can lock the host.

# Conservative pam-auth-update profile. Default: no — operator must opt in
# with --enable. Auth uses [default=ignore] so a missing or broken
# pam_faillock.so cannot break the auth chain (no [default=die]); lockout
# enforcement happens in the Account stack via `required pam_faillock.so`,
# which is how authselect's with-faillock feature gets it right too.
_FAILLOCK_PAM_PROFILE = """\
Name: pam_faillock — track and prevent multiple bad logins (provided by LSS)
Default: no
Priority: 0
Auth-Type: Primary
Auth:
\t[default=ignore]\tpam_faillock.so authfail
Auth-Initial:
\t[default=ignore]\tpam_faillock.so authfail
Account-Type: Additional
Account:
\trequired\tpam_faillock.so
Account-Initial:
\trequired\tpam_faillock.so
"""

_FAILLOCK_PROFILE_PATH = Path("/usr/share/pam-configs/faillock")

_FAILLOCK_REMEDIATION = (
    "to enable: an LSS-provided faillock pam-config profile is installed at "
    "/usr/share/pam-configs/faillock by `sudo lss harden --confirm --control 5.3.2`. "
    "Stock Debian/Ubuntu libpam-runtime does NOT ship one. After the profile is in "
    "place, run `sudo pam-auth-update --enable faillock --package` to wire it into "
    "/etc/pam.d/common-auth. On RHEL/Fedora with authselect, "
    "`sudo authselect enable-feature with-faillock` instead. Re-run lss audit to "
    "confirm; faillock.conf is already populated with the deny/unlock policy."
)


def _faillock_module_active(pam_text: str) -> bool:
    """True if any uncommented line in the PAM file references pam_faillock
    or pam_tally2. Substring matching alone would also match commented-out
    examples (Debian's libpam-runtime ships a commented `pam_faillock` line)."""
    for line in pam_text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#") or not stripped:
            continue
        if "pam_faillock" in stripped or "pam_tally2" in stripped:
            return True
    return False


def _check_faillock() -> CheckResult:
    for pam_path in ["/etc/pam.d/common-auth", "/etc/pam.d/system-auth"]:
        p = Path(pam_path)
        if p.exists() and _faillock_module_active(p.read_text()):
            return CheckResult("pass", f"pam_faillock active in {pam_path}")
    return CheckResult("manual", "pam_faillock not active in PAM auth stack — " + _FAILLOCK_REMEDIATION)


def _fix_faillock() -> list[RollbackEntry]:
    """Write CIS-aligned lockout policy to /etc/security/faillock.conf and
    install an LSS-provided faillock pam-config profile if one is missing.

    Two steps, both rollback-tracked:

    1. faillock.conf — writes deny=5, unlock_time=900, fail_interval=900.
       Idempotent (key updates in place, no duplication).

    2. /usr/share/pam-configs/faillock — only created if absent and the
       /usr/share/pam-configs/ directory exists (Debian-family with
       libpam-runtime). If a profile is already present (operator-supplied,
       or installed by a future libpam-runtime), we leave it alone.

    The fix never edits /etc/pam.d/common-auth itself. The operator runs
    `sudo pam-auth-update --enable faillock --package` to wire the profile
    into the live PAM stack — that's the conservative split: LSS supplies
    the profile, operator chooses when to activate.
    """
    entries: list[RollbackEntry] = []

    conf = Path("/etc/security/faillock.conf")
    bkp = journal.backup_file(str(conf))
    desired = {"deny": "5", "unlock_time": "900", "fail_interval": "900"}
    lines = conf.read_text().splitlines(keepends=True) if conf.exists() else []
    for key, value in desired.items():
        new_line = f"{key} = {value}\n"
        found = False
        for i, line in enumerate(lines):
            if re.match(rf"^\s*#?\s*{key}\s*=", line):
                lines[i] = new_line
                found = True
                break
        if not found:
            if lines and not lines[-1].endswith("\n"):
                lines.append("\n")
            lines.append(new_line)
    conf.write_text("".join(lines))
    entries.append(RollbackEntry(
        action="wrote pam_faillock policy to faillock.conf",
        path=str(conf),
        backup=bkp,
        undo=[] if bkp else [["rm", "-f", str(conf)]],
    ))

    # Install the pam-config profile only on hosts that actually use
    # pam-auth-update (i.e., /usr/share/pam-configs/ exists). Don't clobber
    # an existing profile — could be a distro-supplied one or operator-
    # customized.
    pam_configs_dir = _FAILLOCK_PROFILE_PATH.parent
    if pam_configs_dir.is_dir() and not _FAILLOCK_PROFILE_PATH.exists():
        _FAILLOCK_PROFILE_PATH.write_text(_FAILLOCK_PAM_PROFILE)
        entries.append(RollbackEntry(
            action="installed LSS faillock pam-config profile",
            path=str(_FAILLOCK_PROFILE_PATH),
            backup="",
            # No backup (the file did not previously exist), so undo just
            # removes it. If the operator ran `pam-auth-update --enable
            # faillock --package` between harden and rollback, the live
            # common-auth still references the profile name; rollback also
            # disables it via pam-auth-update so the auth stack stays
            # consistent.
            undo=[
                ["pam-auth-update", "--package", "--disable", "faillock"],
                ["rm", "-f", str(_FAILLOCK_PROFILE_PATH)],
            ],
        ))

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
            stripped = line.lstrip()
            if stripped.startswith("#") or not stripped:
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
    # A pam_unix.so hashing argument OVERRIDES login.defs ENCRYPT_METHOD, so if
    # the PAM stack pins an algorithm that is what actually applies. Check the
    # (uncommented) password stack first, and only the real pam_unix directive —
    # not a substring anywhere in the file (which matched commented examples).
    for pam_path in ("/etc/pam.d/common-password", "/etc/pam.d/system-auth", "/etc/pam.d/password-auth"):
        p = Path(pam_path)
        if not p.exists():
            continue
        for line in p.read_text().splitlines():
            s = line.strip()
            if s.startswith("#") or not s or "pam_unix.so" not in s:
                continue
            algos = [t.lower() for t in s.split() if t.lower() in _HASH_ALGOS]
            if algos:
                if any(a in _STRONG_HASHES for a in algos):
                    return CheckResult("pass", f"pam_unix uses {algos[0]}")
                return CheckResult("fail", f"pam_unix hashing={algos[0]}, recommended: sha512 or yescrypt")
            # pam_unix present with no explicit algo -> it falls back to login.defs.
            break

    # login.defs ENCRYPT_METHOD (authoritative when pam_unix pins no algorithm).
    login_defs = Path("/etc/login.defs")
    if login_defs.exists():
        for line in login_defs.read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            parts = stripped.split()
            if parts[0] == "ENCRYPT_METHOD":
                val = parts[1] if len(parts) > 1 else ""
                if val.upper() in ("SHA512", "YESCRYPT"):
                    return CheckResult("pass")
                return CheckResult("fail", f"ENCRYPT_METHOD={val}, recommended: SHA512 or YESCRYPT")

    return CheckResult("warn", "could not determine password hashing algorithm")


def _set_login_defs(key: str, value: str) -> RollbackEntry:
    """Set a KEY VALUE pair in /etc/login.defs, preserving original on rollback."""
    p = Path("/etc/login.defs")
    bkp = journal.backup_file(str(p))
    lines = p.read_text().splitlines(keepends=True) if p.exists() else []
    new_line = f"{key}\t{value}\n"
    found = False
    for i, line in enumerate(lines):
        stripped = line.lstrip("#").strip()
        parts = stripped.split()
        if parts and parts[0] == key:
            lines[i] = new_line
            found = True
            break
    if not found:
        if lines and not lines[-1].endswith("\n"):
            lines.append("\n")
        lines.append(new_line)
    p.write_text("".join(lines))
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
    login_defs = Path("/etc/login.defs")
    if not login_defs.exists():
        return CheckResult("warn", "login.defs not found")
    for line in login_defs.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        parts = stripped.split()
        if parts[0] == "PASS_MIN_DAYS" and len(parts) >= 2:
            try:
                n = int(parts[1])
                if n >= 1:
                    return CheckResult("pass")
                return CheckResult("fail", f"PASS_MIN_DAYS={n}")
            except ValueError:
                pass
    return CheckResult("warn", "PASS_MIN_DAYS not configured")


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
    val = _get_pwquality("retry")
    if val is not None:
        if val <= 3:
            return CheckResult("pass")
        return CheckResult("fail", f"retry={val}, recommended: ≤ 3")

    # Check PAM
    for pam_path in ["/etc/pam.d/common-password", "/etc/pam.d/system-auth"]:
        p = Path(pam_path)
        if p.exists():
            for line in p.read_text().splitlines():
                # Skip blank and commented lines. A commented
                # `# password requisite pam_pwquality.so retry=3` example
                # enforces nothing, but the old substring test read it and
                # passed 5.3.7.
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if "pam_pwquality" in line:
                    m = re.search(r"retry=(\d+)", line)
                    if m and int(m.group(1)) <= 3:
                        return CheckResult("pass")
                    elif m:
                        return CheckResult("fail", f"retry={m.group(1)}")

    return CheckResult("warn", "retry not configured in pwquality")


def _fix_pw_retry() -> list[RollbackEntry]:
    return [_set_pwquality("retry", 3)]


register(Control(
    id="5.3.7",
    title="Ensure password retry is limited to 3 or fewer attempts",
    section="auth",
    check=_check_pw_retry,
    fix=_fix_pw_retry,
))
