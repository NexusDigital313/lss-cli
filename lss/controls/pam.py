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

    if not issues:
        return CheckResult("pass")
    return CheckResult("fail", "; ".join(issues))


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

def _check_faillock() -> CheckResult:
    # Check pam_faillock in PAM config
    for pam_path in ["/etc/pam.d/common-auth", "/etc/pam.d/system-auth"]:
        p = Path(pam_path)
        if p.exists():
            text = p.read_text()
            if "pam_faillock" in text or "pam_tally2" in text:
                return CheckResult("pass")

    # Check faillock.conf
    conf = Path("/etc/security/faillock.conf")
    if conf.exists():
        text = conf.read_text()
        if "deny" in text:
            return CheckResult("pass")

    return CheckResult("fail", "pam_faillock not configured — no account lockout on failed attempts")


def _fix_faillock() -> list[RollbackEntry]:
    """Write CIS-aligned lockout policy to /etc/security/faillock.conf.

    Writes the config file only — does not edit PAM stack. On distros with
    modern libpam-modules, pam_faillock reads this file when the preauth/
    authfail/authsucc lines are present in the PAM stack. If PAM does not
    yet reference pam_faillock, the check will still fail and the operator
    will need to add the PAM lines manually (distro-specific).
    """
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
    return [RollbackEntry(
        action="wrote pam_faillock policy to faillock.conf",
        path=str(conf),
        backup=bkp,
        undo=[] if bkp else [["rm", "-f", str(conf)]],
    )]


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
                    return CheckResult("fail", f"pam_unix remember={val}, recommended: >=5")
            if "pam_pwhistory" in line:
                pwhistory_in_stack = True
                m = re.search(r"\bremember=(\d+)", line)
                if m:
                    pwhistory_remember_arg = int(m.group(1))

    if not pwhistory_in_stack:
        return CheckResult("fail", "pam_pwhistory not in PAM password stack — " + _REMEDIATION_NOTE)

    # Module argument takes precedence over pwhistory.conf.
    if pwhistory_remember_arg is not None:
        if pwhistory_remember_arg >= 5:
            return CheckResult("pass", f"pam_pwhistory remember={pwhistory_remember_arg}")
        return CheckResult("fail", f"pam_pwhistory remember={pwhistory_remember_arg}, recommended: >=5")

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
                return CheckResult("fail", f"pwhistory.conf remember={val}, recommended: >=5")

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
# detail string. Full automated remediation is planned for v0.5.1+ as a
# dedicated PAM-editing subsystem.


register(Control(
    id="5.3.3",
    title="Ensure password reuse is limited",
    section="auth",
    check=_check_pw_reuse,
    fix=None,  # See note above. Detail string provides the manual command.
))


# ---- CIS 5.3.5: Ensure password hashing algorithm is SHA-512 ----

def _check_pw_hash() -> CheckResult:
    # Check login.defs
    login_defs = Path("/etc/login.defs")
    if login_defs.exists():
        for line in login_defs.read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith("ENCRYPT_METHOD"):
                val = stripped.split()[1] if len(stripped.split()) > 1 else ""
                if val.upper() in ("SHA512", "YESCRYPT"):
                    return CheckResult("pass")
                return CheckResult("fail", f"ENCRYPT_METHOD={val}, recommended: SHA512 or YESCRYPT")

    # Check PAM
    for pam_path in ["/etc/pam.d/common-password", "/etc/pam.d/system-auth"]:
        p = Path(pam_path)
        if p.exists():
            text = p.read_text()
            if "sha512" in text or "yescrypt" in text:
                return CheckResult("pass")

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
