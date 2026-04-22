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


register(Control(
    id="5.3.2",
    title="Ensure lockout for failed password attempts is configured",
    section="auth",
    check=_check_faillock,
    fix=None,  # PAM config is distro-specific and risky to auto-modify
))


# ---- CIS 5.3.3: Ensure password reuse is limited ----

def _check_pw_reuse() -> CheckResult:
    for pam_path in ["/etc/pam.d/common-password", "/etc/pam.d/system-auth"]:
        p = Path(pam_path)
        if p.exists():
            for line in p.read_text().splitlines():
                if "pam_pwhistory" in line or "pam_unix" in line:
                    m = re.search(r"remember=(\d+)", line)
                    if m:
                        val = int(m.group(1))
                        if val >= 5:
                            return CheckResult("pass")
                        return CheckResult("fail", f"remember={val}, recommended: ≥ 5")

    # Check pwquality
    val = _get_pwquality("remember")
    if val is not None and val >= 5:
        return CheckResult("pass")

    return CheckResult("fail", "password reuse not limited (remember not set or < 5)")


register(Control(
    id="5.3.3",
    title="Ensure password reuse is limited",
    section="auth",
    check=_check_pw_reuse,
    fix=None,  # PAM modification is risky
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


register(Control(
    id="5.3.5",
    title="Ensure password hashing algorithm is SHA-512 or stronger",
    section="auth",
    check=_check_pw_hash,
    fix=None,
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


register(Control(
    id="5.3.6",
    title="Ensure minimum password age is consistent in PAM and login.defs",
    section="auth",
    check=_check_pam_mindays,
    fix=None,
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