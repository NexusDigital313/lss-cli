"""CIS Section 5.2 — SSH Server Configuration."""

from __future__ import annotations

from pathlib import Path

from lss.lib.registry import Control, CheckResult, RollbackEntry, register
from lss.lib.sshd import get_sshd_setting as _get_sshd_setting, set_sshd_setting as _set_sshd_setting, setting_in_global_scope, LSS_SSHD_CONF

SSHD_CONFIG = "/etc/ssh/sshd_config"


# ---- CIS 5.2.5: Ensure SSH MaxAuthTries is set to 4 or less ----

def _check_max_auth_tries() -> CheckResult:
    val = _get_sshd_setting("maxauthtries")
    if val is None:
        return CheckResult("warn", "could not read sshd config")
    try:
        n = int(val)
    except ValueError:
        return CheckResult("fail", f"maxauthtries={val}")
    if n <= 4:
        return CheckResult("pass")
    return CheckResult("fail", f"MaxAuthTries={n}, recommended: ≤ 4")


def _fix_max_auth_tries() -> list[RollbackEntry]:
    return [_set_sshd_setting("MaxAuthTries", "4")]


register(Control(
    id="5.2.5",
    title="Ensure SSH MaxAuthTries is set to 4 or less",
    section="ssh",
    check=_check_max_auth_tries,
    fix=_fix_max_auth_tries,
))


# ---- CIS 5.2.6: Ensure SSH IgnoreRhosts is enabled ----

def _check_ignore_rhosts() -> CheckResult:
    val = _get_sshd_setting("ignorerhosts")
    if val is None:
        return CheckResult("warn", "could not read sshd config")
    if val.lower() == "yes":
        return CheckResult("pass")
    return CheckResult("fail", f"IgnoreRhosts={val}")


def _fix_ignore_rhosts() -> list[RollbackEntry]:
    return [_set_sshd_setting("IgnoreRhosts", "yes")]


register(Control(
    id="5.2.6",
    title="Ensure SSH IgnoreRhosts is enabled",
    section="ssh",
    check=_check_ignore_rhosts,
    fix=_fix_ignore_rhosts,
))


# ---- CIS 5.2.11: Ensure SSH PermitRootLogin is disabled ----

def _check_permit_root() -> CheckResult:
    val = _get_sshd_setting("permitrootlogin")
    if val is None:
        return CheckResult("warn", "could not read sshd config")
    # `sshd -T` resolves Match blocks. If the effective value is correct but
    # there's no global setting, the value only applies to the matched scope —
    # other users may still be able to root-log-in. Surface that.
    in_global = setting_in_global_scope("PermitRootLogin")
    if val.lower() == "no":
        if in_global is False:
            return CheckResult("warn", "PermitRootLogin=no resolved via Match block; no global default set")
        return CheckResult("pass")
    if val.lower() == "prohibit-password":
        return CheckResult("warn", "PermitRootLogin=prohibit-password, recommended: no")
    return CheckResult("fail", f"PermitRootLogin={val}")


def _fix_permit_root() -> list[RollbackEntry]:
    # SAFETY: refuse to disable root SSH login when root is the ONLY way in
    # (common on cloud root-only images) — applying it there locks the operator
    # out permanently. Leaving the control failing is the safe outcome; the
    # operator creates a sudo user first, then re-runs.
    # UNVERIFIED on a live host — verify on a throwaway Debian VM.
    from lss.lib.sshd import has_non_root_admin
    from lss.lib.output import warn
    if not has_non_root_admin():
        warn("5.2.11 skipped: no non-root sudo/wheel admin with a login shell — "
             "disabling root SSH login now would lock you out. Create an admin "
             "user first, then re-run harden.")
        return []
    return [_set_sshd_setting("PermitRootLogin", "no")]


register(Control(
    id="5.2.11",
    title="Ensure SSH root login is disabled",
    section="ssh",
    check=_check_permit_root,
    fix=_fix_permit_root,
))


# ---- CIS 5.2.13: Ensure only strong ciphers are used ----

STRONG_CIPHERS = "aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
WEAK_CIPHERS = {"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc", "cast128-cbc"}


def _check_ciphers() -> CheckResult:
    val = _get_sshd_setting("ciphers")
    if val is None:
        return CheckResult("warn", "could not read sshd config")
    active = set(val.split(","))
    weak = active & WEAK_CIPHERS
    if weak:
        return CheckResult("fail", f"weak ciphers: {','.join(sorted(weak))}")
    return CheckResult("pass")


def _fix_ciphers() -> list[RollbackEntry]:
    return [_set_sshd_setting("Ciphers", STRONG_CIPHERS)]


register(Control(
    id="5.2.13",
    title="Ensure only strong ciphers are used",
    section="ssh",
    check=_check_ciphers,
    fix=_fix_ciphers,
))


# ---- CIS 5.2.2: Ensure SSH LogLevel is appropriate ----

def _check_loglevel() -> CheckResult:
    val = _get_sshd_setting("loglevel")
    if val is None:
        return CheckResult("warn", "could not read sshd config")
    if val.upper() in ("VERBOSE", "INFO"):
        return CheckResult("pass")
    return CheckResult("fail", f"LogLevel={val}, recommended: VERBOSE or INFO")


def _fix_loglevel() -> list[RollbackEntry]:
    return [_set_sshd_setting("LogLevel", "VERBOSE")]


register(Control(
    id="5.2.2",
    title="Ensure SSH LogLevel is appropriate",
    section="ssh",
    check=_check_loglevel,
    fix=_fix_loglevel,
))


# ---- CIS 5.2.7: Ensure SSH HostbasedAuthentication is disabled ----

def _check_hostbased_auth() -> CheckResult:
    val = _get_sshd_setting("hostbasedauthentication")
    if val is None:
        return CheckResult("warn", "could not read sshd config")
    if val.lower() == "no":
        return CheckResult("pass")
    return CheckResult("fail", f"HostbasedAuthentication={val}")


def _fix_hostbased_auth() -> list[RollbackEntry]:
    return [_set_sshd_setting("HostbasedAuthentication", "no")]


register(Control(
    id="5.2.7",
    title="Ensure SSH HostbasedAuthentication is disabled",
    section="ssh",
    check=_check_hostbased_auth,
    fix=_fix_hostbased_auth,
))


# ---- CIS 5.2.8: Ensure SSH PermitEmptyPasswords is disabled ----

def _check_permit_empty() -> CheckResult:
    val = _get_sshd_setting("permitemptypasswords")
    if val is None:
        return CheckResult("warn", "could not read sshd config")
    if val.lower() == "no":
        return CheckResult("pass")
    return CheckResult("fail", f"PermitEmptyPasswords={val}")


def _fix_permit_empty() -> list[RollbackEntry]:
    return [_set_sshd_setting("PermitEmptyPasswords", "no")]


register(Control(
    id="5.2.8",
    title="Ensure SSH PermitEmptyPasswords is disabled",
    section="ssh",
    check=_check_permit_empty,
    fix=_fix_permit_empty,
))


# ---- CIS 5.2.9: Ensure SSH PermitUserEnvironment is disabled ----

def _check_permit_user_env() -> CheckResult:
    val = _get_sshd_setting("permituserenvironment")
    if val is None:
        return CheckResult("warn", "could not read sshd config")
    if val.lower() == "no":
        return CheckResult("pass")
    return CheckResult("fail", f"PermitUserEnvironment={val}")


def _fix_permit_user_env() -> list[RollbackEntry]:
    return [_set_sshd_setting("PermitUserEnvironment", "no")]


register(Control(
    id="5.2.9",
    title="Ensure SSH PermitUserEnvironment is disabled",
    section="ssh",
    check=_check_permit_user_env,
    fix=_fix_permit_user_env,
))


# ---- CIS 5.2.4: Ensure SSH X11 forwarding is disabled ----

def _check_x11() -> CheckResult:
    val = _get_sshd_setting("x11forwarding")
    if val is None:
        return CheckResult("warn", "could not read sshd config")
    if val.lower() == "no":
        return CheckResult("pass")
    return CheckResult("fail", f"X11Forwarding={val}")


def _fix_x11() -> list[RollbackEntry]:
    return [_set_sshd_setting("X11Forwarding", "no")]


register(Control(
    id="5.2.4",
    title="Ensure SSH X11 forwarding is disabled",
    section="ssh",
    check=_check_x11,
    fix=_fix_x11,
))


# ---- CIS 5.2.3: Ensure SSH MaxStartups is configured ----

def _check_max_startups() -> CheckResult:
    val = _get_sshd_setting("maxstartups")
    if val is None:
        return CheckResult("warn", "could not read sshd config")
    # Default is "10:30:100" — CIS recommends "10:30:60" or stricter
    parts = val.split(":")
    if len(parts) == 3:
        try:
            start, rate, full = int(parts[0]), int(parts[1]), int(parts[2])
            if start <= 10 and full <= 60:
                return CheckResult("pass")
            return CheckResult("fail", f"MaxStartups={val}, recommended: 10:30:60 or stricter")
        except ValueError:
            pass
    return CheckResult("fail", f"MaxStartups={val}")


def _fix_max_startups() -> list[RollbackEntry]:
    return [_set_sshd_setting("MaxStartups", "10:30:60")]


register(Control(
    id="5.2.3",
    title="Ensure SSH MaxStartups is configured",
    section="ssh",
    check=_check_max_startups,
    fix=_fix_max_startups,
))


# ---- CIS 5.2.15: Ensure SSH LoginGraceTime is set to one minute or less ----

def _check_login_grace() -> CheckResult:
    val = _get_sshd_setting("logingracetime")
    if val is None:
        return CheckResult("warn", "could not read sshd config")
    try:
        n = int(val)
    except ValueError:
        return CheckResult("fail", f"LoginGraceTime={val}")
    if 1 <= n <= 60:
        return CheckResult("pass")
    return CheckResult("fail", f"LoginGraceTime={n}s, recommended: ≤ 60")


def _fix_login_grace() -> list[RollbackEntry]:
    return [_set_sshd_setting("LoginGraceTime", "60")]


register(Control(
    id="5.2.15",
    title="Ensure SSH LoginGraceTime is set to one minute or less",
    section="ssh",
    check=_check_login_grace,
    fix=_fix_login_grace,
))


# ---- CIS 5.2.16: Ensure SSH Idle Timeout Interval is configured ----

def _check_client_alive() -> CheckResult:
    interval = _get_sshd_setting("clientaliveinterval")
    count = _get_sshd_setting("clientalivecountmax")
    if interval is None or count is None:
        return CheckResult("warn", "could not read sshd config")
    try:
        iv, cm = int(interval), int(count)
    except ValueError:
        return CheckResult("fail", f"ClientAliveInterval={interval}, ClientAliveCountMax={count}")
    if 1 <= iv <= 300 and cm <= 3:
        return CheckResult("pass")
    issues = []
    if iv == 0 or iv > 300:
        issues.append(f"ClientAliveInterval={iv}")
    if cm > 3:
        issues.append(f"ClientAliveCountMax={cm}")
    return CheckResult("fail", ", ".join(issues))


def _fix_client_alive() -> list[RollbackEntry]:
    return [
        _set_sshd_setting("ClientAliveInterval", "300"),
        _set_sshd_setting("ClientAliveCountMax", "3"),
    ]


register(Control(
    id="5.2.16",
    title="Ensure SSH idle timeout interval is configured",
    section="ssh",
    check=_check_client_alive,
    fix=_fix_client_alive,
))


# ---- CIS 5.2.17: Ensure SSH AllowTcpForwarding is disabled ----

def _check_tcp_forwarding() -> CheckResult:
    val = _get_sshd_setting("allowtcpforwarding")
    if val is None:
        return CheckResult("warn", "could not read sshd config")
    if val.lower() == "no":
        return CheckResult("pass")
    return CheckResult("fail", f"AllowTcpForwarding={val}")


def _fix_tcp_forwarding() -> list[RollbackEntry]:
    return [_set_sshd_setting("AllowTcpForwarding", "no")]


register(Control(
    id="5.2.17",
    title="Ensure SSH AllowTcpForwarding is disabled",
    section="ssh",
    check=_check_tcp_forwarding,
    fix=_fix_tcp_forwarding,
))


# ---- CIS 5.2.18: Ensure SSH warning banner is configured ----

def _check_banner() -> CheckResult:
    val = _get_sshd_setting("banner")
    if val is None:
        return CheckResult("warn", "could not read sshd config")
    if val.lower() != "none" and val.strip():
        return CheckResult("pass")
    return CheckResult("fail", "no SSH banner configured")


def _fix_banner() -> list[RollbackEntry]:
    banner_path = Path("/etc/issue.net")
    if not banner_path.exists() or not banner_path.read_text().strip():
        banner_path.write_text("Authorized uses only. All activity may be monitored and reported.\n")
    return [_set_sshd_setting("Banner", "/etc/issue.net")]


register(Control(
    id="5.2.18",
    title="Ensure SSH warning banner is configured",
    section="ssh",
    check=_check_banner,
    fix=_fix_banner,
))


# ---- CIS 5.2.19: Ensure SSH MaxSessions is limited ----

def _check_max_sessions() -> CheckResult:
    val = _get_sshd_setting("maxsessions")
    if val is None:
        return CheckResult("warn", "could not read sshd config")
    try:
        n = int(val)
    except ValueError:
        return CheckResult("fail", f"MaxSessions={val}")
    if n <= 10:
        return CheckResult("pass")
    return CheckResult("fail", f"MaxSessions={n}, recommended: ≤ 10")


def _fix_max_sessions() -> list[RollbackEntry]:
    return [_set_sshd_setting("MaxSessions", "10")]


register(Control(
    id="5.2.19",
    title="Ensure SSH MaxSessions is limited",
    section="ssh",
    check=_check_max_sessions,
    fix=_fix_max_sessions,
))


# ---- CIS 5.2.14: Ensure only strong MAC algorithms are used ----

WEAK_MACS = {
    "hmac-md5", "hmac-md5-96", "hmac-ripemd160", "hmac-sha1-96",
    "umac-64@openssh.com", "hmac-md5-etm@openssh.com",
    "hmac-md5-96-etm@openssh.com", "hmac-ripemd160-etm@openssh.com",
    "hmac-sha1-96-etm@openssh.com", "umac-64-etm@openssh.com",
}

STRONG_MACS = (
    "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,"
    "hmac-sha2-512,hmac-sha2-256"
)


def _check_macs() -> CheckResult:
    val = _get_sshd_setting("macs")
    if val is None:
        return CheckResult("warn", "could not read sshd config")
    active = set(val.split(","))
    weak = active & WEAK_MACS
    if weak:
        return CheckResult("fail", f"weak MACs: {','.join(sorted(weak))}")
    return CheckResult("pass")


def _fix_macs() -> list[RollbackEntry]:
    return [_set_sshd_setting("MACs", STRONG_MACS)]


register(Control(
    id="5.2.14",
    title="Ensure only strong MAC algorithms are used",
    section="ssh",
    check=_check_macs,
    fix=_fix_macs,
))
