# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file, 
# via any medium, is strictly prohibited without explicit written authorization.

"""CIS Section 5.2 — SSH Server Configuration."""

from __future__ import annotations

import stat
from pathlib import Path

from lss.lib.registry import Control, CheckResult, RollbackEntry, register
from lss.lib.sshd import get_sshd_setting as _get_sshd_setting, set_sshd_setting as _set_sshd_setting, setting_in_global_scope, LSS_SSHD_CONF
from lss.lib.sshd import audit_sshd as _audit_sshd, sshd_seconds as _sshd_seconds

SSHD_CONFIG = "/etc/ssh/sshd_config"


# ---- CIS 5.2.5: Ensure SSH MaxAuthTries is set to 4 or less ----

def _check_max_auth_tries() -> CheckResult:
    return _audit_sshd("maxauthtries", _get_sshd_setting("maxauthtries"), _eval_max_auth_tries)


def _eval_max_auth_tries(val: str) -> CheckResult:
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
    return _audit_sshd("ignorerhosts", _get_sshd_setting("ignorerhosts"), _eval_ignore_rhosts)


def _eval_ignore_rhosts(val: str) -> CheckResult:
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
    res = _audit_sshd("permitrootlogin", _get_sshd_setting("permitrootlogin"), _eval_permit_root)
    if res.status != "pass":
        return res
    # The effective value is resolved for a local root login. If there's no
    # global setting, "no" only comes from a Match block — other connections
    # may still be able to root-log-in. Surface that.
    if setting_in_global_scope("PermitRootLogin") is False:
        return CheckResult("warn", "PermitRootLogin=no resolved via Match block; no global default set")
    return res


def _eval_permit_root(val: str) -> CheckResult:
    if val.lower() == "no":
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
    return _audit_sshd("ciphers", _get_sshd_setting("ciphers"), _eval_ciphers)


def _eval_ciphers(val: str) -> CheckResult:
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
    return _audit_sshd("loglevel", _get_sshd_setting("loglevel"), _eval_loglevel)


def _eval_loglevel(val: str) -> CheckResult:
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
    return _audit_sshd("hostbasedauthentication", _get_sshd_setting("hostbasedauthentication"), _eval_hostbased_auth)


def _eval_hostbased_auth(val: str) -> CheckResult:
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
    return _audit_sshd("permitemptypasswords", _get_sshd_setting("permitemptypasswords"), _eval_permit_empty)


def _eval_permit_empty(val: str) -> CheckResult:
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
    return _audit_sshd("permituserenvironment", _get_sshd_setting("permituserenvironment"), _eval_permit_user_env)


def _eval_permit_user_env(val: str) -> CheckResult:
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
    return _audit_sshd("x11forwarding", _get_sshd_setting("x11forwarding"), _eval_x11)


def _eval_x11(val: str) -> CheckResult:
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
    return _audit_sshd("maxstartups", _get_sshd_setting("maxstartups"), _eval_max_startups)


def _eval_max_startups(val: str) -> CheckResult:
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
    return _audit_sshd("logingracetime", _get_sshd_setting("logingracetime"), _eval_login_grace)


def _eval_login_grace(val: str) -> CheckResult:
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

def _eval_client_alive(interval: str, count: str) -> CheckResult:
    # ClientAliveCountMax 0 disables termination of unresponsive sessions
    # (OpenSSH >= 8.2), so the count must be 1..3 as well as the interval > 0.
    iv = _sshd_seconds(interval)
    try:
        cm = int(count)
    except ValueError:
        cm = None
    if iv is None or cm is None:
        return CheckResult("fail", f"ClientAliveInterval={interval}, ClientAliveCountMax={count}")
    issues = []
    if not 1 <= iv <= 300:
        issues.append(f"ClientAliveInterval={iv}" + (" (disabled)" if iv == 0 else ""))
    if not 1 <= cm <= 3:
        issues.append(f"ClientAliveCountMax={cm}" + (" (0 disables termination)" if cm == 0 else ""))
    if issues:
        return CheckResult("fail", ", ".join(issues))
    return CheckResult("pass")


def _check_client_alive() -> CheckResult:
    from lss.lib.sshd import match_override_result
    interval = _get_sshd_setting("clientaliveinterval")
    count = _get_sshd_setting("clientalivecountmax")
    if interval is None or count is None:
        return CheckResult("warn", "could not read sshd config")
    res = _eval_client_alive(interval, count)
    if res.status != "pass":
        return res
    return (match_override_result("ClientAliveInterval", lambda v: _eval_client_alive(v, count))
            or match_override_result("ClientAliveCountMax", lambda v: _eval_client_alive(interval, v))
            or res)


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
    return _audit_sshd("allowtcpforwarding", _get_sshd_setting("allowtcpforwarding"), _eval_tcp_forwarding)


def _eval_tcp_forwarding(val: str) -> CheckResult:
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

BANNER_FILE = "/etc/issue.net"


def _check_banner() -> CheckResult:
    return _audit_sshd("banner", _get_sshd_setting("banner"), _eval_banner)


def _eval_banner(val: str) -> CheckResult:
    # The Banner file must exist and be a non-empty regular file; sshd sends
    # nothing for a missing or empty one.
    if not val.strip() or val.strip().lower() == "none":
        return CheckResult("fail", "no SSH banner configured")
    p = Path(val.strip())
    try:
        st = p.stat()
        if not stat.S_ISREG(st.st_mode):
            return CheckResult("fail", f"Banner {val} is not a regular file")
        if not p.read_text(errors="replace").strip():
            return CheckResult("fail", f"Banner file {val} is empty")
    except FileNotFoundError:
        return CheckResult("fail", f"Banner file {val} does not exist")
    except OSError as e:
        return CheckResult("warn", f"cannot read Banner file {val}: {e.strerror or e}")
    return CheckResult("pass")


def _fix_banner() -> list[RollbackEntry]:
    banner_path = Path(BANNER_FILE)
    if not banner_path.exists() or not banner_path.read_text().strip():
        banner_path.write_text("Authorized uses only. All activity may be monitored and reported.\n")
    return [_set_sshd_setting("Banner", BANNER_FILE)]


register(Control(
    id="5.2.18",
    title="Ensure SSH warning banner is configured",
    section="ssh",
    check=_check_banner,
    fix=_fix_banner,
))


# ---- CIS 5.2.19: Ensure SSH MaxSessions is limited ----

def _check_max_sessions() -> CheckResult:
    return _audit_sshd("maxsessions", _get_sshd_setting("maxsessions"), _eval_max_sessions)


def _eval_max_sessions(val: str) -> CheckResult:
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
    # CIS (Ubuntu 20.04/22.04, Debian 11) also lists SHA-1 and UMAC-128.
    "hmac-sha1", "hmac-sha1-etm@openssh.com",
    "umac-128@openssh.com", "umac-128-etm@openssh.com",
}

STRONG_MACS = (
    "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,"
    "hmac-sha2-512,hmac-sha2-256"
)


def _check_macs() -> CheckResult:
    return _audit_sshd("macs", _get_sshd_setting("macs"), _eval_macs)


def _eval_macs(val: str) -> CheckResult:
    active = {m.strip().lower() for m in val.split(",")}
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
