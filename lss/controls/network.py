# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file, 
# via any medium, is strictly prohibited without explicit written authorization.

"""CIS Section 3.3 — Network parameters."""

from fnmatch import fnmatchcase
from pathlib import Path

from lss.lib.registry import Control, CheckResult, RollbackEntry, register
from lss.lib.sysctl import get_sysctl as _get_sysctl, set_sysctl as _set_sysctl
from lss.lib.sysctl import ipv6_disabled as _ipv6_disabled


# ---- Persisted sysctl configuration ----
#
# CIS audits each parameter twice: the running value and the value the
# configuration files apply at boot. A `sysctl -w` that was never persisted,
# or a later sysctl.d file that sets the bad value again, reverts at reboot.
# systemd-sysctl reads *.conf from these directories; a file name in an
# earlier directory shadows the same name in a later one, all files are then
# applied in file-name order, the last explicit assignment of a key wins, and
# an explicit assignment always beats a glob. (/etc/sysctl.conf is applied
# through the /etc/sysctl.d/99-sysctl.conf symlink.)
_SYSCTL_D_DIRS = [
    "/etc/sysctl.d",
    "/run/sysctl.d",
    "/usr/local/lib/sysctl.d",
    "/usr/lib/sysctl.d",
    "/lib/sysctl.d",
]


def _read_text(path: Path) -> str:
    return path.read_text()


def _normalise_key(key: str) -> str:
    # sysctl.d(5): if the first separator is a slash, slashes and dots swap.
    slash, dot = key.find("/"), key.find(".")
    if slash != -1 and (dot == -1 or slash < dot):
        key = key.translate(str.maketrans("/.", "./"))
    return key


def _persisted_assignments() -> list[tuple[str, str | None]] | None:
    """Every (key, value) assignment in boot order; value None excludes the
    key from globs. None if a directory or file could not be read."""
    files: dict[str, Path] = {}
    try:
        for d in _SYSCTL_D_DIRS:
            p = Path(d)
            if not p.is_dir():
                continue
            for f in p.iterdir():
                if f.name.endswith(".conf"):
                    files.setdefault(f.name, f)
        out: list[tuple[str, str | None]] = []
        for name in sorted(files):
            for line in _read_text(files[name]).splitlines():
                s = line.strip()
                if not s or s[0] in "#;":
                    continue
                if "=" not in s:
                    if s.startswith("-"):
                        out.append((_normalise_key(s[1:].strip()), None))
                    continue
                k, v = s.split("=", 1)
                out.append((_normalise_key(k.strip().lstrip("-")), v.strip()))
    except OSError:
        return None
    return out


def _persisted_value(assignments: list[tuple[str, str | None]], key: str) -> str | None:
    explicit: str | None = None
    excluded = False
    glob: str | None = None
    for k, v in assignments:
        if any(c in k for c in "*?["):
            if v is not None and fnmatchcase(key, k):
                glob = v
        elif k == key:
            if v is None:
                excluded = True
            else:
                explicit = v
    if explicit is not None:
        return explicit
    return None if excluded else glob


def _same(value: str | None, want: str) -> bool:
    if value is None:
        return False
    value = value.strip()
    if value == want:
        return True
    try:
        return int(value) == int(want)
    except ValueError:
        return False


def _check_params(want: str, v4_keys: list[str], v6_keys: list[str] | tuple[str, ...] = ()) -> CheckResult:
    """Every key must be `want` both now and at boot. IPv6 keys are skipped
    only when IPv6 is off everywhere; with IPv6 on, an unreadable key fails."""
    keys = list(v4_keys)
    if v6_keys and not _ipv6_disabled():
        keys += list(v6_keys)
    for key in keys:
        val = _get_sysctl(key)
        if not _same(val, want):
            return CheckResult("fail", f"{key}={val}")
    assignments = _persisted_assignments()
    if assignments is None:
        return CheckResult("warn", "could not read the sysctl.d configuration")
    for key in keys:
        pval = _persisted_value(assignments, key)
        if pval is None:
            return CheckResult(
                "fail", f"{key} is not set in sysctl.d (runtime only, reverts at boot)")
        if not _same(pval, want):
            return CheckResult("fail", f"{key} = {pval} in sysctl.d (applied at boot)")
    return CheckResult("pass")


def _fix_params(want: str, v4_keys: list[str], v6_keys: list[str] | tuple[str, ...] = ()) -> list[RollbackEntry]:
    entries = [_set_sysctl(k, want) for k in v4_keys]
    # An IPv6 key only exists while the ipv6 module is loaded.
    entries += [_set_sysctl(k, want) for k in v6_keys if _get_sysctl(k) is not None]
    return entries


# ---- CIS 3.3.1: Ensure source routed packets are not accepted ----

_SOURCE_ROUTE_KEYS = [
    "net.ipv4.conf.all.accept_source_route",
    "net.ipv4.conf.default.accept_source_route",
]
_SOURCE_ROUTE_V6_KEYS = [
    "net.ipv6.conf.all.accept_source_route",
    "net.ipv6.conf.default.accept_source_route",
]


def _check_source_route() -> CheckResult:
    return _check_params("0", _SOURCE_ROUTE_KEYS, _SOURCE_ROUTE_V6_KEYS)


def _fix_source_route() -> list[RollbackEntry]:
    return _fix_params("0", _SOURCE_ROUTE_KEYS, _SOURCE_ROUTE_V6_KEYS)


register(Control(
    id="3.3.1",
    title="Ensure source routed packets are not accepted",
    section="network",
    check=_check_source_route,
    fix=_fix_source_route,
))


# ---- CIS 3.3.2: Ensure ICMP redirects are not accepted ----

_ICMP_KEYS = [
    "net.ipv4.conf.all.accept_redirects",
    "net.ipv4.conf.default.accept_redirects",
]
_ICMP_V6_KEYS = [
    "net.ipv6.conf.all.accept_redirects",
    "net.ipv6.conf.default.accept_redirects",
]


def _check_icmp_redirect() -> CheckResult:
    return _check_params("0", _ICMP_KEYS, _ICMP_V6_KEYS)


def _fix_icmp_redirect() -> list[RollbackEntry]:
    return _fix_params("0", _ICMP_KEYS, _ICMP_V6_KEYS)


register(Control(
    id="3.3.2",
    title="Ensure ICMP redirects are not accepted",
    section="network",
    check=_check_icmp_redirect,
    fix=_fix_icmp_redirect,
))


# ---- CIS 3.3.3: Ensure secure ICMP redirects are not accepted ----

_SECURE_ICMP_KEYS = [
    "net.ipv4.conf.all.secure_redirects",
    "net.ipv4.conf.default.secure_redirects",
]


def _check_secure_redirect() -> CheckResult:
    return _check_params("0", _SECURE_ICMP_KEYS)


def _fix_secure_redirect() -> list[RollbackEntry]:
    return [_set_sysctl(k, "0") for k in _SECURE_ICMP_KEYS]


register(Control(
    id="3.3.3",
    title="Ensure secure ICMP redirects are not accepted",
    section="network",
    check=_check_secure_redirect,
    fix=_fix_secure_redirect,
))


# ---- CIS 3.3.4: Ensure suspicious packets are logged ----

_LOG_MARTIANS_KEYS = [
    "net.ipv4.conf.all.log_martians",
    "net.ipv4.conf.default.log_martians",
]


def _check_log_martians() -> CheckResult:
    return _check_params("1", _LOG_MARTIANS_KEYS)


def _fix_log_martians() -> list[RollbackEntry]:
    return [_set_sysctl(k, "1") for k in _LOG_MARTIANS_KEYS]


register(Control(
    id="3.3.4",
    title="Ensure suspicious packets are logged",
    section="network",
    check=_check_log_martians,
    fix=_fix_log_martians,
))


# ---- CIS 3.1.1: Ensure IP forwarding is disabled ----

_IP_FORWARD_KEYS = [
    "net.ipv4.ip_forward",
]
# Checked only while IPv6 is enabled on some interface.
_IP_FORWARD_V6_KEYS = ["net.ipv6.conf.all.forwarding"]


def _check_ip_forward() -> CheckResult:
    return _check_params("0", _IP_FORWARD_KEYS, _IP_FORWARD_V6_KEYS)


def _fix_ip_forward() -> list[RollbackEntry]:
    return _fix_params("0", _IP_FORWARD_KEYS, _IP_FORWARD_V6_KEYS)


register(Control(
    id="3.1.1",
    title="Ensure IP forwarding is disabled",
    section="network",
    check=_check_ip_forward,
    fix=_fix_ip_forward,
))


# ---- CIS 3.1.2: Ensure packet redirect sending is disabled ----

_SEND_REDIRECTS_KEYS = [
    "net.ipv4.conf.all.send_redirects",
    "net.ipv4.conf.default.send_redirects",
]


def _check_send_redirects() -> CheckResult:
    return _check_params("0", _SEND_REDIRECTS_KEYS)


def _fix_send_redirects() -> list[RollbackEntry]:
    return [_set_sysctl(k, "0") for k in _SEND_REDIRECTS_KEYS]


register(Control(
    id="3.1.2",
    title="Ensure packet redirect sending is disabled",
    section="network",
    check=_check_send_redirects,
    fix=_fix_send_redirects,
))


# ---- CIS 3.3.5: Ensure broadcast ICMP requests are ignored ----

def _check_icmp_echo_broadcast() -> CheckResult:
    return _check_params("1", ["net.ipv4.icmp_echo_ignore_broadcasts"])


def _fix_icmp_echo_broadcast() -> list[RollbackEntry]:
    return [_set_sysctl("net.ipv4.icmp_echo_ignore_broadcasts", "1")]


register(Control(
    id="3.3.5",
    title="Ensure broadcast ICMP requests are ignored",
    section="network",
    check=_check_icmp_echo_broadcast,
    fix=_fix_icmp_echo_broadcast,
))


# ---- CIS 3.3.6: Ensure bogus ICMP responses are ignored ----

def _check_bogus_icmp() -> CheckResult:
    return _check_params("1", ["net.ipv4.icmp_ignore_bogus_error_responses"])


def _fix_bogus_icmp() -> list[RollbackEntry]:
    return [_set_sysctl("net.ipv4.icmp_ignore_bogus_error_responses", "1")]


register(Control(
    id="3.3.6",
    title="Ensure bogus ICMP responses are ignored",
    section="network",
    check=_check_bogus_icmp,
    fix=_fix_bogus_icmp,
))


# ---- CIS 3.3.7: Ensure Reverse Path Filtering is enabled ----

_RP_FILTER_KEYS = [
    "net.ipv4.conf.all.rp_filter",
    "net.ipv4.conf.default.rp_filter",
]


def _check_rp_filter() -> CheckResult:
    return _check_params("1", _RP_FILTER_KEYS)


def _fix_rp_filter() -> list[RollbackEntry]:
    return [_set_sysctl(k, "1") for k in _RP_FILTER_KEYS]


register(Control(
    id="3.3.7",
    title="Ensure Reverse Path Filtering is enabled",
    section="network",
    check=_check_rp_filter,
    fix=_fix_rp_filter,
))


# ---- CIS 3.3.8: Ensure TCP SYN Cookies is enabled ----

def _check_syn_cookies() -> CheckResult:
    return _check_params("1", ["net.ipv4.tcp_syncookies"])


def _fix_syn_cookies() -> list[RollbackEntry]:
    return [_set_sysctl("net.ipv4.tcp_syncookies", "1")]


register(Control(
    id="3.3.8",
    title="Ensure TCP SYN Cookies is enabled",
    section="network",
    check=_check_syn_cookies,
    fix=_fix_syn_cookies,
))


# ---- CIS 3.3.9: Ensure IPv6 router advertisements are not accepted ----

_IPV6_RA_KEYS = [
    "net.ipv6.conf.all.accept_ra",
    "net.ipv6.conf.default.accept_ra",
]


def _check_ipv6_ra() -> CheckResult:
    # Only relevant if IPv6 is enabled. all.disable_ipv6 = 1 alone does not
    # disable IPv6 on an interface that was re-enabled afterwards or created
    # later; ipv6_disabled() checks them all.
    if _ipv6_disabled():
        return CheckResult("pass", "IPv6 is disabled")
    return _check_params("0", [], _IPV6_RA_KEYS)


def _fix_ipv6_ra() -> list[RollbackEntry]:
    return _fix_params("0", [], _IPV6_RA_KEYS)


register(Control(
    id="3.3.9",
    title="Ensure IPv6 router advertisements are not accepted",
    section="network",
    check=_check_ipv6_ra,
    fix=_fix_ipv6_ra,
))
