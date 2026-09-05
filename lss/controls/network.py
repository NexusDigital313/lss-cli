# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized reproduction, copying, modification, distribution,
# redistribution, publication, reverse engineering, decompilation, or
# disassembly of this file, in whole or in part, via any medium, is
# strictly prohibited without explicit prior written authorization.

"""CIS Section 3.3 — Network parameters."""

from lss.lib.registry import Control, CheckResult, RollbackEntry, register
from lss.lib.sysctl import get_sysctl as _get_sysctl, set_sysctl as _set_sysctl


# ---- CIS 3.3.1: Ensure source routed packets are not accepted ----

_SOURCE_ROUTE_KEYS = [
    "net.ipv4.conf.all.accept_source_route",
    "net.ipv4.conf.default.accept_source_route",
]


def _check_source_route() -> CheckResult:
    for key in _SOURCE_ROUTE_KEYS:
        val = _get_sysctl(key)
        if val != "0":
            return CheckResult("fail", f"{key}={val}")
    return CheckResult("pass")


def _fix_source_route() -> list[RollbackEntry]:
    entries = []
    for key in _SOURCE_ROUTE_KEYS:
        entries.append(_set_sysctl(key, "0"))
    return entries


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


def _check_icmp_redirect() -> CheckResult:
    for key in _ICMP_KEYS:
        val = _get_sysctl(key)
        if val != "0":
            return CheckResult("fail", f"{key}={val}")
    return CheckResult("pass")


def _fix_icmp_redirect() -> list[RollbackEntry]:
    entries = []
    for key in _ICMP_KEYS:
        entries.append(_set_sysctl(key, "0"))
    return entries


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
    for key in _SECURE_ICMP_KEYS:
        val = _get_sysctl(key)
        if val != "0":
            return CheckResult("fail", f"{key}={val}")
    return CheckResult("pass")


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
    for key in _LOG_MARTIANS_KEYS:
        val = _get_sysctl(key)
        if val != "1":
            return CheckResult("fail", f"{key}={val}")
    return CheckResult("pass")


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

# Only check IPv6 if it's enabled on the system
def _check_ip_forward() -> CheckResult:
    for key in _IP_FORWARD_KEYS:
        val = _get_sysctl(key)
        if val != "0":
            return CheckResult("fail", f"{key}={val}")
    v6 = _get_sysctl("net.ipv6.conf.all.forwarding")
    if v6 is not None and v6 != "0":
        return CheckResult("fail", f"net.ipv6.conf.all.forwarding={v6}")
    return CheckResult("pass")


def _fix_ip_forward() -> list[RollbackEntry]:
    entries = [_set_sysctl("net.ipv4.ip_forward", "0")]
    v6 = _get_sysctl("net.ipv6.conf.all.forwarding")
    if v6 is not None:
        entries.append(_set_sysctl("net.ipv6.conf.all.forwarding", "0"))
    return entries


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
    for key in _SEND_REDIRECTS_KEYS:
        val = _get_sysctl(key)
        if val != "0":
            return CheckResult("fail", f"{key}={val}")
    return CheckResult("pass")


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
    val = _get_sysctl("net.ipv4.icmp_echo_ignore_broadcasts")
    if val == "1":
        return CheckResult("pass")
    return CheckResult("fail", f"icmp_echo_ignore_broadcasts={val}")


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
    val = _get_sysctl("net.ipv4.icmp_ignore_bogus_error_responses")
    if val == "1":
        return CheckResult("pass")
    return CheckResult("fail", f"icmp_ignore_bogus_error_responses={val}")


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
    for key in _RP_FILTER_KEYS:
        val = _get_sysctl(key)
        if val != "1":
            return CheckResult("fail", f"{key}={val}")
    return CheckResult("pass")


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
    val = _get_sysctl("net.ipv4.tcp_syncookies")
    if val == "1":
        return CheckResult("pass")
    return CheckResult("fail", f"tcp_syncookies={val}")


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
    # Only relevant if IPv6 is enabled
    v6_all = _get_sysctl("net.ipv6.conf.all.disable_ipv6")
    if v6_all == "1":
        return CheckResult("pass", "IPv6 is disabled")
    for key in _IPV6_RA_KEYS:
        val = _get_sysctl(key)
        if val is not None and val != "0":
            return CheckResult("fail", f"{key}={val}")
    return CheckResult("pass")


def _fix_ipv6_ra() -> list[RollbackEntry]:
    entries = []
    for key in _IPV6_RA_KEYS:
        val = _get_sysctl(key)
        if val is not None:
            entries.append(_set_sysctl(key, "0"))
    return entries


register(Control(
    id="3.3.9",
    title="Ensure IPv6 router advertisements are not accepted",
    section="network",
    check=_check_ipv6_ra,
    fix=_fix_ipv6_ra,
))
