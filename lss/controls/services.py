# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized reproduction, copying, modification, distribution,
# redistribution, publication, reverse engineering, decompilation, or
# disassembly of this file, in whole or in part, via any medium, is
# strictly prohibited without explicit prior written authorization.

"""CIS Section 2.2 — Service configuration (disable unnecessary services)."""

from __future__ import annotations

import subprocess
from pathlib import Path

from lss.lib import journal
from lss.lib.registry import Control, CheckResult, RollbackEntry, register


def _service_is_active(name: str) -> bool | None:
    """Check if a systemd service is active. Returns None if not installed."""
    try:
        r = subprocess.run(
            ["systemctl", "is-active", name],
            capture_output=True, text=True,
        )
        return r.stdout.strip() == "active"
    except FileNotFoundError:
        return None


def _service_is_enabled(name: str) -> bool | None:
    """Check if a systemd service is enabled."""
    try:
        r = subprocess.run(
            ["systemctl", "is-enabled", name],
            capture_output=True, text=True,
        )
        status = r.stdout.strip()
        if status == "not-found":
            return None
        return status == "enabled"
    except FileNotFoundError:
        return None


def _pkg_is_installed(name: str) -> bool:
    """Check if a package is installed (Debian or RHEL).

    A missing package manager (dpkg-query/rpm not on this host) means the
    package can't be installed via it — treat as not-installed rather than
    letting FileNotFoundError escape and crash the caller's check."""
    # Debian family
    try:
        r = subprocess.run(
            ["dpkg-query", "-W", "-f=${Status}", name],
            capture_output=True, text=True,
        )
        if r.returncode == 0 and "install ok installed" in r.stdout:
            return True
    except FileNotFoundError:
        pass

    # RHEL family
    try:
        r = subprocess.run(
            ["rpm", "-q", name],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            return True
    except FileNotFoundError:
        pass

    return False


def _check_service_disabled(svc_name: str, pkg_name: str) -> CheckResult:
    """Generic check: service should not be active or enabled, ideally not installed."""
    enabled = _service_is_enabled(svc_name)

    # Not installed at all — best case
    if enabled is None:
        if not _pkg_is_installed(pkg_name):
            return CheckResult("pass", "not installed")
        return CheckResult("pass", "installed but service not found")

    active = _service_is_active(svc_name)

    if active:
        return CheckResult("fail", f"{svc_name} is active")
    if enabled:
        return CheckResult("fail", f"{svc_name} is enabled")
    return CheckResult("pass")


def _fix_service_disabled(svc_name: str) -> list[RollbackEntry]:
    """Stop, disable, and mask a service."""
    entries = []

    if subprocess.run(["systemctl", "stop", svc_name],
                      capture_output=True, text=True).returncode == 0:
        entries.append(RollbackEntry(
            action=f"stopped {svc_name}",
            undo=[["systemctl", "start", svc_name]],
        ))

    if subprocess.run(["systemctl", "disable", svc_name],
                      capture_output=True, text=True).returncode == 0:
        entries.append(RollbackEntry(
            action=f"disabled {svc_name}",
            undo=[["systemctl", "enable", svc_name]],
        ))

    if subprocess.run(["systemctl", "mask", svc_name],
                      capture_output=True, text=True).returncode == 0:
        entries.append(RollbackEntry(
            action=f"masked {svc_name}",
            undo=[["systemctl", "unmask", svc_name]],
        ))

    return entries


# Define services that CIS says should not be enabled on a server
# (id, title, service_name, package_name)
_SERVICES = [
    ("2.2.2",  "Ensure Avahi Server is not installed",       "avahi-daemon",       "avahi-daemon"),
    ("2.2.3",  "Ensure CUPS is not installed",               "cups",               "cups"),
    ("2.2.4",  "Ensure DHCP Server is not installed",        "isc-dhcp-server",    "isc-dhcp-server"),
    ("2.2.5",  "Ensure LDAP server is not installed",        "slapd",              "slapd"),
    ("2.2.6",  "Ensure NFS is not installed",                "nfs-server",         "nfs-kernel-server"),
    ("2.2.7",  "Ensure DNS server is not installed",         "named",              "bind9"),
    ("2.2.8",  "Ensure FTP server is not installed",         "vsftpd",             "vsftpd"),
    ("2.2.9",  "Ensure HTTP server is not installed",        "apache2",            "apache2"),
    ("2.2.10", "Ensure IMAP and POP3 server is not installed", "dovecot",          "dovecot-core"),
    ("2.2.11", "Ensure Samba is not installed",              "smbd",               "samba"),
    ("2.2.12", "Ensure HTTP Proxy server is not installed",  "squid",              "squid"),
    ("2.2.13", "Ensure SNMP server is not installed",        "snmpd",              "snmpd"),
    ("2.2.14", "Ensure NIS server is not installed",         "ypserv",             "nis"),
    ("2.2.16", "Ensure rsync service is not installed",      "rsync",              "rsync"),
]

# 2.2.15 is intentionally NOT in the list above. CIS "mail transfer agent is
# configured for local-only mode" does NOT mean "disable the MTA" — a mail
# server bound to loopback is compliant and expected. Disabling/masking postfix
# (as the generic service handler would) tears down a correctly-configured
# local MTA. It gets its own check/fix below that only constrains the listener.


for _id, _title, _svc, _pkg in _SERVICES:
    svc, pkg = _svc, _pkg  # capture

    def _make_check(s, p):
        def check():
            return _check_service_disabled(s, p)
        return check

    def _make_fix(s):
        def fix():
            return _fix_service_disabled(s)
        return fix

    register(Control(
        id=_id,
        title=_title,
        section="services",
        check=_make_check(svc, pkg),
        fix=_make_fix(svc),
    ))


# ---- CIS 2.2.15: Ensure mail transfer agent is configured for local-only mode ----

# Loopback-only listener values postfix accepts for inet_interfaces.
_MTA_LOCAL_VALUES = {"loopback-only", "localhost"}


def _postconf(param: str) -> str | None:
    """Return the effective postfix value for `param`, or None if unavailable."""
    try:
        r = subprocess.run(["postconf", "-h", param], capture_output=True, text=True)
    except FileNotFoundError:
        return None
    if r.returncode != 0:
        return None
    return r.stdout.strip()


def _check_mta_local_only() -> CheckResult:
    """Pass if postfix listens only on loopback (or isn't installed). We do NOT
    fail merely because postfix is running — a local-only MTA is compliant."""
    val = _postconf("inet_interfaces")
    if val is None:
        # postconf missing / postfix not configured
        if not _pkg_is_installed("postfix"):
            return CheckResult("pass", "no MTA installed")
        return CheckResult("warn", "postfix installed but inet_interfaces unreadable")
    low = val.lower()
    if low in _MTA_LOCAL_VALUES:
        return CheckResult("pass", f"inet_interfaces={val}")
    # An explicit interface list is local-only if every entry is a loopback addr.
    entries = [e.strip().lower() for e in val.replace(",", " ").split() if e.strip()]
    if entries and all(e in ("127.0.0.1", "::1", "localhost") for e in entries):
        return CheckResult("pass", f"inet_interfaces={val}")
    return CheckResult("fail", f"inet_interfaces={val} — should be loopback-only")


def _fix_mta_local_only() -> list[RollbackEntry]:
    """Constrain postfix to loopback. Backs up main.cf, sets inet_interfaces,
    reloads. Does NOT stop/disable/mask postfix — the MTA keeps working for
    local delivery."""
    maincf = Path("/etc/postfix/main.cf")
    if not maincf.exists():
        return []
    bkp = journal.backup_file(str(maincf))
    r = subprocess.run(
        ["postconf", "-e", "inet_interfaces=loopback-only"],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(f"postconf failed: {r.stderr.strip()}")
    # Reload (preferred) so live delivery keeps running; fall back to restart.
    if subprocess.run(["systemctl", "reload", "postfix"], capture_output=True).returncode != 0:
        subprocess.run(["systemctl", "restart", "postfix"], capture_output=True)
    return [RollbackEntry(
        action="set postfix inet_interfaces=loopback-only",
        path=str(maincf),
        backup=bkp,
        # Restore main.cf from backup, then reload so the old listener is live.
        undo=[["systemctl", "reload", "postfix"]],
    )]


register(Control(
    id="2.2.15",
    title="Ensure mail transfer agent is configured for local-only mode",
    section="services",
    check=_check_mta_local_only,
    fix=_fix_mta_local_only,
))