"""CIS Section 2.2 — Service configuration (disable unnecessary services)."""

from __future__ import annotations

import subprocess

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
    """Check if a package is installed (Debian or RHEL)."""
    # Debian family
    r = subprocess.run(
        ["dpkg-query", "-W", "-f=${Status}", name],
        capture_output=True, text=True,
    )
    if r.returncode == 0 and "install ok installed" in r.stdout:
        return True

    # RHEL family
    r = subprocess.run(
        ["rpm", "-q", name],
        capture_output=True, text=True,
    )
    if r.returncode == 0:
        return True

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
    ("2.2.15", "Ensure mail transfer agent is local-only",   "postfix",            "postfix"),
    ("2.2.16", "Ensure rsync service is not installed",      "rsync",              "rsync"),
]


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