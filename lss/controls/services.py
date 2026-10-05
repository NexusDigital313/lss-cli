# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file, 
# via any medium, is strictly prohibited without explicit written authorization.

"""CIS Section 2.2 — Service configuration (disable unnecessary services)."""

from __future__ import annotations

import subprocess
from pathlib import Path

from lss.lib import journal
from lss.lib.registry import Control, CheckResult, RollbackEntry, register


# `systemctl is-active` states in which the unit's process is (or is about
# to be) running. A crash-looping Restart= unit sits in "activating".
_RUNNING_STATES = {"active", "activating", "reloading", "deactivating", "refreshing"}
# `systemctl is-enabled` states that start the unit at boot.
_ENABLED_STATES = {"enabled", "enabled-runtime"}


class _NoSystemctl(Exception):
    """systemctl could not be run, so unit state is unknown."""


def _unit_enabled_state(name: str) -> str | None:
    """`systemctl is-enabled` output, or None if the unit does not exist."""
    try:
        r = subprocess.run(
            ["systemctl", "is-enabled", name],
            capture_output=True, text=True,
        )
    except FileNotFoundError as exc:
        raise _NoSystemctl() from exc
    status = r.stdout.strip()
    if status == "not-found":
        return None
    # systemd < 250 prints nothing on stdout for a missing unit.
    if not status and "No such file" in r.stderr:
        return None
    return status


def _service_is_active(name: str) -> bool | None:
    """Check if a systemd unit is running. Returns None if systemctl is missing."""
    try:
        r = subprocess.run(
            ["systemctl", "is-active", name],
            capture_output=True, text=True,
        )
        return r.stdout.strip() in _RUNNING_STATES
    except FileNotFoundError:
        return None


def _service_is_enabled(name: str) -> bool | None:
    """Check if a systemd unit is enabled. Returns None if not installed."""
    try:
        status = _unit_enabled_state(name)
    except _NoSystemctl:
        return None
    if status is None:
        return None
    return status in _ENABLED_STATES


def _dpkg_installed(status: str) -> bool:
    # ${Status} is "<want> <error> <state>". The files are on disk unless the
    # state is not-installed or config-files: "hold ok installed" (apt-mark
    # hold) and "deinstall ok installed" (selected for removal) are installed.
    parts = status.split()
    return len(parts) == 3 and parts[2] not in ("not-installed", "config-files")


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
        if r.returncode == 0 and _dpkg_installed(r.stdout):
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


def _check_service_disabled(units: list[str], pkgs: list[str]) -> CheckResult:
    """Generic check: no unit that runs the server may be active or enabled,
    ideally the package is not installed.

    `units` lists every unit that can start the server: the Debian and RHEL
    service names and any socket or path unit that activates it on demand
    (a disabled cups.service still starts through an enabled cups.socket).
    """
    try:
        states = {u: _unit_enabled_state(u) for u in units}
    except _NoSystemctl:
        installed = [p for p in pkgs if _pkg_is_installed(p)]
        if installed:
            return CheckResult(
                "warn", f"{installed[0]} installed but systemctl unavailable to check its service")
        return CheckResult("pass", "not installed")

    # A socket or path unit cannot start a masked service; CIS remediation
    # masks the service and the socket, so a leftover cups.path is inert.
    masked = {u.rsplit(".", 1)[0] for u, st in states.items()
              if u.endswith(".service") and st == "masked"}
    found = [u for u, st in states.items() if st is not None
             and (u.endswith(".service") or u.rsplit(".", 1)[0] not in masked)]
    # Not installed at all — best case
    if not found:
        if not any(_pkg_is_installed(p) for p in pkgs):
            return CheckResult("pass", "not installed")
        return CheckResult("pass", "installed but service not found")

    for u in found:
        if _service_is_active(u):
            return CheckResult("fail", f"{u} is active")
    for u in found:
        if states[u] in _ENABLED_STATES:
            return CheckResult("fail", f"{u} is enabled")
    return CheckResult("pass")


def _fix_service_disabled(units: list[str]) -> list[RollbackEntry]:
    """Stop, disable, and mask every unit that can start the service.

    Activating units (sockets, paths) go first so they cannot restart the
    service between its stop and its mask."""
    entries = []
    present = []
    for u in units:
        try:
            if _unit_enabled_state(u) is not None:
                present.append(u)
        except _NoSystemctl:
            return entries
    ordered = ([u for u in present if not u.endswith(".service")]
               + [u for u in present if u.endswith(".service")])

    for svc_name in ordered:
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
# (id, title, units, packages). Units and packages cover Debian/Ubuntu and
# RHEL names; units that do not exist on a host are skipped.
_SERVICES = [
    ("2.2.2",  "Ensure Avahi Server is not installed",
     ["avahi-daemon.socket", "avahi-daemon.service"], ["avahi-daemon", "avahi"]),
    ("2.2.3",  "Ensure CUPS is not installed",
     ["cups.socket", "cups.path", "cups.service"], ["cups"]),
    ("2.2.4",  "Ensure DHCP Server is not installed",
     ["isc-dhcp-server.service", "isc-dhcp-server6.service",
      "dhcpd.service", "dhcpd6.service"], ["isc-dhcp-server", "dhcp-server", "dhcp"]),
    ("2.2.5",  "Ensure LDAP server is not installed",
     ["slapd.service"], ["slapd", "openldap-servers"]),
    ("2.2.6",  "Ensure NFS is not installed",
     ["nfs-server.service"], ["nfs-kernel-server", "nfs-utils"]),
    ("2.2.7",  "Ensure DNS server is not installed",
     ["named.service", "bind9.service"], ["bind9", "bind"]),
    ("2.2.8",  "Ensure FTP server is not installed",
     ["vsftpd.service"], ["vsftpd"]),
    ("2.2.9",  "Ensure HTTP server is not installed",
     ["apache2.service", "httpd.service", "nginx.service"], ["apache2", "httpd", "nginx"]),
    ("2.2.10", "Ensure IMAP and POP3 server is not installed",
     ["dovecot.socket", "dovecot.service"], ["dovecot-core", "dovecot"]),
    ("2.2.11", "Ensure Samba is not installed",
     ["smbd.service", "smb.service"], ["samba"]),
    ("2.2.12", "Ensure HTTP Proxy server is not installed",
     ["squid.service"], ["squid"]),
    ("2.2.13", "Ensure SNMP server is not installed",
     ["snmpd.service"], ["snmpd", "net-snmp"]),
    ("2.2.14", "Ensure NIS server is not installed",
     ["ypserv.service"], ["nis", "ypserv"]),
    ("2.2.16", "Ensure rsync service is not installed",
     ["rsync.service", "rsyncd.socket", "rsyncd.service"], ["rsync", "rsync-daemon"]),
]

# 2.2.15 is intentionally NOT in the list above. CIS "mail transfer agent is
# configured for local-only mode" does NOT mean "disable the MTA" — a mail
# server bound to loopback is compliant and expected. Disabling/masking postfix
# (as the generic service handler would) tears down a correctly-configured
# local MTA. It gets its own check/fix below that only constrains the listener.


for _id, _title, _units, _pkgs in _SERVICES:

    def _make_check(units, pkgs):
        def check():
            return _check_service_disabled(units, pkgs)
        return check

    def _make_fix(units):
        def fix():
            return _fix_service_disabled(units)
        return fix

    register(Control(
        id=_id,
        title=_title,
        section="services",
        check=_make_check(_units, _pkgs),
        fix=_make_fix(_units),
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


# SMTP, submissions and submission ports (CIS checks all three).
_MTA_PORTS = {"25", "465", "587"}
# Packages that provide an MTA daemon, for when the listener list is unreadable.
_MTA_PACKAGES = ["postfix", "exim4-daemon-light", "exim4-daemon-heavy", "exim",
                 "sendmail", "opensmtpd"]
_POSTFIX_MAIN_CF = "/etc/postfix/main.cf"


def _is_loopback(host: str) -> bool:
    host = host.strip("[]").split("%", 1)[0].lower()
    return (host.startswith("127.") or host == "::1"
            or host.startswith("::ffff:127.") or host == "localhost")


def _external_mta_listeners() -> list[str] | None:
    """Local addresses listening on an MTA port off loopback, as `ss` shows
    them. None if `ss` could not be run."""
    try:
        r = subprocess.run(["ss", "-H", "-tuln"], capture_output=True, text=True)
    except FileNotFoundError:
        return None
    if r.returncode != 0:
        return None
    out = []
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0].lower() == "netid":
            continue
        local = parts[4]
        host, _, port = local.rpartition(":")
        if port in _MTA_PORTS and not _is_loopback(host):
            out.append(local)
    return out


def _check_mta_local_only() -> CheckResult:
    """Pass if no MTA listens off loopback (CIS: ss shows nothing on :25,
    :465 or :587 except 127.0.0.1 / ::1) and postfix's configured listener
    is loopback-only, so it stays that way after a restart. We do NOT fail
    merely because an MTA is running — a local-only MTA is compliant."""
    listeners = _external_mta_listeners()
    if listeners:
        return CheckResult(
            "fail", f"MTA listening on {', '.join(listeners)} — should be loopback-only")
    if listeners is None and any(_pkg_is_installed(p) for p in _MTA_PACKAGES):
        return CheckResult("warn", "MTA installed but listening sockets unreadable (ss failed)")

    val = _postconf("inet_interfaces")
    if val is None:
        # postconf missing / postfix not configured
        if not _pkg_is_installed("postfix"):
            return CheckResult("pass", "no MTA listening off loopback")
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
    restarts. Does NOT stop/disable/mask postfix — the MTA keeps working for
    local delivery. Other MTAs (exim4) are left for the operator."""
    maincf = Path(_POSTFIX_MAIN_CF)
    if not maincf.exists():
        return []
    bkp = journal.backup_file(str(maincf))
    r = subprocess.run(
        ["postconf", "-e", "inet_interfaces=loopback-only"],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(f"postconf failed: {r.stderr.strip()}")
    # postfix only rebinds its listeners on a full restart; a reload keeps
    # the old sockets, so the MTA would still listen on every interface.
    # The mail queue survives the restart.
    subprocess.run(["systemctl", "restart", "postfix"], capture_output=True)
    return [RollbackEntry(
        action="set postfix inet_interfaces=loopback-only",
        path=str(maincf),
        backup=bkp,
        # Restore main.cf from backup, then restart so the old listener is live.
        undo=[["systemctl", "restart", "postfix"]],
    )]


register(Control(
    id="2.2.15",
    title="Ensure mail transfer agent is configured for local-only mode",
    section="services",
    check=_check_mta_local_only,
    fix=_fix_mta_local_only,
))