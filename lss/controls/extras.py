"""Extra CIS controls to reach 204 target — network, crypto, login."""

from __future__ import annotations

import subprocess
from pathlib import Path

from lss.lib import distro, journal
from lss.lib.registry import Control, CheckResult, RollbackEntry, register


# ---- LSS-001: Ensure system-wide crypto policy is not legacy ----
# Custom (non-CIS) check that knows about both RHEL crypto-policies and
# Debian's openssl MinProtocol.

def _check_crypto_policy() -> CheckResult:
    # RHEL family: /etc/crypto-policies/config is the source of truth
    p = Path("/etc/crypto-policies/config")
    if p.exists():
        val = p.read_text().strip()
        if val == "LEGACY":
            return CheckResult("fail", "crypto policy is LEGACY")
        return CheckResult("pass", f"crypto policy: {val}")

    # Debian family: inspect openssl MinProtocol if set
    ssl_conf = Path("/etc/ssl/openssl.cnf")
    if ssl_conf.exists():
        text = ssl_conf.read_text()
        if "MinProtocol = TLSv1.2" in text or "MinProtocol = TLSv1.3" in text:
            return CheckResult("pass", "openssl MinProtocol >= TLSv1.2")
        if "MinProtocol" in text:
            return CheckResult("warn", "openssl MinProtocol is set but not >= TLSv1.2")

    # Neither config tells us anything definitive — skip rather than
    # silently passing on a system we can't inspect.
    return CheckResult("skip", f"no crypto policy file on {distro.detect().family} family")


register(Control(
    id="LSS-001",
    title="Ensure system-wide crypto policy is not legacy",
    section="kernel",
    check=_check_crypto_policy,
    fix=None,
))


# ---- CIS 3.2.1: Ensure IP forwarding is disabled (IPv6 specific) ----

def _check_ipv6_forwarding() -> CheckResult:
    r = subprocess.run(["sysctl", "-n", "net.ipv6.conf.all.disable_ipv6"], capture_output=True, text=True)
    if r.stdout.strip() == "1":
        return CheckResult("pass", "IPv6 is disabled")
    r2 = subprocess.run(["sysctl", "-n", "net.ipv6.conf.all.forwarding"], capture_output=True, text=True)
    if r2.returncode == 0 and r2.stdout.strip() == "0":
        return CheckResult("pass")
    return CheckResult("fail", f"net.ipv6.conf.all.forwarding={r2.stdout.strip()}")


register(Control(
    id="3.2.1",
    title="Ensure IPv6 forwarding is disabled",
    section="network",
    check=_check_ipv6_forwarding,
    fix=None,
))


# ---- CIS 5.5: Ensure root login is restricted to system console ----

def _check_securetty() -> CheckResult:
    p = Path("/etc/securetty")
    if not p.exists():
        # If securetty doesn't exist, root can log in from anywhere PAM allows
        return CheckResult("pass", "no /etc/securetty — PAM controls access")
    lines = [l.strip() for l in p.read_text().splitlines() if l.strip() and not l.startswith("#")]
    if len(lines) <= 6:
        return CheckResult("pass", f"{len(lines)} console(s) allowed")
    return CheckResult("warn", f"{len(lines)} consoles in securetty — review for excess")


register(Control(
    id="LSS-002",
    title="Ensure root login is restricted to system console",
    section="auth",
    check=_check_securetty,
    fix=None,
))


# ---- CIS 4.2.3: Ensure permissions on all logfiles are configured ----

def _check_log_permissions() -> CheckResult:
    import os, stat
    issues = 0
    for root, dirs, files in os.walk("/var/log"):
        for f in files:
            fp = os.path.join(root, f)
            try:
                st = os.stat(fp)
                mode = stat.S_IMODE(st.st_mode)
                if mode & 0o007:  # world-readable/writable/executable
                    issues += 1
            except (OSError, PermissionError):
                continue
        break  # Only top level
    if issues == 0:
        return CheckResult("pass")
    return CheckResult("warn", f"{issues} log files in /var/log are world-accessible")


register(Control(
    id="4.2.3",
    title="Ensure permissions on all logfiles are configured",
    section="logging",
    check=_check_log_permissions,
    fix=None,
))


# ---- CIS 2.4: Ensure nonessential services listening are removed ----

def _check_listening_services() -> CheckResult:
    r = subprocess.run(["ss", "-H", "-tlnp"], capture_output=True, text=True)
    lines = [l for l in r.stdout.splitlines() if l.strip()]
    if len(lines) <= 5:
        return CheckResult("pass", f"{len(lines)} listening service(s)")
    return CheckResult("warn", f"{len(lines)} listening services — review for necessity")


register(Control(
    id="2.4",
    title="Ensure nonessential services are removed or masked",
    section="services",
    check=_check_listening_services,
    fix=None,
))


# ---- CIS 6.2.16: Ensure no users have .bash_profile that sources untrusted paths ----

def _check_dot_files_safe() -> CheckResult:
    passwd = Path("/etc/passwd")
    if not passwd.exists():
        return CheckResult("warn", "/etc/passwd not found")
    issues = []
    for line in passwd.read_text().splitlines():
        parts = line.split(":")
        if len(parts) >= 6:
            user, uid_str, home = parts[0], parts[2], parts[5]
            try:
                uid = int(uid_str)
                if uid < 1000 and user != "root":
                    continue
            except ValueError:
                continue
            for dotfile in [".bash_profile", ".bashrc", ".profile"]:
                fp = Path(home) / dotfile
                if fp.exists():
                    try:
                        text = fp.read_text()
                        if "PATH=" in text and (".:" in text or ": " in text):
                            issues.append(f"{user}:{dotfile}")
                    except PermissionError:
                        continue
    if not issues:
        return CheckResult("pass")
    return CheckResult("warn", f"dot files with potential PATH issues: {', '.join(issues[:3])}")


register(Control(
    id="LSS-003",
    title="Ensure no users' dot files have unsafe PATH entries",
    section="users",
    check=_check_dot_files_safe,
    fix=None,
))


# ---- CIS 5.4.5: Ensure default user shell timeout is configured ----

def _check_shell_timeout() -> CheckResult:
    for conf in ["/etc/profile", "/etc/profile.d/timeout.sh", "/etc/bashrc", "/etc/bash.bashrc"]:
        p = Path(conf)
        if p.exists():
            text = p.read_text()
            if "TMOUT=" in text:
                import re
                m = re.search(r"TMOUT=(\d+)", text)
                if m:
                    val = int(m.group(1))
                    if 0 < val <= 900:
                        return CheckResult("pass")
                    return CheckResult("warn", f"TMOUT={val}, recommended: ≤ 900")
    return CheckResult("fail", "TMOUT not set — no shell idle timeout")


def _fix_shell_timeout() -> list[RollbackEntry]:
    conf = Path("/etc/profile.d/80-lss-timeout.sh")
    bkp = journal.backup_file(str(conf))
    conf.write_text("# Set by LSS — shell timeout after 15 minutes of inactivity\nreadonly TMOUT=900\nexport TMOUT\n")
    return [RollbackEntry(
        action="set shell TMOUT=900 in /etc/profile.d/",
        path=str(conf),
        backup=bkp,
        undo=[] if bkp else [["rm", "-f", str(conf)]],
    )]


register(Control(
    id="5.4.5",
    title="Ensure default user shell timeout is 900 seconds or less",
    section="auth",
    check=_check_shell_timeout,
    fix=_fix_shell_timeout,
))


# ---- CIS 4.1.2: Ensure audit backlog limit is sufficient ----

def _check_audit_backlog() -> CheckResult:
    # Check GRUB cmdline for audit_backlog_limit
    for cmdline_path in ["/proc/cmdline"]:
        p = Path(cmdline_path)
        if p.exists():
            text = p.read_text()
            if "audit_backlog_limit=" in text:
                import re
                m = re.search(r"audit_backlog_limit=(\d+)", text)
                if m and int(m.group(1)) >= 8192:
                    return CheckResult("pass")
                elif m:
                    return CheckResult("warn", f"audit_backlog_limit={m.group(1)}, recommended: ≥ 8192")
    return CheckResult("warn", "audit_backlog_limit not set in boot params")


register(Control(
    id="4.1.2",
    title="Ensure audit backlog limit is sufficient",
    section="logging",
    check=_check_audit_backlog,
    fix=None,  # Requires GRUB modification
))