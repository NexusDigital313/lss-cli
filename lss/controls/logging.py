"""CIS Section 4 — Logging and Auditing."""

from __future__ import annotations

import subprocess
from pathlib import Path

from lss.lib import journal
from lss.lib.registry import Control, CheckResult, RollbackEntry, register


def _systemd_is_active(unit: str) -> bool:
    r = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True)
    return r.stdout.strip() == "active"


def _systemd_is_enabled(unit: str) -> bool:
    r = subprocess.run(["systemctl", "is-enabled", unit], capture_output=True, text=True)
    return r.stdout.strip() == "enabled"


# ---- CIS 4.1.1.1: Ensure auditd is installed ----

def _check_auditd_installed() -> CheckResult:
    r = subprocess.run(["which", "auditd"], capture_output=True, text=True)
    if r.returncode == 0:
        return CheckResult("pass")
    # Check package
    r2 = subprocess.run(["dpkg-query", "-W", "auditd"], capture_output=True, text=True)
    if r2.returncode == 0:
        return CheckResult("pass")
    r3 = subprocess.run(["rpm", "-q", "audit"], capture_output=True, text=True)
    if r3.returncode == 0:
        return CheckResult("pass")
    return CheckResult("fail", "auditd is not installed")


register(Control(
    id="4.1.1.1",
    title="Ensure auditd is installed",
    section="logging",
    check=_check_auditd_installed,
    fix=None,  # Package installation requires user decision
))


# ---- CIS 4.1.1.2: Ensure auditd service is enabled and running ----

def _check_auditd_running() -> CheckResult:
    if not _systemd_is_enabled("auditd"):
        return CheckResult("fail", "auditd is not enabled")
    if not _systemd_is_active("auditd"):
        return CheckResult("fail", "auditd is not active")
    return CheckResult("pass")


def _fix_auditd_running() -> list[RollbackEntry]:
    entries = []
    if subprocess.run(["systemctl", "enable", "auditd"],
                      capture_output=True, text=True).returncode == 0:
        entries.append(RollbackEntry(action="enabled auditd", undo=[["systemctl", "disable", "auditd"]]))
    if subprocess.run(["systemctl", "start", "auditd"],
                      capture_output=True, text=True).returncode == 0:
        entries.append(RollbackEntry(action="started auditd", undo=[["systemctl", "stop", "auditd"]]))
    return entries


register(Control(
    id="4.1.1.2",
    title="Ensure auditd service is enabled and running",
    section="logging",
    check=_check_auditd_running,
    fix=_fix_auditd_running,
))


# ---- CIS 4.1.1.3: Ensure audit log storage size is configured ----

def _check_audit_log_size() -> CheckResult:
    conf = Path("/etc/audit/auditd.conf")
    if not conf.exists():
        return CheckResult("warn", "auditd.conf not found")
    for line in conf.read_text().splitlines():
        if line.strip().startswith("max_log_file"):
            parts = line.split("=")
            if len(parts) == 2:
                val = parts[1].strip()
                try:
                    if int(val) >= 8:
                        return CheckResult("pass")
                    return CheckResult("warn", f"max_log_file={val}MB, recommended: ≥ 8")
                except ValueError:
                    pass
    return CheckResult("fail", "max_log_file not set in auditd.conf")


register(Control(
    id="4.1.1.3",
    title="Ensure audit log storage size is configured",
    section="logging",
    check=_check_audit_log_size,
    fix=None,  # Requires site-specific sizing
))


# ---- CIS 4.1.1.4: Ensure audit logs are not automatically deleted ----

def _check_audit_log_retention() -> CheckResult:
    conf = Path("/etc/audit/auditd.conf")
    if not conf.exists():
        return CheckResult("warn", "auditd.conf not found")
    for line in conf.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("max_log_file_action"):
            val = stripped.split("=")[1].strip().lower() if "=" in stripped else ""
            if val == "keep_logs":
                return CheckResult("pass")
            return CheckResult("fail", f"max_log_file_action={val}, recommended: keep_logs")
    return CheckResult("fail", "max_log_file_action not set")


def _fix_audit_log_retention() -> list[RollbackEntry]:
    conf = Path("/etc/audit/auditd.conf")
    if not conf.exists():
        return []
    bkp = journal.backup_file(str(conf))
    text = conf.read_text()
    lines = text.splitlines(keepends=True)
    found = False
    for i, line in enumerate(lines):
        if line.strip().startswith("max_log_file_action"):
            lines[i] = "max_log_file_action = keep_logs\n"
            found = True
            break
    if not found:
        lines.append("max_log_file_action = keep_logs\n")
    conf.write_text("".join(lines))
    return [RollbackEntry(
        action="set max_log_file_action = keep_logs",
        path=str(conf),
        backup=bkp,
    )]


register(Control(
    id="4.1.1.4",
    title="Ensure audit logs are not automatically deleted",
    section="logging",
    check=_check_audit_log_retention,
    fix=_fix_audit_log_retention,
))


# ---- CIS 4.2.1.1: Ensure journald is configured to write to persistent storage ----

def _check_journald_persistent() -> CheckResult:
    conf = Path("/etc/systemd/journald.conf")
    if not conf.exists():
        return CheckResult("warn", "journald.conf not found")
    for line in conf.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("Storage="):
            val = stripped.split("=")[1].strip().lower()
            if val == "persistent":
                return CheckResult("pass")
            return CheckResult("fail", f"Storage={val}, recommended: persistent")
    # Default behavior — check if /var/log/journal exists
    if Path("/var/log/journal").exists():
        return CheckResult("pass", "persistent by default")
    return CheckResult("fail", "journald Storage not set to persistent")


def _fix_journald_persistent() -> list[RollbackEntry]:
    conf = Path("/etc/systemd/journald.conf")
    bkp = journal.backup_file(str(conf))
    text = conf.read_text() if conf.exists() else "[Journal]\n"
    lines = text.splitlines(keepends=True)
    found = False
    for i, line in enumerate(lines):
        if line.strip().startswith("Storage=") or line.strip().startswith("#Storage="):
            lines[i] = "Storage=persistent\n"
            found = True
            break
    if not found:
        lines.append("Storage=persistent\n")
    conf.write_text("".join(lines))

    # Create the directory
    Path("/var/log/journal").mkdir(exist_ok=True)

    # Restart journald to pick up the change
    subprocess.run(["systemctl", "restart", "systemd-journald"], capture_output=True)

    return [RollbackEntry(
        action="set journald Storage=persistent",
        path=str(conf),
        backup=bkp,
        # After the file is restored, rollback also needs to restart journald
        # so the previous setting takes effect again.
        undo=[["systemctl", "restart", "systemd-journald"]],
    )]


register(Control(
    id="4.2.1.1",
    title="Ensure journald is configured to write to persistent storage",
    section="logging",
    check=_check_journald_persistent,
    fix=_fix_journald_persistent,
))


# ---- CIS 4.2.1.2: Ensure journald is configured to compress large log files ----

def _check_journald_compress() -> CheckResult:
    conf = Path("/etc/systemd/journald.conf")
    if not conf.exists():
        return CheckResult("warn", "journald.conf not found")
    for line in conf.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("Compress="):
            val = stripped.split("=")[1].strip().lower()
            if val == "yes":
                return CheckResult("pass")
            return CheckResult("fail", f"Compress={val}")
    # Default is yes in most distros
    return CheckResult("pass", "default is yes")


register(Control(
    id="4.2.1.2",
    title="Ensure journald is configured to compress large log files",
    section="logging",
    check=_check_journald_compress,
    fix=None,  # Default is usually correct
))


# ---- CIS 4.2.2.1: Ensure rsyslog is installed ----

def _check_rsyslog() -> CheckResult:
    r = subprocess.run(["which", "rsyslogd"], capture_output=True, text=True)
    if r.returncode == 0:
        return CheckResult("pass")
    r2 = subprocess.run(["dpkg-query", "-W", "rsyslog"], capture_output=True, text=True)
    if r2.returncode == 0 and "install ok installed" in r2.stdout:
        return CheckResult("pass")
    r3 = subprocess.run(["rpm", "-q", "rsyslog"], capture_output=True, text=True)
    if r3.returncode == 0:
        return CheckResult("pass")
    return CheckResult("warn", "rsyslog not installed — journald may be sole log source")


register(Control(
    id="4.2.2.1",
    title="Ensure rsyslog is installed",
    section="logging",
    check=_check_rsyslog,
    fix=None,  # Package installation
))