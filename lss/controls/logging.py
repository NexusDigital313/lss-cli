# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file, 
# via any medium, is strictly prohibited without explicit written authorization.

"""CIS Section 4 — Logging and Auditing."""

from __future__ import annotations

import subprocess
from pathlib import Path

from lss.lib import journal, pkg
from lss.lib.registry import Control, CheckResult, RollbackEntry, register


def _systemd_is_active(unit: str) -> bool:
    r = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True)
    return r.stdout.strip() == "active"


def _systemd_is_enabled(unit: str) -> bool:
    r = subprocess.run(["systemctl", "is-enabled", unit], capture_output=True, text=True)
    return r.stdout.strip() == "enabled"


# ---- CIS 4.1.1.1: Ensure auditd is installed ----

def _check_auditd_installed() -> CheckResult:
    verified = False
    try:
        r = subprocess.run(["which", "auditd"], capture_output=True, text=True)
        verified = True
        if r.returncode == 0:
            return CheckResult("pass")
    except FileNotFoundError:
        pass
    # Check package. Query the install Status, not just the exit code:
    # `dpkg-query -W` exits 0 for a removed-but-not-purged package (status
    # `deinstall ok config-files`, auditd binary gone), so the rc alone
    # false-passed this control on a host with no auditd.
    try:
        r2 = subprocess.run(["dpkg-query", "-W", "-f=${Status}", "auditd"], capture_output=True, text=True)
        verified = True
        if r2.returncode == 0 and "install ok installed" in r2.stdout:
            return CheckResult("pass")
    except FileNotFoundError:
        pass
    try:
        r3 = subprocess.run(["rpm", "-q", "audit"], capture_output=True, text=True)
        verified = True
        if r3.returncode == 0:
            return CheckResult("pass")
    except FileNotFoundError:
        pass
    if not verified:
        return CheckResult("warn", "cannot verify auditd installation — no 'which' or package manager available")
    return CheckResult("fail", "auditd is not installed")


register(Control(
    id="4.1.1.1",
    title="Ensure auditd is installed",
    section="logging",
    check=_check_auditd_installed,
    fix=lambda: pkg.install("auditd"),
))


# ---- CIS 4.1.1.2: Ensure auditd service is enabled and running ----

def _check_auditd_running() -> CheckResult:
    try:
        if not _systemd_is_enabled("auditd"):
            return CheckResult("fail", "auditd is not enabled")
        if not _systemd_is_active("auditd"):
            return CheckResult("fail", "auditd is not active")
    except FileNotFoundError:
        return CheckResult("warn", "systemctl not found — cannot verify auditd service state")
    return CheckResult("pass")


def _fix_auditd_running() -> list[RollbackEntry]:
    """Enable and start auditd. Raise if either step fails so the harden
    engine surfaces the failure rather than silently returning a partial
    rollback set that the caller would treat as success."""
    entries = []
    r_enable = subprocess.run(["systemctl", "enable", "auditd"], capture_output=True, text=True)
    if r_enable.returncode == 0:
        entries.append(RollbackEntry(action="enabled auditd", undo=[["systemctl", "disable", "auditd"]]))
    else:
        raise RuntimeError(f"systemctl enable auditd failed: {r_enable.stderr.strip()}")
    r_start = subprocess.run(["systemctl", "start", "auditd"], capture_output=True, text=True)
    if r_start.returncode == 0:
        entries.append(RollbackEntry(action="started auditd", undo=[["systemctl", "stop", "auditd"]]))
    else:
        # On RHEL family, systemd intentionally refuses systemctl start auditd;
        # fall back to the legacy service command before raising.
        r_legacy = subprocess.run(["service", "auditd", "start"], capture_output=True, text=True)
        if r_legacy.returncode == 0:
            entries.append(RollbackEntry(action="started auditd via service", undo=[["service", "auditd", "stop"]]))
        else:
            raise RuntimeError(
                f"could not start auditd: systemctl rc={r_start.returncode} ({r_start.stderr.strip()}); "
                f"service rc={r_legacy.returncode} ({r_legacy.stderr.strip()})"
            )
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
    try:
        text = conf.read_text()
    except FileNotFoundError:
        return CheckResult("warn", "auditd.conf not found")
    except OSError as e:
        return CheckResult("warn", f"cannot read auditd.conf: {e}")
    for line in text.splitlines():
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


def _fix_audit_log_size() -> list[RollbackEntry]:
    """Set max_log_file = 32 (MB) in /etc/audit/auditd.conf and reload auditd.

    32MB is a conservative default well above the CIS minimum of 8MB;
    operators with specific retention needs can adjust manually.

    auditd reads its config only at startup, so a config-only write would
    leave the running daemon at the old value (cosmetic-pass class).
    `service auditd reload` (which sends SIGUSR1 — the canonical reload
    signal) picks up the new value without restarting the daemon. systemd
    intentionally refuses `systemctl restart auditd` on RHEL family, so we
    use the legacy service command which works on both Debian and RHEL.
    """
    conf = Path("/etc/audit/auditd.conf")
    if not conf.exists():
        # Silently returning [] would leave the harden engine reporting
        # "Applied: 1" while the post-fix audit still warns "auditd.conf
        # not found" — cosmetic-pass class. Refuse instead so the operator
        # sees a clear actionable error and the run summary counts it as
        # failed, not applied. 4.1.1.1 (`lss harden --control 4.1.1.1`)
        # installs auditd; running the full harden pass applies that
        # control before this one.
        raise RuntimeError(
            "auditd.conf not found at /etc/audit/auditd.conf — install auditd "
            "first. On Debian/Ubuntu/Kali: `sudo apt install auditd`. On "
            "RHEL/Fedora: `sudo dnf install audit`. Or run `sudo lss harden "
            "--confirm --control 4.1.1.1` to install it via LSS."
        )
    bkp = journal.backup_file(str(conf))
    lines = conf.read_text().splitlines(keepends=True)
    # Ensure last line ends with newline before potentially appending — a
    # hand-edited file without trailing newline would otherwise produce
    # `prev_linemax_log_file = 32\n` which auditd rejects on next startup.
    if lines and not lines[-1].endswith("\n"):
        lines[-1] = lines[-1] + "\n"
    found = False
    for i, line in enumerate(lines):
        if line.strip().startswith("max_log_file") and "max_log_file_action" not in line:
            lines[i] = "max_log_file = 32\n"
            found = True
            break
    if not found:
        lines.append("max_log_file = 32\n")
    conf.write_text("".join(lines))
    # Reload running daemon so the new value takes effect immediately.
    # Best-effort: log but don't fail the fix if reload is unavailable
    # (e.g., auditd not yet running). The check verifies file content,
    # which is correct for the persisted policy.
    subprocess.run(["service", "auditd", "reload"], capture_output=True)
    return [RollbackEntry(
        action="set auditd max_log_file = 32 MB and reloaded auditd",
        path=str(conf),
        backup=bkp,
        # On rollback the file is restored from backup; reload again so the
        # running daemon reverts to the prior value.
        undo=[["service", "auditd", "reload"]],
    )]


register(Control(
    id="4.1.1.3",
    title="Ensure audit log storage size is configured",
    section="logging",
    check=_check_audit_log_size,
    fix=_fix_audit_log_size,
))


# ---- CIS 4.1.1.4: Ensure audit logs are not automatically deleted ----

def _check_audit_log_retention() -> CheckResult:
    conf = Path("/etc/audit/auditd.conf")
    try:
        text = conf.read_text()
    except FileNotFoundError:
        return CheckResult("warn", "auditd.conf not found")
    except OSError as e:
        return CheckResult("warn", f"cannot read auditd.conf: {e}")
    for line in text.splitlines():
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
        raise RuntimeError(
            "auditd.conf not found at /etc/audit/auditd.conf — install auditd "
            "first. On Debian/Ubuntu/Kali: `sudo apt install auditd`. On "
            "RHEL/Fedora: `sudo dnf install audit`. Or run `sudo lss harden "
            "--confirm --control 4.1.1.1` to install it via LSS."
        )
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
    try:
        text = conf.read_text()
    except FileNotFoundError:
        return CheckResult("warn", "journald.conf not found")
    except OSError as e:
        return CheckResult("warn", f"cannot read journald.conf: {e}")
    for line in text.splitlines():
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

    # Create the directory. Track whether WE created it: journald treats the
    # mere existence of /var/log/journal as "persistent" (the check does too),
    # so if we leave the directory behind on rollback the change is not actually
    # reversed even after journald.conf is restored.
    journal_dir = Path("/var/log/journal")
    created_dir = not journal_dir.exists()
    journal_dir.mkdir(exist_ok=True)

    # Restart journald to pick up the change
    subprocess.run(["systemctl", "restart", "systemd-journald"], capture_output=True)

    # After the file is restored, rollback also needs to restart journald so the
    # previous setting takes effect again. If we created the directory, remove
    # it too — `rmdir` only removes an EMPTY directory, so it can never delete
    # logs journald has since written there (it just no-ops with an error we
    # surface, which is the safe outcome).
    undo: list[list[str]] = []
    if created_dir:
        undo.append(["rmdir", str(journal_dir)])
    undo.append(["systemctl", "restart", "systemd-journald"])

    return [RollbackEntry(
        action="set journald Storage=persistent",
        path=str(conf),
        backup=bkp,
        undo=undo,
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
    try:
        text = conf.read_text()
    except FileNotFoundError:
        return CheckResult("warn", "journald.conf not found")
    except OSError as e:
        return CheckResult("warn", f"cannot read journald.conf: {e}")
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Compress="):
            val = stripped.split("=")[1].strip().lower()
            if val == "yes":
                return CheckResult("pass")
            return CheckResult("fail", f"Compress={val}")
    # Default is yes in most distros
    return CheckResult("pass", "default is yes")


def _fix_journald_compress() -> list[RollbackEntry]:
    conf = Path("/etc/systemd/journald.conf")
    if not conf.exists():
        raise RuntimeError(
            "journald.conf not found at /etc/systemd/journald.conf — systemd is "
            "not installed or not the active init. journald is required for this "
            "control; nothing to harden on a non-systemd host."
        )
    bkp = journal.backup_file(str(conf))
    lines = conf.read_text().splitlines(keepends=True)
    found = False
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith("Compress=") or s.startswith("#Compress="):
            lines[i] = "Compress=yes\n"
            found = True
            break
    if not found:
        if lines and not lines[-1].endswith("\n"):
            lines.append("\n")
        lines.append("Compress=yes\n")
    conf.write_text("".join(lines))
    subprocess.run(["systemctl", "restart", "systemd-journald"], capture_output=True)
    return [RollbackEntry(
        action="set journald Compress=yes",
        path=str(conf),
        backup=bkp,
        undo=[["systemctl", "restart", "systemd-journald"]],
    )]


register(Control(
    id="4.2.1.2",
    title="Ensure journald is configured to compress large log files",
    section="logging",
    check=_check_journald_compress,
    fix=_fix_journald_compress,
))


# ---- CIS 4.2.2.1: Ensure rsyslog is installed ----

def _check_rsyslog() -> CheckResult:
    verified = False
    try:
        r = subprocess.run(["which", "rsyslogd"], capture_output=True, text=True)
        verified = True
        if r.returncode == 0:
            return CheckResult("pass")
    except FileNotFoundError:
        pass
    try:
        # -f=${Status}: plain `dpkg-query -W` prints only name/version, so the
        # "install ok installed" guard below could never match.
        r2 = subprocess.run(["dpkg-query", "-W", "-f=${Status}", "rsyslog"], capture_output=True, text=True)
        verified = True
        if r2.returncode == 0 and "install ok installed" in r2.stdout:
            return CheckResult("pass")
    except FileNotFoundError:
        pass
    try:
        r3 = subprocess.run(["rpm", "-q", "rsyslog"], capture_output=True, text=True)
        verified = True
        if r3.returncode == 0:
            return CheckResult("pass")
    except FileNotFoundError:
        pass
    if not verified:
        return CheckResult("warn", "cannot verify rsyslog installation — no 'which' or package manager available")
    return CheckResult("warn", "rsyslog not installed — journald may be sole log source")


register(Control(
    id="4.2.2.1",
    title="Ensure rsyslog is installed",
    section="logging",
    check=_check_rsyslog,
    fix=lambda: pkg.install("rsyslog"),
))
