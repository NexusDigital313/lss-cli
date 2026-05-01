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


def _fix_crypto_policy() -> list[RollbackEntry]:
    """On RHEL family, set crypto policy to DEFAULT if currently LEGACY.

    On Debian family, set openssl MinProtocol = TLSv1.2 in /etc/ssl/openssl.cnf.
    No-op if neither config source is available (check returns skip).
    """
    rhel_conf = Path("/etc/crypto-policies/config")
    if rhel_conf.exists():
        prev = rhel_conf.read_text().strip()
        r = subprocess.run(
            ["update-crypto-policies", "--set", "DEFAULT"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            raise RuntimeError(f"update-crypto-policies failed: {r.stderr.strip()}")
        return [RollbackEntry(
            action=f"set crypto policy to DEFAULT (was {prev})",
            undo=[["update-crypto-policies", "--set", prev]],
        )]

    ssl_conf = Path("/etc/ssl/openssl.cnf")
    if ssl_conf.exists():
        bkp = journal.backup_file(str(ssl_conf))
        text = ssl_conf.read_text()
        if "MinProtocol" in text:
            import re
            text = re.sub(r"MinProtocol\s*=\s*\S+", "MinProtocol = TLSv1.2", text)
        else:
            text = text.rstrip() + "\n\n[system_default_sect]\nMinProtocol = TLSv1.2\n"
        ssl_conf.write_text(text)
        return [RollbackEntry(
            action="set openssl MinProtocol = TLSv1.2",
            path=str(ssl_conf),
            backup=bkp,
        )]

    return []


register(Control(
    id="LSS-001",
    title="Ensure system-wide crypto policy is not legacy",
    section="kernel",
    check=_check_crypto_policy,
    fix=_fix_crypto_policy,
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


def _fix_ipv6_forwarding() -> list[RollbackEntry]:
    from lss.lib.sysctl import set_sysctl, get_sysctl
    # If IPv6 is disabled the check already passes — no-op.
    if get_sysctl("net.ipv6.conf.all.disable_ipv6") == "1":
        return []
    return [set_sysctl("net.ipv6.conf.all.forwarding", "0")]


register(Control(
    id="3.2.1",
    title="Ensure IPv6 forwarding is disabled",
    section="network",
    check=_check_ipv6_forwarding,
    fix=_fix_ipv6_forwarding,
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


def _fix_securetty() -> list[RollbackEntry]:
    """Trim /etc/securetty to the CIS-minimal set (console, tty1).

    Only trims — never creates the file. If /etc/securetty does not exist,
    PAM already controls access (check passes) so no-op.
    """
    p = Path("/etc/securetty")
    if not p.exists():
        return []
    bkp = journal.backup_file(str(p))
    p.write_text("console\ntty1\n")
    return [RollbackEntry(
        action="trimmed /etc/securetty to CIS-minimal (console, tty1)",
        path=str(p),
        backup=bkp,
    )]


register(Control(
    id="LSS-002",
    title="Ensure root login is restricted to system console",
    section="auth",
    check=_check_securetty,
    fix=_fix_securetty,
))


# ---- CIS 4.2.3: Ensure permissions on all logfiles are configured ----

def _world_accessible_logs() -> list[str]:
    """Return paths of files in /var/log (top level) with any world bits set."""
    import os, stat
    hits = []
    try:
        entries = os.listdir("/var/log")
    except (OSError, PermissionError):
        return hits
    for name in entries:
        fp = os.path.join("/var/log", name)
        try:
            st = os.stat(fp)
        except (OSError, PermissionError):
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        if stat.S_IMODE(st.st_mode) & 0o007:
            hits.append(fp)
    return hits


def _check_log_permissions() -> CheckResult:
    hits = _world_accessible_logs()
    if not hits:
        return CheckResult("pass")
    return CheckResult("warn", f"{len(hits)} log files in /var/log are world-accessible")


def _fix_log_permissions() -> list[RollbackEntry]:
    """Strip world bits from world-accessible files in /var/log top level.

    Records each file's pre-change mode so rollback restores exactly, without
    forcing a blanket 0640 on files that originally had stricter permissions.
    """
    import os, stat
    entries: list[RollbackEntry] = []
    for fp in _world_accessible_logs():
        try:
            st = os.stat(fp)
        except (OSError, PermissionError):
            continue
        prev_mode = stat.S_IMODE(st.st_mode)
        new_mode = prev_mode & ~0o007
        try:
            os.chmod(fp, new_mode)
        except (OSError, PermissionError):
            continue
        entries.append(RollbackEntry(
            action=f"stripped world bits from {fp} ({oct(prev_mode)} -> {oct(new_mode)})",
            undo=[["chmod", oct(prev_mode)[2:].zfill(4), fp]],
        ))
    return entries


register(Control(
    id="4.2.3",
    title="Ensure permissions on all logfiles are configured",
    section="logging",
    check=_check_log_permissions,
    fix=_fix_log_permissions,
))


# ---- CIS 2.4: Ensure nonessential services listening are removed ----

def _check_listening_services() -> CheckResult:
    r = subprocess.run(["ss", "-H", "-tlnp"], capture_output=True, text=True)
    lines = [l for l in r.stdout.splitlines() if l.strip()]
    if not lines:
        return CheckResult("pass", "no TCP services listening")
    ports = set()
    for line in lines:
        cols = line.split()
        if len(cols) >= 4:
            addr = cols[3]
            port = addr.rsplit(":", 1)[-1]
            if port.isdigit():
                ports.add(port)
    sample = ",".join(sorted(ports, key=int)[:6])
    more = "…" if len(ports) > 6 else ""
    return CheckResult(
        "warn",
        f"{len(lines)} listening TCP service(s) on port(s) {sample}{more} — review with `ss -tlnp` and remove/mask any that aren't required",
    )


register(Control(
    id="2.4",
    title="Ensure nonessential services are removed or masked",
    section="services",
    check=_check_listening_services,
    fix=None,
))


# ---- CIS 6.2.16: Ensure no users have .bash_profile that sources untrusted paths ----

_PATH_ASSIGN_RE = None  # lazy-compiled


def _path_line_is_unsafe(line: str) -> bool:
    """A PATH= assignment line is unsafe if it injects '.' or an empty component.

    Empty component (PATH=:/usr/bin or PATH=/usr/bin:) silently means '.' to
    most shells. We extract the assigned value, strip surrounding quotes and
    a leading 'export ', then split on ':' and look for '.' / '' components.
    Comment lines and prose containing 'PATH=' as a substring are ignored.
    """
    import re
    global _PATH_ASSIGN_RE
    if _PATH_ASSIGN_RE is None:
        _PATH_ASSIGN_RE = re.compile(r"^\s*(?:export\s+)?PATH=([^\s#]+)")
    stripped = line.lstrip()
    if stripped.startswith("#"):
        return False
    m = _PATH_ASSIGN_RE.match(line)
    if not m:
        return False
    val = m.group(1).strip()
    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
        val = val[1:-1]
    parts = val.split(":")
    for p in parts:
        if p == "." or p == "":
            return True
    return False


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
                try:
                    if not fp.exists():
                        continue
                    text = fp.read_text()
                except (PermissionError, OSError):
                    continue
                for ln in text.splitlines():
                    if _path_line_is_unsafe(ln):
                        issues.append(f"{user}:{dotfile}")
                        break
    if not issues:
        return CheckResult("pass")
    return CheckResult("warn", f"dot files with potential PATH issues: {', '.join(issues[:3])}")


def _fix_dot_files_safe() -> list[RollbackEntry]:
    """Comment out unsafe PATH= lines in real users' shell dotfiles.

    Matches the same heuristic as the check: a line containing `PATH=` with
    either `.:` (current directory) or `: ` (empty component). The whole
    offending line gets prefixed with `# [LSS-DISABLED]`, never deleted,
    so the operator can review it and the file's overall content survives.
    """
    passwd = Path("/etc/passwd")
    if not passwd.exists():
        return []
    entries: list[RollbackEntry] = []
    for line in passwd.read_text().splitlines():
        parts = line.split(":")
        if len(parts) < 6:
            continue
        user, _x, uid_str = parts[0], parts[1], parts[2]
        home = parts[5]
        try:
            uid = int(uid_str)
        except ValueError:
            continue
        if uid < 1000 and user != "root":
            continue
        for dotfile in [".bash_profile", ".bashrc", ".profile"]:
            fp = Path(home) / dotfile
            if not fp.exists():
                continue
            try:
                text = fp.read_text()
            except PermissionError:
                continue
            lines = text.splitlines(keepends=True)
            if not any(_path_line_is_unsafe(ln) for ln in lines):
                continue
            bkp = journal.backup_file(str(fp))
            changed = False
            for i, ln in enumerate(lines):
                if _path_line_is_unsafe(ln):
                    lines[i] = f"# [LSS-DISABLED] {ln}"
                    changed = True
            if not changed:
                continue
            fp.write_text("".join(lines))
            entries.append(RollbackEntry(
                action=f"commented unsafe PATH line(s) in {fp}",
                path=str(fp),
                backup=bkp,
            ))
    return entries


register(Control(
    id="LSS-003",
    title="Ensure no users' dot files have unsafe PATH entries",
    section="users",
    check=_check_dot_files_safe,
    fix=_fix_dot_files_safe,
))


# ---- CIS 5.4.5: Ensure default user shell timeout is configured ----

def _check_shell_timeout() -> CheckResult:
    """Look for a non-commented TMOUT=<seconds> assignment in any file a login
    shell would actually source: /etc/profile, /etc/bashrc, /etc/bash.bashrc,
    and every /etc/profile.d/*.sh file (which login shells source in lexical
    order). The fix writes /etc/profile.d/80-lss-timeout.sh, so the audit must
    scan that directory or it cosmetic-fails its own fix."""
    import re
    files: list[Path] = [
        Path("/etc/profile"),
        Path("/etc/bashrc"),
        Path("/etc/bash.bashrc"),
    ]
    profile_d = Path("/etc/profile.d")
    if profile_d.is_dir():
        files.extend(sorted(profile_d.glob("*.sh")))
    # Anchor to start-of-line and disallow `#` before TMOUT so a commented-out
    # assignment doesn't masquerade as a real one (cosmetic-pass class).
    pattern = re.compile(r"^[^#\n]*\bTMOUT=(\d+)", re.MULTILINE)
    for p in files:
        if not p.exists():
            continue
        m = pattern.search(p.read_text())
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
    import re
    p = Path("/proc/cmdline")
    if p.exists():
        text = p.read_text()
        m = re.search(r"audit_backlog_limit=(\d+)", text)
        if m and int(m.group(1)) >= 8192:
            return CheckResult("pass")
        if m:
            return CheckResult(
                "warn",
                f"audit_backlog_limit={m.group(1)}, recommended: >= 8192. "
                f"Edit GRUB_CMDLINE_LINUX in /etc/default/grub, then run update-grub and reboot.",
            )
    return CheckResult(
        "warn",
        "audit_backlog_limit not set in /proc/cmdline. Add audit_backlog_limit=8192 to "
        "GRUB_CMDLINE_LINUX in /etc/default/grub, then run update-grub and reboot.",
    )


register(Control(
    id="4.1.2",
    title="Ensure audit backlog limit is sufficient",
    section="logging",
    check=_check_audit_backlog,
    fix=None,  # Intentionally manual: bad GRUB edits brick hosts; rollback can't reach a host that won't boot.
))


# ---- LSS-004: AppArmor service condition-skip on Live+persistence boots ----
#
# Debian's /usr/lib/systemd/system/apparmor.service ships with the condition
# `ConditionPathExists=!/run/live/overlay/work`. On a normal install /run/live
# does not exist and the condition is satisfied (service starts). On a Debian
# Live boot (or Kali Live, which derives from it) the path exists and the
# condition fails — the service is skipped, no profiles enforce, and no
# AppArmor confinement applies even though the kernel module is loaded and
# the profiles are present on disk.
#
# This still bites on Live boots with persistence enabled, where the customer
# expects a "real" install experience. It's invisible to standard CIS scanners
# because aa-status reports "module is loaded" and the kernel parameter is
# correct — only checking the systemd ConditionResult exposes the gap.
#
# Detection pairs the Live+persistence indicator with ConditionResult=no on
# apparmor.service. Remediation is a one-line systemd drop-in that wipes the
# inherited condition.

def _is_live_persistence() -> bool:
    """True if booted from Debian/Kali Live media with a persistence overlay."""
    cmdline = Path("/proc/cmdline")
    if not cmdline.exists() or "boot=live" not in cmdline.read_text():
        return False
    persistence_dir = Path("/run/live/persistence")
    if not persistence_dir.exists():
        return False
    try:
        return any(persistence_dir.iterdir())
    except (OSError, PermissionError):
        return False


def _apparmor_service_condition_skipped() -> bool:
    """True if apparmor.service is loaded but skipped by a unit Condition.

    Returns False if the service is not loaded at all (different problem,
    handled by 1.6.1) or if the condition is satisfied (service runs).
    """
    r = subprocess.run(
        ["systemctl", "show", "apparmor.service",
         "--property=LoadState", "--property=ConditionResult"],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        return False
    out = r.stdout
    if "LoadState=loaded" not in out:
        return False
    return "ConditionResult=no" in out


def _check_apparmor_live_condition() -> CheckResult:
    if not _is_live_persistence():
        return CheckResult("skip", "not a Debian/Kali Live + persistence system")
    if not _apparmor_service_condition_skipped():
        return CheckResult("pass", "apparmor.service condition is satisfied")
    return CheckResult(
        "fail",
        "apparmor.service is condition-skipped on this Live+persistence host. "
        "Debian's unit file has `ConditionPathExists=!/run/live/overlay/work` "
        "which prevents the service from starting whenever the Live overlay is "
        "in use — even with persistence configured. No profiles are enforcing "
        "as a result. Remediate by writing a systemd drop-in that empties the "
        "condition: `sudo install -d /etc/systemd/system/apparmor.service.d && "
        "printf '[Unit]\\nConditionPathExists=\\n' | sudo tee "
        "/etc/systemd/system/apparmor.service.d/override.conf >/dev/null && "
        "sudo systemctl daemon-reload && sudo systemctl enable --now apparmor.service`.",
    )


register(Control(
    id="LSS-004",
    title="Ensure apparmor.service is not condition-skipped on Live+persistence boots",
    section="kernel",
    check=_check_apparmor_live_condition,
    fix=None,  # Audit-only in v1.0; auto-fix planned for a future release after testing across Live distros.
))


# ---- LSS-005: Forensic-grade user execve auditing (beyond CIS 4.1.13) ----
#
# CIS 4.1.13 specifies a narrow execve audit rule that fires only on
# privilege-transition execves (effective UID becomes 0 while real UID
# differs) — covering sudo, su, pkexec, and setuid-root binaries. That
# answers "what got root" but is silent on what a user runs as themselves
# before, after, or alongside privilege use.
#
# Forensic responders typically want broader coverage: every execve performed
# by a real user (auid >= 1000). LSS-005 detects whether any such rule is
# active and surfaces a remediation if not.
#
# This is intentionally audit-only. The broader rule produces audit log
# volume proportional to user shell activity — tens to hundreds of MB per
# day on an interactive host — and should be enabled deliberately, with the
# operator's audit log rotation policy reviewed first.

_LSS005_RULES = [
    "-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=4294967295 -k user-exec",
    "-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=4294967295 -k user-exec",
]


def _check_forensic_execve() -> CheckResult:
    """Pass when an active execve rule scoped to real users (auid>=1000) exists.

    Operators using a different key than `user-exec` still satisfy the
    requirement; the check looks for the syscall + auid filter combination,
    not a specific key name.
    """
    r = subprocess.run(["auditctl", "-l"], capture_output=True, text=True)
    if r.returncode != 0:
        return CheckResult("warn", "auditctl unavailable — cannot inspect loaded rules")
    for line in r.stdout.splitlines():
        if "-S execve" in line and "auid>=1000" in line:
            return CheckResult("pass", "broader user-execve audit rule active")
    return CheckResult(
        "manual",
        "no broader user-execve audit rule active. CIS 4.1.13 captures only "
        "privilege-transition execves (sudo/su/pkexec/setuid). For forensic "
        "coverage of every command run as a real user, add to "
        "/etc/audit/rules.d/: "
        f"`{_LSS005_RULES[0]}` and `{_LSS005_RULES[1]}`, then `augenrules --load`. "
        "Volume warning: this rule can produce hundreds of MB of audit logs "
        "per day on an interactive host — review your audit log rotation "
        "(/etc/audit/auditd.conf max_log_file, num_logs) before enabling."
    )


register(Control(
    id="LSS-005",
    title="Forensic-grade user execve auditing (beyond CIS 4.1.13)",
    section="logging",
    check=_check_forensic_execve,
    fix=None,  # Audit-only by design — log-volume impact requires operator opt-in.
))
