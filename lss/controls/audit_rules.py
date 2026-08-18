# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file, 
# via any medium, is strictly prohibited without explicit written authorization.

"""CIS Section 4.1 — Audit rules."""

from __future__ import annotations

import shlex
import subprocess
from pathlib import Path

from lss.lib import journal
from lss.lib.registry import Control, CheckResult, RollbackEntry, register

# Legacy shared file — kept for the immutable-flag control's path and for
# rollback of pre-1.0.2 journals. New rule writes go to a per-control file (see
# _rules_path_for) so rolling back one audit control can't restore a stale
# whole-file snapshot and silently delete another control's rules.
LSS_AUDIT_RULES = "/etc/audit/rules.d/80-lss.rules"


def _rules_path_for(control_id: str) -> str:
    """Per-control audit rules file, e.g. 4.1.3 -> 80-lss-4-1-3.rules."""
    safe = control_id.replace(".", "-")
    return f"/etc/audit/rules.d/80-lss-{safe}.rules"


def _rule_is_active(pattern: str) -> bool:
    """Check if an audit rule matching the pattern is loaded."""
    try:
        r = subprocess.run(["auditctl", "-l"], capture_output=True, text=True)
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                if pattern in line:
                    return True
    except FileNotFoundError:
        pass
    return False


def _rule_is_persisted(pattern: str) -> bool:
    """Check if rule exists in /etc/audit/rules.d/."""
    rules_dir = Path("/etc/audit/rules.d")
    try:
        if not rules_dir.exists():
            return False
        rule_files = list(rules_dir.glob("*.rules"))
    except OSError:
        return False
    for f in rule_files:
        try:
            contents = f.read_text()
        except OSError:
            # File vanished mid-scan or is unreadable — skip it rather than
            # crash the whole audit. A missing/unreadable file can't prove the
            # rule is persisted, so treat it as not found here.
            continue
        for line in contents.splitlines():
            if pattern in line:
                return True
    return False


def _delete_argv_for(rule_argv: list[str]) -> list[str] | None:
    """Build the `auditctl -d`/`-W` argv that deletes a rule produced by
    `auditctl -a`/`-w`. Returns None if the rule shape is unrecognized.
    """
    if not rule_argv:
        return None
    head = rule_argv[0]
    rest = rule_argv[1:]
    if head in ("-a", "-A"):
        return ["auditctl", "-d", *rest]
    if head == "-w":
        # -w <path> -p <perms> -k <key>  →  -W <path> -p <perms> -k <key>
        return ["auditctl", "-W", *rest]
    return None


def _add_audit_rule(rule: str, control_id: str) -> RollbackEntry:
    """Add an audit rule to runtime and persist it to this control's own file.

    Splits the rule with shlex (no shell), runs `auditctl <args>` with
    shell=False, and records an argv-form delete for rollback. The persisted
    rules file is per-control and backed up before modification so rollback
    restores it without touching any other control's rules.
    """
    rule_argv = shlex.split(rule)
    p = Path(_rules_path_for(control_id))
    p.parent.mkdir(parents=True, exist_ok=True)
    bkp = journal.backup_file(str(p))

    # Runtime
    subprocess.run(["auditctl", *rule_argv], capture_output=True)

    # Persist
    existing = p.read_text() if p.exists() else "# LSS audit rules\n"
    if rule not in existing:
        p.write_text(existing + rule + "\n")

    delete_argv = _delete_argv_for(rule_argv)
    undo: list[list[str]] = []
    if delete_argv:
        undo.append(delete_argv)

    return RollbackEntry(
        action=f"added audit rule: {rule}",
        path=str(p),
        backup=bkp,
        undo=undo,
    )


# ---- Audit rule definitions ----
# Each entry: (control_id, title, check_pattern, rules_to_add)

_AUDIT_CONTROLS = [
    (
        "4.1.3",
        "Ensure events that modify date and time information are collected",
        "time-change",
        [
            "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change",
            "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change",
            "-a always,exit -F arch=b64 -S clock_settime -k time-change",
            "-w /etc/localtime -p wa -k time-change",
        ],
    ),
    (
        "4.1.4",
        "Ensure events that modify user/group information are collected",
        "identity",
        [
            "-w /etc/group -p wa -k identity",
            "-w /etc/passwd -p wa -k identity",
            "-w /etc/gshadow -p wa -k identity",
            "-w /etc/shadow -p wa -k identity",
            "-w /etc/security/opasswd -p wa -k identity",
        ],
    ),
    (
        "4.1.5",
        "Ensure events that modify the system's network environment are collected",
        "system-locale",
        [
            "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale",
            "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale",
            "-w /etc/issue -p wa -k system-locale",
            "-w /etc/issue.net -p wa -k system-locale",
            "-w /etc/hosts -p wa -k system-locale",
            "-w /etc/hostname -p wa -k system-locale",
        ],
    ),
    (
        "4.1.6",
        "Ensure events that modify the system's Mandatory Access Controls are collected",
        "MAC-policy",
        [
            "-w /etc/apparmor/ -p wa -k MAC-policy",
            "-w /etc/apparmor.d/ -p wa -k MAC-policy",
        ],
    ),
    (
        "4.1.7",
        "Ensure login and logout events are collected",
        "logins",
        [
            "-w /var/log/faillog -p wa -k logins",
            "-w /var/log/lastlog -p wa -k logins",
            "-w /var/log/tallylog -p wa -k logins",
        ],
    ),
    (
        "4.1.8",
        "Ensure session initiation information is collected",
        "session",
        [
            "-w /var/run/utmp -p wa -k session",
            "-w /var/log/wtmp -p wa -k session",
            "-w /var/log/btmp -p wa -k session",
        ],
    ),
    (
        "4.1.9",
        "Ensure discretionary access control permission modification events are collected",
        "perm_mod",
        [
            "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod",
            "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod",
            "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod",
            "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod",
            "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod",
            "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod",
        ],
    ),
    (
        "4.1.10",
        "Ensure unsuccessful unauthorized file access attempts are collected",
        "access",
        [
            "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access",
            "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access",
            "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access",
            "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access",
        ],
    ),
    (
        "4.1.11",
        "Ensure file deletion events by users are collected",
        "delete",
        [
            "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete",
            "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete",
        ],
    ),
    (
        "4.1.12",
        "Ensure changes to system administration scope (sudoers) are collected",
        "scope",
        [
            "-w /etc/sudoers -p wa -k scope",
            "-w /etc/sudoers.d/ -p wa -k scope",
        ],
    ),
    (
        "4.1.13",
        "Ensure system administrator command executions (sudo) are collected",
        "actions",
        [
            "-a always,exit -F arch=b64 -C euid!=uid -F euid=0 -S execve -k actions",
        ],
    ),
    (
        "4.1.14",
        "Ensure kernel module loading and unloading is collected",
        "modules",
        [
            "-w /sbin/insmod -p x -k modules",
            "-w /sbin/rmmod -p x -k modules",
            "-w /sbin/modprobe -p x -k modules",
            "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules",
            "-a always,exit -F arch=b32 -S init_module -S delete_module -k modules",
        ],
    ),
    (
        "4.1.15",
        "Ensure file system mounts are collected",
        "mounts",
        [
            "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts",
            "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts",
        ],
    ),
]


for _id, _title, _pattern, _rules in _AUDIT_CONTROLS:
    pattern, rules, cid = _pattern, _rules, _id

    def _make_check(pat):
        def check():
            if _rule_is_active(pat):
                return CheckResult("pass")
            if _rule_is_persisted(pat):
                return CheckResult("warn", "rule persisted but not loaded — restart auditd")
            return CheckResult("fail", f"no audit rules for {pat}")
        return check

    def _make_fix(rs, cid):
        def fix():
            return [_add_audit_rule(r, cid) for r in rs]
        return fix

    register(Control(
        id=_id,
        title=_title,
        section="logging",
        check=_make_check(pattern),
        fix=_make_fix(rules, cid),
    ))


# ---- CIS 4.1.16: Ensure the audit configuration is immutable ----

def _check_audit_immutable() -> CheckResult:
    if _rule_is_active("-e 2"):
        return CheckResult("pass")
    if _rule_is_persisted("-e 2"):
        return CheckResult("warn", "immutable flag persisted but not active — reboot required")
    return CheckResult(
        "manual",
        "audit config not immutable — add `-e 2` as the LAST line of "
        "/etc/audit/rules.d/*.rules by hand, then reboot. Apply it last: once "
        "active, the audit config cannot be changed again without a reboot, so "
        "LSS cannot auto-undo it.",
    )


def _fix_audit_immutable() -> list[RollbackEntry]:
    p = Path(LSS_AUDIT_RULES)
    p.parent.mkdir(parents=True, exist_ok=True)
    bkp = journal.backup_file(str(p))
    existing = p.read_text() if p.exists() else ""
    if "-e 2" not in existing:
        # Must be the LAST rule
        new_text = existing
        if new_text and not new_text.endswith("\n"):
            new_text += "\n"
        new_text += "\n# Make audit configuration immutable (requires reboot to change)\n-e 2\n"
        p.write_text(new_text)
    return [RollbackEntry(
        action="set audit configuration immutable (-e 2)",
        path=str(p),
        backup=bkp,
        # NOTE: -e 2 makes auditd immutable until next reboot. Rolling back
        # the file is fine, but the runtime kernel state still says immutable.
        # The operator needs to reboot for the file change to take effect.
    )]


register(Control(
    id="4.1.16",
    title="Ensure the audit configuration is immutable",
    section="logging",
    check=_check_audit_immutable,
    fix=None,  # DEFANGED: -e 2 is irreversible until reboot and can block other audit fixes; apply by hand, last.
))