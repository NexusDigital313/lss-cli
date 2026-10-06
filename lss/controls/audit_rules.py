# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file, 
# via any medium, is strictly prohibited without explicit written authorization.

"""CIS Section 4.1 — Audit rules."""

from __future__ import annotations

import os
import re
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

# Directory augenrules assembles the persistent rule set from. A module
# constant so tests can redirect it.
AUDIT_RULES_DIR = "/etc/audit/rules.d"


def _rules_path_for(control_id: str) -> str:
    """Per-control audit rules file, e.g. 4.1.3 -> 80-lss-4-1-3.rules."""
    safe = control_id.replace(".", "-")
    return f"/etc/audit/rules.d/80-lss-{safe}.rules"


def _line_has_rule(line: str, pattern: str) -> bool:
    """True if this audit rule line carries `pattern`.

    A bare key (e.g. "access") must appear as the rule's key. `auditctl -l`
    prints a syscall rule's key as `-F key=<k>` and a watch rule's as
    `-k <k>`, unquoted (a quoted value is tolerated); rules files may use
    either form. The old `pattern in line` substring test let an unrelated
    rule satisfy a control — generic keys like access/delete/actions matched
    a watched path (`-w /etc/security/access.conf ... -k identity` passed
    4.1.10), a syscall name (`-S delete_module` passed 4.1.11), or a longer
    key (`unauthorized-access`, `privileged-actions`), a false pass.

    Non-key patterns such as the `-e 2` immutable flag keep the plain
    substring match.
    """
    if pattern and not pattern.startswith("-") and not re.search(r"\s", pattern):
        return re.search(rf'(?:-k\s+|key=)"?{re.escape(pattern)}(?![\w-])', line) is not None
    return pattern in line


def _rule_is_active(pattern: str) -> bool:
    """Check if an audit rule matching the pattern is loaded."""
    try:
        r = subprocess.run(["auditctl", "-l"], capture_output=True, text=True)
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                if _line_has_rule(line, pattern):
                    return True
    except FileNotFoundError:
        pass
    return False


def _rule_is_persisted(pattern: str) -> bool:
    """Check if rule exists in /etc/audit/rules.d/. A commented-out rule is
    not persisted, so comment lines never count."""
    rules_dir = Path(AUDIT_RULES_DIR)
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
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if _line_has_rule(s, pattern):
                return True
    return False


def _loaded_rule_lines() -> list[str] | None:
    """`auditctl -l` output lines, or None when the loaded rules can't be read."""
    try:
        r = subprocess.run(["auditctl", "-l"], capture_output=True, text=True)
    except (FileNotFoundError, OSError):
        return None
    if r.returncode != 0:
        return None
    return r.stdout.splitlines()


def _persisted_rule_lines() -> list[str]:
    """Every line augenrules would read from rules.d/*.rules. Unreadable files
    contribute nothing, so they can never prove a rule is persisted."""
    lines: list[str] = []
    try:
        files = sorted(Path(AUDIT_RULES_DIR).glob("*.rules"))
    except OSError:
        return lines
    for f in files:
        try:
            lines.extend(f.read_text().splitlines())
        except OSError:
            continue
    return lines


# `-F arch=` spellings auditctl accepts, folded to b64/b32.
_ARCH_ALIASES = {
    "x86_64": "b64", "aarch64": "b64", "ppc64": "b64", "ppc64le": "b64", "s390x": "b64",
    "i386": "b32", "i686": "b32", "arm": "b32", "armeb": "b32", "ppc": "b32", "s390": "b32",
}
_B32_COMPAT = {"x86_64": "i386", "aarch64": "arm", "ppc64": "ppc", "ppc64le": "ppc", "s390x": "s390"}


def _machine() -> str:
    return os.uname().machine


def _parse_rule(line: str) -> dict | None:
    """Parse an audit rule line (rules-file or `auditctl -l` form) into what it
    collects. Returns None for comments, control lines (-D, -b, -e ...) and
    rules that do not record exit events (`-a never,exit`, other lists)."""
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    try:
        toks = shlex.split(s)
    except ValueError:
        toks = s.split()
    rule = {"keys": set(), "path": None, "perms": None, "arch": None,
            "syscalls": set(), "exit": None, "kind": None}
    it = iter(toks)
    for flag in it:
        val = next(it, "")
        if flag == "-w":
            rule["kind"], rule["path"] = "watch", val
        elif flag == "-p":
            rule["perms"] = set(val)
        elif flag == "-k":
            rule["keys"].add(val)
        elif flag in ("-a", "-A"):
            parts = set(val.split(","))
            if parts != {"always", "exit"}:
                return None
            rule["kind"] = "syscall"
        elif flag == "-S":
            rule["syscalls"].update(x for x in val.split(",") if x)
        elif flag == "-F":
            m = re.match(r"(\w+)(=|!=|>=|<=|>|<|&=|&)(.*)$", val)
            if not m or m.group(2) != "=":
                continue
            name, v = m.group(1), m.group(3).strip('"')
            if name == "key":
                rule["keys"].add(v)
            elif name == "arch":
                rule["arch"] = _ARCH_ALIASES.get(v, v)
            elif name == "exit":
                rule["exit"] = v
            elif name in ("path", "dir"):
                rule["path"] = v
            elif name == "perm":
                rule["perms"] = set(v)
    if rule["kind"] is None:
        return None
    if rule["path"] is not None:
        p = rule["path"].rstrip("/") or "/"
        if p.startswith("/var/run/"):
            p = p[len("/var"):]  # /var/run is a symlink to /run
        rule["path"] = p
        if rule["perms"] is None:
            rule["perms"] = set("rwxa")
    if rule["kind"] == "syscall" and not rule["syscalls"] and rule["path"] is None:
        rule["syscalls"] = {"all"}
    return rule


def _syscall_unknown(arch: str, name: str, cache: dict) -> bool:
    """True if this kernel has no syscall `name` for `arch` (b64/b32), so a
    rule cannot name it — e.g. `open` on aarch64, or any b64 rule on a 32-bit
    host. Anything ausyscall can't positively call unknown stays required."""
    if (arch, name) in cache:
        return cache[(arch, name)]
    m = _machine()
    if m in _B32_COMPAT:
        table = m if arch == "b64" else _B32_COMPAT[m]
    elif arch == "b64":
        cache[(arch, name)] = True  # 32-bit kernel: no b64 syscalls at all
        return True
    else:
        table = "i386" if re.fullmatch(r"i[3-6]86", m) else ("arm" if m.startswith("arm") else m)
    try:
        r = subprocess.run(["ausyscall", table, name, "--exact"], capture_output=True, text=True)
        unknown = r.returncode != 0 and "unknown syscall" in (r.stdout + r.stderr).lower()
    except (FileNotFoundError, OSError):
        unknown = False
    cache[(arch, name)] = unknown
    return unknown


def _missing_rules(required: list[str], key: str, lines: list[str], cache: dict) -> list[str]:
    """The required rules that `lines` do not collect under `key`.

    A watch is covered by a rule on the same path with at least its
    permissions; a syscall rule by rules of the same arch (and exit filter)
    that together name every syscall this kernel has. Extra filters such as
    auid are not compared.
    """
    have = [r for r in map(_parse_rule, lines) if r and key in r["keys"]]
    if not have:
        return list(required)
    missing = []
    for text in required:
        want = _parse_rule(text)
        if want["kind"] == "watch":
            ok = any(h["path"] == want["path"] and want["perms"] <= (h["perms"] or set())
                     for h in have)
        else:
            named: set[str] = set()
            for h in have:
                if (h["kind"] == "syscall" and h["arch"] == want["arch"]
                        and h["exit"] in (None, want["exit"])):
                    named |= h["syscalls"]
            ok = "all" in named or all(
                s in named or _syscall_unknown(want["arch"], s, cache)
                for s in want["syscalls"])
        if not ok:
            missing.append(text)
    return missing


def _summarize(rules: list[str]) -> str:
    shown = "; ".join(rules[:3])
    return shown + (f"; +{len(rules) - 3} more" if len(rules) > 3 else "")


def _check_rule_set(key: str, required: list[str]) -> CheckResult:
    """CIS checks both the on-disk (rules.d) and the running (`auditctl -l`)
    configuration, and every rule of the control in each."""
    cache: dict = {}
    loaded = _loaded_rule_lines()
    loaded_missing = _missing_rules(required, key, loaded or [], cache)
    persisted_missing = _missing_rules(required, key, _persisted_rule_lines(), cache)
    if not loaded_missing and not persisted_missing:
        return CheckResult("pass")
    if not persisted_missing:
        if loaded is None:
            return CheckResult("warn", "rule persisted but loaded rules unreadable (auditctl -l failed)")
        return CheckResult("warn", "rule persisted but not loaded — restart auditd")
    if not loaded_missing:
        return CheckResult(
            "fail",
            f"{key} rules loaded but not persisted in {AUDIT_RULES_DIR} — augenrules drops "
            f"them when auditd restarts; missing: {_summarize(persisted_missing)}",
        )
    if len(persisted_missing) == len(required) and len(loaded_missing) == len(required):
        return CheckResult("fail", f"no audit rules for {key}")
    return CheckResult("fail", f"incomplete {key} audit rules; missing: {_summarize(persisted_missing)}")


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
    # Compare whole uncommented lines: a commented-out copy is not persisted.
    if rule not in {ln.strip() for ln in existing.splitlines()}:
        if not existing.endswith("\n"):
            existing += "\n"
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

    def _make_check(pat, rs):
        def check():
            return _check_rule_set(pat, rs)
        return check

    def _make_fix(rs, cid):
        def fix():
            return [_add_audit_rule(r, cid) for r in rs]
        return fix

    register(Control(
        id=_id,
        title=_title,
        section="logging",
        check=_make_check(pattern, rules),
        fix=_make_fix(rules, cid),
    ))


# ---- CIS 4.1.16: Ensure the audit configuration is immutable ----

def _audit_enabled_flag() -> int | None:
    """The kernel audit `enabled` flag from `auditctl -s` — 0 off, 1 on,
    2 immutable — or None when it can't be read.

    `auditctl -l` lists loaded rules but never prints the `-e` flag, so the
    immutable state is only visible in the status report. Reading it from `-l`
    (as this control used to) meant 4.1.16 could never pass at runtime."""
    try:
        r = subprocess.run(["auditctl", "-s"], capture_output=True, text=True)
    except (FileNotFoundError, OSError):
        return None
    if r.returncode != 0:
        return None
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "enabled":
            try:
                return int(parts[1])
            except ValueError:
                return None
    return None


def _check_audit_immutable() -> CheckResult:
    if _audit_enabled_flag() == 2:
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