"""CIS Section 1.1 — Separate partitions and mount options."""

from __future__ import annotations

import subprocess

from lss.lib.registry import Control, CheckResult, RollbackEntry, register


def _is_separate_mount(path: str) -> bool:
    """Check if a path is a separate mount point."""
    r = subprocess.run(["findmnt", "-n", path], capture_output=True, text=True)
    return r.returncode == 0 and path in r.stdout


def _get_mount_options(path: str) -> set[str]:
    r = subprocess.run(["findmnt", "-n", "-o", "OPTIONS", path], capture_output=True, text=True)
    if r.returncode == 0 and r.stdout.strip():
        return set(r.stdout.strip().split(","))
    return set()


# ---- Separate partition checks ----

_PARTITION_CHECKS = [
    ("1.1.2", "Ensure /tmp is configured", "/tmp"),
    ("1.1.3", "Ensure /var is configured", "/var"),
    ("1.1.4", "Ensure /var/tmp is configured", "/var/tmp"),
    ("1.1.5", "Ensure /var/log is configured", "/var/log"),
    ("1.1.6", "Ensure /var/log/audit is configured", "/var/log/audit"),
    ("1.1.7", "Ensure /home is configured", "/home"),
]

for _id, _title, _path in _PARTITION_CHECKS:
    path = _path

    def _make_check(p):
        def check():
            if _is_separate_mount(p):
                return CheckResult("pass")
            return CheckResult("warn", f"{p} is not a separate partition")
        return check

    register(Control(
        id=_id,
        title=_title,
        section="filesystem",
        check=_make_check(path),
        fix=None,  # Requires repartitioning — cannot auto-fix
    ))


# ---- Mount option checks ----

_MOUNT_OPTION_CHECKS = [
    ("1.1.10", "Ensure noexec option set on /var/tmp", "/var/tmp", ["noexec", "nosuid", "nodev"]),
    ("1.1.11", "Ensure nodev option set on /var/tmp", "/var/tmp", ["nodev"]),
    ("1.1.12", "Ensure nosuid option set on /var/tmp", "/var/tmp", ["nosuid"]),
    ("1.1.13", "Ensure nodev option set on /home", "/home", ["nodev"]),
    ("1.1.14", "Ensure nosuid option set on /home", "/home", ["nosuid"]),
]

for _id, _title, _path, _opts in _MOUNT_OPTION_CHECKS:
    path, opts = _path, _opts

    def _make_check(p, required_opts):
        def check():
            if not _is_separate_mount(p):
                return CheckResult("warn", f"{p} is not a separate mount")
            current = _get_mount_options(p)
            missing = [o for o in required_opts if o not in current]
            if not missing:
                return CheckResult("pass")
            return CheckResult("fail", f"{p} missing: {','.join(missing)}")
        return check

    def _make_fix(p, required_opts):
        def fix():
            if not _is_separate_mount(p):
                return []
            current = _get_mount_options(p)
            # Capture the previous option set so rollback can restore exactly
            # what was there before — don't strip unrelated mount flags like
            # relatime, errors=continue, etc.
            previous_opts = ",".join(sorted(current)) if current else "defaults"
            merged = current.union(required_opts)
            opt_str = ",".join(sorted(merged))
            subprocess.run(
                ["mount", "-o", f"remount,{opt_str}", p],
                capture_output=True, check=True,
            )
            return [RollbackEntry(
                action=f"remounted {p} with {','.join(required_opts)} (preserved existing options)",
                undo=[["mount", "-o", f"remount,{previous_opts}", p]],
            )]
        return fix

    register(Control(
        id=_id,
        title=_title,
        section="filesystem",
        check=_make_check(path, opts),
        fix=_make_fix(path, opts),
    ))