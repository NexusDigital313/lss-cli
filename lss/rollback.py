# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file, 
# via any medium, is strictly prohibited without explicit written authorization.

"""Rollback engine — reverses hardening changes using the journal.

For each entry: if a backup exists, restore it (with mtime safety check);
then run any argv-list undo commands with shell=False. Never uses shell=True.
"""

from __future__ import annotations

import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from lss.lib import journal, syslog, sshd
from lss.lib.output import info, header, err, warn, GREEN, RED, YELLOW, DIM, RESET


def _restore_backup(control_id: str, backup: str, path: str,
                    run_epoch: float | None = None) -> tuple[bool, str]:
    """Restore `path` from `backup`. Returns (ok, message).

    Warns (but still restores) if the live file has been modified since the
    harden run that produced this journal — the operator should know they may
    be losing edits made after hardening. We compare against the RUN timestamp,
    not the backup's mtime: the backup preserves the original file's pre-harden
    mtime, so a backup-vs-live comparison would fire on every rollback (harden
    always rewrites the file). Comparing against the run time only flags files
    an operator (or another process) touched after LSS hardened them.
    """
    src = Path(backup)
    dst = Path(path)
    if not src.exists():
        return False, f"backup file missing: {backup}"

    if dst.exists() and run_epoch is not None:
        try:
            live_mtime = dst.stat().st_mtime
            if live_mtime > run_epoch + 1:  # 1s grace for FS resolution
                warn(f"  {control_id}   {path} was modified after the harden run — restoring anyway will overwrite those changes")
        except OSError:
            pass

    shutil.copy2(src, dst)
    return True, f"restored {path} from backup"


def _run_undo(control_id: str, argv: list[str]) -> tuple[bool, str]:
    """Run a single argv list with shell=False. Returns (ok, message)."""
    if not argv or not isinstance(argv, list):
        return False, f"malformed undo (expected argv list, got {type(argv).__name__})"
    try:
        subprocess.run(
            argv,
            shell=False,
            check=True,
            capture_output=True,
            text=True,
        )
        return True, " ".join(argv)
    except FileNotFoundError:
        return False, f"command not found: {argv[0]}"
    except subprocess.CalledProcessError as exc:
        msg = (exc.stderr or "").strip().splitlines()[-1] if exc.stderr else f"exit {exc.returncode}"
        return False, f"{' '.join(argv)} → {msg}"


def run_rollback(args) -> int:
    """Undo a previous harden run."""
    run_id = None
    if args.last:
        runs = journal.list_runs()
        if not runs:
            err("no harden runs found in journal")
            return 1
        run_id = runs[0]
    elif args.run_id:
        run_id = args.run_id

    run_data = journal.read_run(run_id)
    if not run_data:
        err(f"journal not found or unreadable for run: {run_id}")
        return 1

    # Tolerate a journal missing optional metadata rather than KeyError-ing.
    resolved_run_id = run_data.get("run_id", run_id or "unknown")
    timestamp = run_data.get("timestamp", "unknown")

    # Reference time for the "modified after harden" guard in _restore_backup.
    run_epoch: float | None = None
    if timestamp != "unknown":
        try:
            run_epoch = datetime.fromisoformat(timestamp).timestamp()
        except (ValueError, TypeError):
            run_epoch = None

    info(f"Rolling back run: {resolved_run_id}  ({timestamp})")
    syslog.info(
        f"rollback start run_id={resolved_run_id} "
        f"target={'control:' + args.control if args.control else 'all'}"
    )

    controls = run_data.get("controls", {})

    if args.control:
        if args.control not in controls:
            err(f"control {args.control} not found in run {resolved_run_id}")
            return 1
        controls = {args.control: controls[args.control]}

    header("Rollback")

    errors = 0
    sshd_touched = False
    # Iterate controls in reverse application order so that when multiple
    # controls modified the same file, the LAST control's undo runs first.
    # If the OUTER loop runs forward, an early control's `rm -f` deletes
    # the file before later controls' "restore from backup" recreate it
    # with their stale post-edit state — leaving the file partially
    # hardened. See rollback regression test for the multi-control case.
    for control_id, entries in reversed(list(controls.items())):
        for entry in reversed(entries):  # reverse order for safe undo
            action = entry.get("action", "")
            backup = entry.get("backup", "") or ""
            path = entry.get("path", "") or ""
            undo = entry.get("undo", []) or []

            # Tolerate legacy string-form undos by skipping (not executing) them
            # and warning the operator. We never run shell=True commands, even
            # for old journals — that's the entire point of this refactor.
            skipped_legacy = False
            if isinstance(undo, str):
                warn(f"  {control_id}   skipping legacy shell-string undo: {undo!r}")
                undo = []
                skipped_legacy = True

            did_something = False

            # 1. Restore from backup if available
            if backup and path:
                ok, msg = _restore_backup(control_id, backup, path, run_epoch)
                if ok:
                    print(f"{GREEN}  ✓{RESET} {control_id}   {msg}")
                    did_something = True
                else:
                    err(f"  {control_id}   {msg}")
                    errors += 1

            # 2. Run undo argv lists in order
            for argv in undo:
                ok, msg = _run_undo(control_id, argv)
                if ok:
                    print(f"{GREEN}  ✓{RESET} {control_id}   {action} {DIM}({msg}){RESET}")
                    did_something = True
                else:
                    err(f"  {control_id}   undo failed: {msg}")
                    errors += 1

            if not did_something and action:
                # An entry we recorded but could NOT reverse (no backup, no
                # runnable undo, or only a skipped legacy shell-string) means
                # this change is still in force. Count it as an error so the
                # final status and exit code don't claim a full rollback that
                # didn't happen — the whole point of the journal is honesty
                # about what was and wasn't undone.
                if skipped_legacy:
                    err(f"  {control_id}   NOT reversed — legacy shell-string undo cannot be run safely: {action}")
                else:
                    err(f"  {control_id}   NOT reversed — no backup or undo recorded for: {action}")
                errors += 1

            # An SSH config file was reverted on disk, but the RUNNING sshd
            # still holds the hardened settings until it is reloaded. Harden
            # reloads on apply; rollback must too, or the revert looks done
            # while the live daemon keeps enforcing the old rules.
            if path.startswith("/etc/ssh"):
                sshd_touched = True

    if sshd_touched:
        if sshd.reload_sshd():
            info("reloaded sshd so the reverted SSH config is live on the running daemon")
        else:
            warn("reverted SSH config on disk but could not reload sshd — "
                 "run from the console: sudo systemctl reload ssh")

    print()
    if errors:
        err(f"rollback completed with {errors} error(s) — some changes were NOT reversed (see above)")
        syslog.err(f"rollback complete run_id={resolved_run_id} errors={errors}")
    else:
        info("rollback complete — all changes reversed")
        syslog.info(f"rollback complete run_id={resolved_run_id} errors=0")

    return errors
