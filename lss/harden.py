"""Harden engine — applies fixes for failing controls and records rollback entries."""

from __future__ import annotations

from lss.lib import distro, journal, syslog
from lss.lib.output import info, header, err, warn, print_result, print_summary, DIM, RESET, GREEN, YELLOW
from lss.lib.registry import get_controls, CheckResult, RollbackEntry

# Controls in this list disable services that a customer may be actively using
# in production (mail server, web server, etc.). When the operator runs
# `lss harden --confirm` we surface a clear warning before any of these run, so
# nobody loses their production email server to an unattended hardening pass.
DESTRUCTIVE_SERVICE_CONTROLS = {
    "2.2.3":  "CUPS (printing)",
    "2.2.6":  "NFS server",
    "2.2.7":  "DNS server (bind9)",
    "2.2.8":  "FTP server (vsftpd)",
    "2.2.9":  "HTTP server (apache2)",
    "2.2.10": "IMAP/POP3 (dovecot)",
    "2.2.11": "Samba",
    "2.2.12": "HTTP proxy (squid)",
    "2.2.13": "SNMP",
    "2.2.14": "NIS server",
    "2.2.15": "Postfix MTA",
    "2.2.16": "rsync service",
}

# Import control modules
import lss.controls.filesystem        # noqa: F401
import lss.controls.filesystem_perms  # noqa: F401
import lss.controls.file_perms        # noqa: F401
import lss.controls.mounts            # noqa: F401
import lss.controls.kernel            # noqa: F401
import lss.controls.network           # noqa: F401
import lss.controls.firewall          # noqa: F401
import lss.controls.services          # noqa: F401
import lss.controls.ssh               # noqa: F401
import lss.controls.auth              # noqa: F401
import lss.controls.pam               # noqa: F401
import lss.controls.logging           # noqa: F401
import lss.controls.audit_rules       # noqa: F401
import lss.controls.cron              # noqa: F401
import lss.controls.banners           # noqa: F401
import lss.controls.boot              # noqa: F401
import lss.controls.gdm               # noqa: F401
import lss.controls.users             # noqa: F401
import lss.controls.misc              # noqa: F401
import lss.controls.extras            # noqa: F401


def run_harden(args) -> int:
    """Run failing controls' fix functions, record rollback journal."""
    host = distro.detect()
    dry_run = bool(getattr(args, "dry_run", False))

    info(f"Host:   {host.name}    Kernel: {host.kernel}")
    if dry_run:
        info("Mode:   dry-run — no changes will be made")
    else:
        info("Mode:   harden — changes WILL be applied")

    controls = get_controls(ids=args.control if args.control else None)

    # Pre-flight warning for destructive service-disabling controls. The
    # operator may be actively using these services (mail server, web server,
    # etc.); running harden unattended could break production. We list them up
    # front so the operator can ctrl-C or use --control to skip.
    selected_destructive = [
        (ctrl.id, DESTRUCTIVE_SERVICE_CONTROLS[ctrl.id])
        for ctrl in controls
        if ctrl.id in DESTRUCTIVE_SERVICE_CONTROLS and ctrl.fix is not None
    ]
    if selected_destructive and not dry_run:
        warn("The following controls disable services that may be in production use:")
        for cid, label in selected_destructive:
            warn(f"    {cid}  {label}")
        warn("Skip individual controls with --control, or run with --dry-run first.")
        print()

    run_id = journal.new_run_id()
    info(f"Run ID: {run_id}")

    # Make the run_id available to control fixes that need to back up files
    if not dry_run:
        journal.set_current_run_id(run_id)
        ctl = ",".join(args.control) if args.control else "all"
        syslog.info(f"harden start run_id={run_id} controls={ctl}")

    header("Dry-run plan" if dry_run else "Hardening")

    journal_entries: dict[str, list[dict]] = {}
    applied = skipped = failed = would_fix = 0

    for ctrl in controls:
        if ctrl.check is None or ctrl.fix is None:
            continue

        # Check first — only fix what's broken
        try:
            result = ctrl.check()
        except Exception as exc:
            print_result(ctrl.id, ctrl.title, "fail", f"check error: {exc}")
            failed += 1
            continue

        if result.status == "pass":
            print_result(ctrl.id, ctrl.title, "pass", "already compliant")
            skipped += 1
            continue

        if dry_run:
            print(
                f"{YELLOW}  ?{RESET} {ctrl.id}   {ctrl.title}   "
                f"{DIM}(would fix — {result.detail or result.status}){RESET}"
            )
            would_fix += 1
            continue

        # Apply the fix
        try:
            rollback_entries = ctrl.fix()
            journal_entries[ctrl.id] = [
                {"action": e.action, "undo": e.undo, "path": e.path, "backup": e.backup}
                for e in rollback_entries
            ]

            verify = ctrl.check()
            if verify.status == "pass":
                print(
                    f"{GREEN}  ✓{RESET} {ctrl.id}   {ctrl.title}   "
                    f"{DIM}(fixed → pass){RESET}"
                )
                syslog.info(f"harden fix run_id={run_id} control={ctrl.id} status=fixed")
                applied += 1
            else:
                print(
                    f"{YELLOW}  !{RESET} {ctrl.id}   {ctrl.title}   "
                    f"{DIM}(fix applied but still {verify.status}: {verify.detail}){RESET}"
                )
                syslog.warn(
                    f"harden fix run_id={run_id} control={ctrl.id} "
                    f"status=applied-but-{verify.status} detail={verify.detail!r}"
                )
                applied += 1

        except Exception as exc:
            print_result(ctrl.id, ctrl.title, "fail", f"fix error: {exc}")
            syslog.err(f"harden fix run_id={run_id} control={ctrl.id} error={exc!r}")
            failed += 1

    if dry_run:
        print()
        info(f"Would fix: {would_fix}   Skipped (already pass): {skipped}   Check errors: {failed}")
        info("Re-run with --confirm to apply.")
        return 0

    # Always write the journal, even when no changes were made — this gives
    # `lss rollback --last` a stable meaning (an empty run is a no-op, not a
    # missing-journal error).
    jpath = journal.write_run(run_id, journal_entries)
    journal.set_current_run_id(None)

    print()
    info(f"Applied: {applied}   Skipped (already pass): {skipped}   Failed: {failed}")
    syslog.info(
        f"harden complete run_id={run_id} applied={applied} "
        f"skipped={skipped} failed={failed}"
    )
    if journal_entries:
        info(f"Rollback journal: {jpath}")
        info("To undo:  sudo lss rollback --last")
    else:
        info("Nothing to harden — all controls already passed.")

    return failed
