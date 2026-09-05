# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized reproduction, copying, modification, distribution,
# redistribution, publication, reverse engineering, decompilation, or
# disassembly of this file, in whole or in part, via any medium, is
# strictly prohibited without explicit prior written authorization.

"""Harden engine — applies fixes for failing controls and records rollback entries."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from lss.lib import distro, journal, syslog
from lss.lib.output import info, header, err, warn, print_result, print_summary, DIM, RESET, GREEN, YELLOW
from lss.lib.registry import get_controls, CheckResult, RollbackEntry


def _save_partial_journal(run_id: str, journal_entries: dict) -> None:
    """Write whatever rollback entries we have on abort/interrupt.

    Tries the normal journal path first. If that raises (disk full,
    permission denied, missing parent dir), falls back to an emergency
    dump under /tmp/ so the operator can recover the rollback record
    rather than losing it silently.
    """
    if not journal_entries:
        return
    try:
        jpath = journal.write_run(run_id, journal_entries)
        info(f"Partial run journaled at: {jpath}")
    except Exception as exc:
        fallback = Path(f"/tmp/lss-emergency-journal-{os.getpid()}-{run_id}.json")
        try:
            fallback.write_text(json.dumps(journal_entries, default=str, indent=2))
            err(f"Failed to write journal ({exc}). Emergency dump at {fallback}. "
                f"Manual rollback will require this file.")
        except Exception as exc2:
            err(f"Failed to write journal AND emergency dump: {exc2}. "
                f"Applied changes have NO rollback record.")

# Controls in this list disable a service or network path a customer may be
# actively depending on (mail server, web server, remote connectivity, etc.).
# When the operator runs `lss harden --confirm` we surface a clear warning
# before any of these run, so nobody loses a production service — or their
# remote session — to an unattended hardening pass.
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
    # Forces inet_interfaces=loopback-only. A host relaying outbound mail for
    # other local applications (a common multi-purpose setup) loses external
    # delivery — it is not merely "the MTA stops listening".
    "2.2.15": "Postfix / MTA (local-only mode cuts off outbound mail relay)",
    "2.2.16": "rsync service",
    # Not a service — a connectivity risk. Disabling IPv6 router-advertisement
    # acceptance drops the box's IPv6 default route on a SLAAC-configured host,
    # which can cut off an IPv6-only admin session mid-run.
    "3.3.9":  "IPv6 router advertisements (may drop the IPv6 default route on SLAAC hosts)",
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
    interactive = bool(getattr(args, "interactive", False))

    if interactive and dry_run:
        # --interactive and --dry-run mean different things; refuse rather
        # than silently disabling one. The operator should choose: --dry-run
        # to preview the plan, or --interactive to approve each fix as it
        # would actually run.
        err("--interactive and --dry-run are mutually exclusive. "
            "Use --dry-run to preview the plan, or --interactive to approve "
            "fixes one by one as they apply.")
        return 2

    if interactive and not (sys.stdin.isatty() and sys.stdout.isatty()):
        err("--interactive requires a TTY on both stdin and stdout. "
            "Either run lss harden in a terminal, or drop --interactive.")
        return 1

    info(f"Host:   {host.name}    Kernel: {host.kernel}")
    if dry_run:
        info("Mode:   dry-run — no changes will be made")
    elif interactive:
        info("Mode:   interactive harden — you will be prompted before each fix")
    else:
        info("Mode:   harden — changes WILL be applied")

    controls = get_controls(ids=args.control if args.control else None)

    # A typo'd or unknown --control ID selects zero matching controls. Without
    # this guard the run would sail through the loop doing nothing and report
    # "all controls already passed" with exit 0 — telling the operator a
    # control they explicitly asked about is compliant when it was never even
    # evaluated. Fail loudly instead.
    if args.control:
        known = {c.id for c in controls}
        unknown = [cid for cid in args.control if cid not in known]
        if unknown:
            err(f"unknown control ID(s): {', '.join(unknown)}. "
                f"Run `lss list` to see valid control IDs.")
            return 2

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
        warn("The following controls disable a service or network path that may be in production use:")
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
    applied = skipped = failed = would_fix = declined = not_verified = 0
    manual_remaining = 0
    aborted = False

    for ctrl in controls:
        if ctrl.check is None or ctrl.fix is None:
            continue

        # Check first — only fix what's broken
        try:
            result = ctrl.check()
        except KeyboardInterrupt:
            aborted = True
            break
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

        # Interactive prompt — show context, ask y/N. Default is N (skip),
        # so an accidental Enter on a live box doesn't apply a fix.
        if interactive:
            print()
            print(f"{YELLOW}  ?{RESET} {ctrl.id}   {ctrl.title}")
            print(f"{DIM}    Current: {result.detail or result.status}{RESET}")
            if ctrl.id in DESTRUCTIVE_SERVICE_CONTROLS:
                warn(f"    NOTE: this fix affects {DESTRUCTIVE_SERVICE_CONTROLS[ctrl.id]} — "
                     "may break a service or connectivity in production use.")
            try:
                response = input("    Apply fix? [y/N] ").strip().lower()
            except EOFError:
                # stdin closed mid-prompt — treat as abort, not silent decline.
                # If we kept going, every subsequent prompt would also EOFError
                # and the run would silently "decline" all remaining controls
                # with exit 0, which is exactly the silent-non-enforcement
                # class we're trying to prevent.
                print()
                err("stdin closed mid-prompt — aborting interactive run. "
                    "No further controls will be processed.")
                _save_partial_journal(run_id, journal_entries)
                journal.set_current_run_id(None)
                return 1
            except KeyboardInterrupt:
                print()
                err("Aborted by operator (Ctrl-C). No further controls will be processed.")
                _save_partial_journal(run_id, journal_entries)
                journal.set_current_run_id(None)
                return 130  # 128 + SIGINT
            if response not in ("y", "yes"):
                print(f"{DIM}    skipped (operator declined){RESET}")
                declined += 1
                continue

        # Apply the fix
        try:
            rollback_entries = ctrl.fix()
            journal_entries[ctrl.id] = [
                {"action": e.action, "undo": e.undo, "path": e.path, "backup": e.backup}
                for e in rollback_entries
            ]
            # Flush the journal incrementally so a hard kill (SIGKILL / OOM /
            # power loss) part-way through a run still leaves a rollback record
            # for every change applied so far — the in-memory dict alone would
            # be lost. Best-effort: a flush failure must not abort the run, and
            # the authoritative write_run() still runs at the end.
            try:
                journal.write_run(run_id, journal_entries)
            except Exception:
                pass

            verify = ctrl.check()
            if verify.status == "pass":
                print(
                    f"{GREEN}  ✓{RESET} {ctrl.id}   {ctrl.title}   "
                    f"{DIM}(fixed → pass){RESET}"
                )
                syslog.info(f"harden fix run_id={run_id} control={ctrl.id} status=fixed")
                applied += 1
            elif verify.status == "manual":
                # The automatable half is done and the remainder is operator
                # action BY DESIGN (e.g. 5.3.1 writes the pwquality values but
                # cannot wire pam_pwquality.so into the PAM stack; 5.3.2 the
                # same for pam_faillock). That is not a failed fix, and `lss
                # audit` already excludes manual controls from its exit code —
                # counting it as not-verified here inflated the count and the
                # exit code for hosts whose automatable settings were correct.
                print(
                    f"{YELLOW}  !{RESET} {ctrl.id}   {ctrl.title}   "
                    f"{DIM}(fix applied; operator action still required: {verify.detail}){RESET}"
                )
                syslog.warn(
                    f"harden fix run_id={run_id} control={ctrl.id} "
                    f"status=applied-manual-remaining detail={verify.detail!r}"
                )
                manual_remaining += 1
            else:
                print(
                    f"{YELLOW}  !{RESET} {ctrl.id}   {ctrl.title}   "
                    f"{DIM}(fix applied but still {verify.status}: {verify.detail}){RESET}"
                )
                syslog.warn(
                    f"harden fix run_id={run_id} control={ctrl.id} "
                    f"status=applied-but-{verify.status} detail={verify.detail!r}"
                )
                # The fix ran without raising but the control is STILL not
                # compliant (e.g. an sshd directive shadowed by a lower-numbered
                # drop-in, or a setting not honored). This must not read as
                # success: count it separately and fold it into the exit code so
                # `lss harden --confirm` in CI can't return 0 while the box is
                # left non-compliant. The change is still journaled above, so
                # rollback works.
                not_verified += 1

        except KeyboardInterrupt:
            # Ctrl-C mid-fix in a non-interactive --confirm run. The control
            # whose fix was interrupted may be half-applied AND its rollback
            # entries are lost — fix() returns its RollbackEntry list only when
            # it completes, so an interrupt before `return` leaves any on-disk
            # change it already made with NO journal entry. Name the control
            # explicitly so the operator knows to inspect it by hand; everything
            # before it is journaled (incremental flush above).
            print()
            warn(f"Interrupted while applying {ctrl.id} ({ctrl.title}). "
                 f"This control may have partially-applied changes that are NOT "
                 f"in the rollback journal — inspect it manually. All controls "
                 f"completed before it are journaled and can be rolled back.")
            syslog.warn(f"harden interrupted-mid-fix run_id={run_id} control={ctrl.id}")
            aborted = True
            break
        except Exception as exc:
            print_result(ctrl.id, ctrl.title, "fail", f"fix error: {exc}")
            syslog.err(f"harden fix run_id={run_id} control={ctrl.id} error={exc!r}")
            failed += 1

    if dry_run:
        print()
        info(f"Would fix: {would_fix}   Skipped (already pass): {skipped}   Check errors: {failed}")
        info("Re-run with --confirm to apply.")
        return 0

    # Interactive summary appended below the standard one.
    interactive_note = f"   Declined: {declined}" if interactive else ""

    if aborted:
        print()
        err("Aborted by operator (Ctrl-C) — writing the rollback journal for "
            "changes applied so far. Undo with: sudo lss rollback --last")

    # Always write the journal, even when no changes were made — this gives
    # `lss rollback --last` a stable meaning (an empty run is a no-op, not a
    # missing-journal error).
    jpath = journal.write_run(run_id, journal_entries)
    journal.set_current_run_id(None)

    print()
    not_verified_note = f"   Applied-but-still-failing: {not_verified}" if not_verified else ""
    manual_note = f"   Needs operator action: {manual_remaining}" if manual_remaining else ""
    info(f"Applied: {applied}   Skipped (already pass): {skipped}   Failed: {failed}{not_verified_note}{manual_note}{interactive_note}")
    if manual_remaining:
        warn(f"{manual_remaining} control(s) had their automatable part applied but "
             f"still need a manual step (see the detail above). These do NOT count "
             f"toward the exit code, matching how `lss audit` reports manual controls.")
    if not_verified:
        warn(f"{not_verified} control(s) had a fix applied but did NOT reach a "
             f"passing state — the host is not fully compliant. Re-run `lss audit` "
             f"and review those controls.")
    syslog.info(
        f"harden complete run_id={run_id} applied={applied} "
        f"skipped={skipped} failed={failed} not_verified={not_verified} "
        f"manual_remaining={manual_remaining}"
    )
    if journal_entries:
        info(f"Rollback journal: {jpath}")
        info("To undo:  sudo lss rollback --last")
    elif failed or not_verified:
        info("No changes applied — the failing controls above could not be fixed automatically.")
    else:
        info("Nothing to harden — all controls already passed.")

    if aborted:
        return 130  # 128 + SIGINT
    # A fix that ran but left the control non-compliant counts toward the
    # failure exit code — otherwise automation reads exit 0 as full success.
    return failed + not_verified
