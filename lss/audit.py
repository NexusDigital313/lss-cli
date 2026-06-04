"""Audit engine — runs all registered controls in read-only mode."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from lss import __version__
from lss.lib import distro
from lss.lib.output import (
    console, print_summary, print_banner_art, print_fails_table,
    print_manuals_table, print_section_breakdown, print_next_steps,
    audit_progress,
)
from lss.lib.registry import get_controls, CheckResult

# Import control modules so they register themselves
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

# Persist last audit results so `lss report` can read them
RESULTS_DIR = Path("/var/log/lss")


def _get_uptime() -> str:
    """Get system uptime as a human-readable string."""
    try:
        with open("/proc/uptime") as f:
            seconds = float(f.read().split()[0])
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        if days > 0:
            return f"{days}d {hours}h"
        if hours > 0:
            return f"{hours}h {int((seconds % 3600) // 60)}m"
        return f"{int(seconds // 60)}m"
    except Exception:
        return "unknown"


def run_audit(args) -> int:
    """Execute audit and return exit code (number of failures)."""
    host = distro.detect()
    json_mode = bool(getattr(args, "json", False))

    # In --json mode, suppress all decorative rich output so the JSON on stdout
    # stays parseable.
    if not json_mode:
        print_banner_art()

    controls = get_controls(ids=args.control if args.control else None)
    checkable = [c for c in controls if c.check is not None]

    results: list[dict] = []
    counts = {"pass": 0, "warn": 0, "fail": 0, "manual": 0, "skip": 0}

    def _check(ctrl):
        try:
            r: CheckResult = ctrl.check()
        except Exception as exc:
            r = CheckResult(status="fail", detail=f"check error: {exc}")
        results.append({
            "id": ctrl.id, "title": ctrl.title, "section": ctrl.section,
            "level": ctrl.level, "status": r.status, "detail": r.detail,
        })
        counts[r.status if r.status in counts else "fail"] += 1

    # Live progress while scanning (TTY only) — the "watch it work" beat.
    # Non-TTY / --json: run the checks silently, no decorative output.
    if not json_mode and console.is_terminal:
        with audit_progress() as progress:
            task = progress.add_task("audit", total=len(checkable), cur="")
            for ctrl in checkable:
                progress.update(task, cur=f"{ctrl.id}  {ctrl.title[:36]}")
                _check(ctrl)
                progress.update(task, advance=1)
    else:
        for ctrl in checkable:
            _check(ctrl)

    passes, warns, fails = counts["pass"], counts["warn"], counts["fail"]
    manuals, skips = counts["manual"], counts["skip"]

    # Persist results (+ HTML); returns the report URI for the NEXT block.
    report_uri = _save_results(results, host, passes, warns, fails, skips,
                               manuals=manuals, json_mode=json_mode, args=args)

    if not json_mode:
        print_summary(passes, warns, fails, skips, manuals=manuals,
                      host_label=host.name, hostname=_hostname())
        print_section_breakdown(results)
        print_fails_table(results)
        print_manuals_table(results)
        print_next_steps(fails, manuals, report_uri=report_uri or "")

    if json_mode:
        # Hardened score: passes / (pass+warn+fail) — what LSS finished
        # Compliance score: passes / (pass+warn+fail+manual) — full posture
        hardened_applicable = passes + warns + fails
        compliance_applicable = passes + warns + fails + manuals
        print(json.dumps({"controls": results, "summary": {
            "pass": passes, "warn": warns, "fail": fails,
            "manual": manuals, "skip": skips,
            "total": len(results),
            "score": round(passes / hardened_applicable * 100) if hardened_applicable else 0,
            "compliance_score": round(passes / compliance_applicable * 100) if compliance_applicable else 0,
        }}, indent=2))

    return fails


def _hostname() -> str:
    import socket
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"


def _save_results(results: list[dict], host, passes: int, warns: int, fails: int, skips: int = 0, manuals: int = 0, json_mode: bool = False, args=None):
    """Write audit results to disk for report generation."""
    import os
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    total = passes + warns + fails + skips + manuals
    hardened_applicable = passes + warns + fails
    compliance_applicable = passes + warns + fails + manuals
    data = {
        "timestamp": ts,
        "host": {
            "name": host.name,
            "id": host.id,
            "family": host.family,
            "version": host.version,
            "kernel": host.kernel,
        },
        "summary": {
            "pass": passes,
            "warn": warns,
            "fail": fails,
            "manual": manuals,
            "skip": skips,
            "total": total,
            "score": round(passes / hardened_applicable * 100) if hardened_applicable else 0,
            "compliance_score": round(passes / compliance_applicable * 100) if compliance_applicable else 0,
        },
        "controls": results,
    }

    out = RESULTS_DIR / f"audit-{ts}.json"
    out.write_text(json.dumps(data, indent=2))

    # Atomic latest-symlink swap (avoids the unlink→symlink race window)
    latest = RESULTS_DIR / "audit-latest.json"
    tmp_link = RESULTS_DIR / "audit-latest.json.new"
    if tmp_link.exists() or tmp_link.is_symlink():
        tmp_link.unlink()
    tmp_link.symlink_to(out.name)
    os.replace(tmp_link, latest)

    # Auto-emit HTML report alongside the JSON (customers shouldn't have to
    # run a second command just to view results in a browser). Honors
    # --no-report on the audit subcommand for JSON-only / scripted use.
    # --json implies --no-report: scripted/CI consumers want stdout JSON, not
    # an unrelated HTML side-effect on disk.
    report_uri = ""
    html_path = None
    skip_html = json_mode or bool(
        args is not None and getattr(args, "no_report", False)
    )
    if not skip_html:
        try:
            from lss.report import write_html_report
            from lss.lib.paths import file_uri
            html_path = write_html_report(data)
            report_uri = file_uri(html_path)
        except Exception as exc:
            if not json_mode:
                console.print(f"  [yellow]Could not generate HTML report:[/] {exc}")

    if html_path is not None and args is not None and getattr(args, "open", False):
        from lss.lib.paths import open_in_browser
        if not open_in_browser(html_path):
            if not json_mode:
                console.print("  [yellow]Could not launch a browser; open the URL above manually.[/]")

    return report_uri
