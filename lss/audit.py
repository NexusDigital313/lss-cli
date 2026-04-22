"""Audit engine — runs all registered controls in read-only mode."""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from lss import __version__
from lss.lib import distro
from lss.lib.output import (
    console, info, header, rule, heavy_rule, section_header,
    print_result, print_summary, print_banner_art, print_host_info,
    print_fails_table, print_warns_table,
    DIM, RESET, BOLD, CYAN,
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
    uptime = _get_uptime()
    json_mode = bool(getattr(args, "json", False))

    # In --json mode, suppress all decorative rich output so the JSON on stdout
    # is parseable. Status messages still go to stderr.
    if not json_mode:
        print_banner_art()

    controls = get_controls(ids=args.control if args.control else None)
    if not json_mode:
        print_host_info(host.name, _hostname(), host.kernel, uptime, len(controls))

    results: list[dict] = []
    passes = warns = fails = skips = 0
    current_section = ""
    seen_sections: set[str] = set()

    for ctrl in controls:
        if ctrl.check is None:
            continue

        if not json_mode and ctrl.section != current_section:
            current_section = ctrl.section
            if current_section not in seen_sections:
                seen_sections.add(current_section)
                section_header(current_section)

        try:
            r: CheckResult = ctrl.check()
        except Exception as exc:
            r = CheckResult(status="fail", detail=f"check error: {exc}")

        if not json_mode:
            print_result(ctrl.id, ctrl.title, r.status, r.detail)

        results.append({
            "id": ctrl.id,
            "title": ctrl.title,
            "section": ctrl.section,
            "level": ctrl.level,
            "status": r.status,
            "detail": r.detail,
        })

        if r.status == "pass":
            passes += 1
        elif r.status == "warn":
            warns += 1
        elif r.status == "skip":
            skips += 1
        else:
            fails += 1

    if not json_mode:
        print_summary(passes, warns, fails, skips)
        print_fails_table(results)
        print_warns_table(results)

    # Always persist results — `lss report` reads them
    _save_results(results, host, passes, warns, fails, skips, json_mode=json_mode)

    if not json_mode and fails > 0:
        console.print(
            "  [grey50]Apply remediations now?  Run:[/]  "
            "[bold bright_cyan]sudo lss harden --confirm[/]"
        )
        console.print()

    if json_mode:
        applicable = passes + warns + fails
        print(json.dumps({"controls": results, "summary": {
            "pass": passes, "warn": warns, "fail": fails, "skip": skips,
            "total": len(results),
            "score": round(passes / applicable * 100) if applicable else 0,
        }}, indent=2))

    return fails


def _hostname() -> str:
    import socket
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"


def _save_results(results: list[dict], host, passes: int, warns: int, fails: int, skips: int = 0, json_mode: bool = False):
    """Write audit results to disk for report generation."""
    import os
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    total = passes + warns + fails + skips
    applicable = passes + warns + fails
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
            "skip": skips,
            "total": total,
            "score": round(passes / applicable * 100) if applicable else 0,
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

    if not json_mode:
        console.print(f"  [grey50]Report data:[/]  [grey70]{out}[/]")
        console.print("  [grey50]HTML report:[/]  [bold]sudo lss report[/]")
        console.print()
