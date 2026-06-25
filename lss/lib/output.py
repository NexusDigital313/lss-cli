"""Rich terminal output for the Linux Security Suite."""

import os
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich.text import Text
from rich.columns import Columns
from rich.rule import Rule
from rich.align import Align
from rich.layout import Layout
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich import box

# Global console — shared everywhere
console = Console(highlight=False)
err_console = Console(highlight=False, file=sys.stderr)

# Legacy color vars (used by cli.py help-all and other places)
_use_color = console.is_terminal
RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""
DIM = BOLD = UNDERLINE = RESET = ""
BG_RED = BG_GREEN = BG_YELLOW = BG_BLUE = ""
_DEEP_BLUE = _MED_BLUE = _SKY_BLUE = _BRIGHT_CYAN = ""
_ORANGE = _AMBER = _CORAL = _MINT = _SOFT_GREEN = _LAVENDER = _PINK = ""
_GRAY = _LIGHT_GRAY = ""
_BG_DEEP_BLUE = _BG_NAVY = _BG_GREEN_B = _BG_ORANGE_B = _BG_RED_B = _BG_GRAY = ""

if _use_color:
    RED = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"; BLUE = "\033[34m"
    MAGENTA = "\033[35m"; CYAN = "\033[36m"; WHITE = "\033[37m"
    DIM = "\033[2m"; BOLD = "\033[1m"; UNDERLINE = "\033[4m"; RESET = "\033[0m"
    BG_RED = "\033[41m"; BG_GREEN = "\033[42m"; BG_YELLOW = "\033[43m"; BG_BLUE = "\033[44m"
    _SKY_BLUE = "\033[38;5;75m"; _BRIGHT_CYAN = "\033[38;5;87m"
    _ORANGE = "\033[38;5;208m"; _AMBER = "\033[38;5;214m"; _CORAL = "\033[38;5;203m"
    _MINT = "\033[38;5;121m"; _SOFT_GREEN = "\033[38;5;114m"
    _LAVENDER = "\033[38;5;147m"; _PINK = "\033[38;5;211m"
    _GRAY = "\033[38;5;241m"; _LIGHT_GRAY = "\033[38;5;248m"
    _DEEP_BLUE = "\033[38;5;17m"; _MED_BLUE = "\033[38;5;33m"


def disable_color():
    global _use_color
    _use_color = False
    # Also strip rich's own coloring (Panels/Tables/Text), not just the legacy
    # ANSI constants — otherwise --no-color only half-works.
    console.no_color = True
    err_console.no_color = True


# ---------------------------------------------------------------------------
# Section labels
# ---------------------------------------------------------------------------
_SECTION_LABELS = {
    "filesystem": "Filesystem Configuration",
    "kernel":     "Kernel Hardening",
    "banners":    "Warning Banners",
    "boot":       "Boot & Package Settings",
    "services":   "Service Configuration",
    "network":    "Network Parameters & Firewall",
    "logging":    "Logging & Auditing",
    "cron":       "Cron & Scheduled Tasks",
    "ssh":        "SSH Server",
    "auth":       "Authentication & Password Policy",
    "users":      "User Accounts & Groups",
}

_SECTION_STYLES = [
    "bright_cyan", "dodger_blue2", "spring_green3", "dark_sea_green",
    "medium_purple1", "dark_orange", "gold1", "hot_pink",
    "bright_cyan", "dodger_blue2", "spring_green3",
]
_section_idx = 0


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
_BANNER_ART = r"""
            ██      ██ ███    ██ ██    ██ ██   ██
            ██      ██ ████   ██ ██    ██  ██ ██
             ██      ██ ██ ██  ██ ██    ██   ███
            ██      ██ ██  ██ ██ ██    ██  ██ ██
            ███████ ██ ██   ████  ██████  ██   ██
███████ ███████  ██████ ██    ██ ██████  ██ ████████ ██    ██
██      ██      ██      ██    ██ ██   ██ ██    ██     ██  ██
 ███████ █████   ██      ██    ██ ██████  ██    ██      ████
      ██ ██      ██      ██    ██ ██   ██ ██    ██       ██
 ███████ ███████  ██████  ██████  ██   ██ ██    ██       ██
            ███████ ██    ██ ██ ████████ ███████
               ██      ██    ██ ██    ██    ██
             ███████ ██    ██ ██    ██    █████
                    ██ ██    ██ ██    ██    ██
            ███████  ██████  ██    ██    ███████
"""


def _banner_centered(style):
    return Align.center(Text(_BANNER_ART, style=f"bold {style}"))


def _banner_tagline():
    from lss import __version__
    return Align.center(Text(f"audit · harden · roll back        v{__version__}", style="grey50"))


def print_banner_art():
    """Big, centered 'Linux Security Suite' wordmark."""
    console.print()
    console.print(_banner_centered("grey93"))
    console.print()
    console.print(_banner_tagline())
    console.print(Rule(style="grey30"))


def banner_fade(subtitle=None):
    """Fade the big wordmark in (monochrome brightness ramp), centered."""
    if not console.is_terminal:
        print_banner_art()
        if subtitle:
            console.print(f"  [grey50]{subtitle}[/]")
            console.print()
        return
    import time
    ramp = ["grey11", "grey19", "grey27", "grey35", "grey46",
            "grey54", "grey62", "grey74", "grey85", "grey93"]
    console.print()
    with Live(console=console, refresh_per_second=30, transient=False) as live:
        for style in ramp:
            live.update(_banner_centered(style))
            time.sleep(0.13)
    console.print()
    console.print(_banner_tagline())
    console.print(Rule(style="grey30"))
    if subtitle:
        console.print(f"  [grey50]{subtitle}[/]")
        console.print()


# ---------------------------------------------------------------------------
# Host info panel
# ---------------------------------------------------------------------------
def print_host_info(host_name: str, hostname: str, kernel: str, uptime: str, control_count: int):
    grid = Table.grid(padding=(0, 3))
    grid.add_column(style="grey50", justify="right")
    grid.add_column()

    grid.add_row("Profile", f"[bold bright_cyan]CIS {host_name}[/]")
    grid.add_row("Host", f"[bold dodger_blue2]{hostname}[/]")
    grid.add_row("Kernel", f"[grey70]{kernel}[/]")
    grid.add_row("Uptime", f"[grey70]{uptime}[/]")
    grid.add_row("Controls", f"[bold spring_green3]{control_count}[/] [grey70]loaded[/]")
    grid.add_row("Mode", "[bright_cyan]read-only[/] [grey50]— no changes will be made[/]")

    console.print(Panel(grid, border_style="blue", title="[bold]System Info[/]", title_align="left"))


# ---------------------------------------------------------------------------
# Section headers
# ---------------------------------------------------------------------------
def section_header(section: str, count: int = 0):
    global _section_idx
    label = _SECTION_LABELS.get(section, section.title())
    style = _SECTION_STYLES[_section_idx % len(_SECTION_STYLES)]
    _section_idx += 1
    console.print()
    console.print(Rule(f"[bold {style}] {label} [/]", style=style, align="left"))


def section_footer():
    pass


# ---------------------------------------------------------------------------
# Control result formatting
# ---------------------------------------------------------------------------
def print_result(control_id: str, title: str, status: str, detail: str = ""):
    if status == "pass":
        sym = "[spring_green3]  ✓[/]"
        id_style = "spring_green3"
    elif status == "warn":
        sym = "[dark_orange]  ▲[/]"
        id_style = "dark_orange"
    elif status == "manual":
        sym = "[gold1]  ◐[/]"
        id_style = "gold1"
    elif status == "skip":
        sym = "[grey50]  -[/]"
        id_style = "grey50"
    else:
        sym = "[red1]  ✗[/]"
        id_style = "red1"

    line = f"{sym} [{id_style} bold]{control_id:<8s}[/] [grey70]{title}[/]"
    if detail:
        line += f"   [grey50]({detail})[/]"
    console.print(line)


def stream_scan(checkable, check_fn):
    """Watch-it-work scan: run each control and stream its result live,
    grouped under elegant section headers.

    `check_fn(ctrl)` runs the check (recording results/counts in the caller)
    and returns (status, detail) so the line renders as the check completes.
    Controls are ordered by CIS section then id so the stream reads top-down
    instead of jumping between sections. A small per-line delay keeps the
    scan visibly streaming even when individual checks are instant; set
    LSS_NO_ANIM=1 (or pipe to a non-TTY) to disable the pacing.
    """
    import os
    import time

    animate = console.is_terminal and not os.environ.get("LSS_NO_ANIM")
    order = {s: i for i, s in enumerate(_SECTION_LABELS)}
    ordered = sorted(checkable, key=lambda c: (order.get(c.section, len(order)), c.id))

    last_section = None
    for ctrl in ordered:
        if ctrl.section != last_section:
            if last_section is not None and animate:
                time.sleep(0.12)
            section_header(ctrl.section)
            last_section = ctrl.section
        status, detail = check_fn(ctrl)
        print_result(ctrl.id, ctrl.title, status, detail)
        if animate:
            time.sleep(0.016)
    console.print()


# ---------------------------------------------------------------------------
# Score gauge
# ---------------------------------------------------------------------------
def _bar(frac: float, width: int, style: str) -> Text:
    f = max(0, min(width, round(frac * width)))
    bar = Text()
    bar.append("█" * f, style=style)
    bar.append("░" * (width - f), style="grey35")
    return bar


def _verdict(score: int) -> tuple[str, str]:
    if score >= 90:
        return "HARDENED", "spring_green3"
    if score >= 70:
        return "NEEDS WORK", "gold1"
    return "AT RISK", "red1"


# ---------------------------------------------------------------------------
# Summary — verdict-led scorecard you read in one glance
# ---------------------------------------------------------------------------
def print_summary(passes: int, warns: int, fails: int, skips: int = 0,
                  manuals: int = 0, host_label: str = "", hostname: str = ""):
    # Hardened — passes / (pass+warn+fail), what LSS can act on.
    # Compliance — passes / (pass+warn+fail+manual), full CIS posture.
    # Manuals don't drag the hardened score: they're deliberate opt-ins.
    hardened_applicable = passes + warns + fails
    compliance_applicable = passes + warns + fails + manuals
    hardened = round(passes / hardened_applicable * 100) if hardened_applicable else 0
    compliance = round(passes / compliance_applicable * 100) if compliance_applicable else 0
    verdict, vstyle = _verdict(hardened)

    console.print()
    head = Table.grid(expand=True)
    head.add_column(justify="left")
    head.add_column(justify="right")
    ctx = f"{hostname} · {host_label}" if hostname else host_label
    head.add_row(Text("  SECURITY POSTURE", style="bold grey70"),
                 Text(f"{ctx}  ", style="grey50"))
    console.print(head)
    console.print()

    score = Text("  ")
    score.append(f"{hardened}%  ", style=f"bold {vstyle}")
    score.append_text(_bar(hardened / 100, 34, vstyle))
    score.append(f"   {verdict}", style=f"bold {vstyle}")
    console.print(score)
    console.print(
        Text("  hardened", style="grey50"),
        Text(f"   ·   {compliance}% full compliance (incl. manual review)", style="grey42"),
    )
    console.print()

    tiles = Text("  ")
    for label, n, style, sym in (
        ("pass", passes, "spring_green3", "✔"),
        ("warn", warns, "gold1", "▲"),
        ("fail", fails, "red1", "✘"),
        ("manual", manuals, "orange1", "◐"),
        ("skip", skips, "grey50", "·"),
    ):
        tiles.append(f"{sym} ", style=style)
        tiles.append(f"{n} ", style=f"bold {style}")
        tiles.append(f"{label}    ", style="grey54")
    console.print(tiles)
    console.print()


# ---------------------------------------------------------------------------
# Section breakdown — one bar per CIS section so gaps jump out
# ---------------------------------------------------------------------------
def print_section_breakdown(results: list[dict]):
    agg: dict[str, list[int]] = {}
    for r in results:
        if r.get("status") == "skip":
            continue
        a = agg.setdefault(r.get("section", ""), [0, 0])
        a[1] += 1
        if r.get("status") == "pass":
            a[0] += 1
    order = list(_SECTION_LABELS.keys())
    rows = [(s, agg[s][0], agg[s][1]) for s in order if s in agg and agg[s][1] > 0]
    rows += [(s, agg[s][0], agg[s][1]) for s in agg
             if s not in order and agg[s][1] > 0]
    if not rows:
        return
    console.print(Text("  BY SECTION", style="bold grey70"))
    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="left", style="grey70", min_width=24)
    grid.add_column()
    grid.add_column(justify="right", style="grey58")
    for sec, p, t in rows:
        frac = p / t if t else 0
        style = "spring_green3" if frac >= 0.9 else "gold1" if frac >= 0.6 else "red1"
        grid.add_row(f"  {_SECTION_LABELS.get(sec, sec.title())}",
                     _bar(frac, 18, style), f"{p}/{t}")
    console.print(grid)
    console.print()


# ---------------------------------------------------------------------------
# Next steps — hand the operator the exact command
# ---------------------------------------------------------------------------
def print_next_steps(fails: int, manuals: int, report_uri: str = ""):
    nxt = Table.grid(padding=(0, 2))
    nxt.add_column(style="bright_cyan", min_width=30)
    nxt.add_column(style="grey54")
    if fails:
        nxt.add_row(Text(" sudo lss harden --confirm", style="bold bright_cyan"),
                    f"apply {fails} fixes · every change is reversible")
        nxt.add_row(Text(" sudo lss harden --dry-run", style="bright_cyan"),
                    "preview the plan, change nothing")
    nxt.add_row(Text(" sudo lss rollback --last", style="bright_cyan"),
                "undo the last harden run instantly")
    console.print(Panel(nxt, title="[bold grey85]NEXT[/]", title_align="left",
                        border_style="grey30", box=box.ROUNDED, padding=(1, 2)))
    if report_uri:
        console.print(Text(f"  report → {report_uri}", style="grey50"))
    console.print()


# ---------------------------------------------------------------------------
# Live scan progress — transient bar that clears when the scan finishes
# ---------------------------------------------------------------------------
def audit_progress() -> Progress:
    return Progress(
        SpinnerColumn(style="bright_cyan"),
        TextColumn("[grey85]Auditing[/]"),
        BarColumn(bar_width=30, complete_style="bright_cyan",
                  finished_style="bright_cyan", pulse_style="grey35"),
        TextColumn("[bold bright_cyan]{task.percentage:>3.0f}%[/]"),
        TextColumn("[grey54]{task.fields[cur]}[/]"),
        console=console,
        transient=True,
    )


# ---------------------------------------------------------------------------
# Fails and warns summary tables
# ---------------------------------------------------------------------------
def print_fails_table(results: list[dict], limit: int = 12):
    fails = [r for r in results if r["status"] == "fail"]
    if not fails:
        return

    shown = fails[:limit]
    extra = len(fails) - len(shown)
    table = Table(
        title=f"[bold red1]Failing controls[/]  [grey54]({len(fails)} · all auto-fixable)[/]",
        title_justify="left",
        caption=(f"[grey50]+ {extra} more — full list in the report[/]" if extra else None),
        caption_justify="left",
        border_style="grey30",
        box=box.SIMPLE,
        show_lines=False,
        padding=(0, 1),
    )
    table.add_column("", style="red1", width=1)
    table.add_column("ID", style="bold grey82", width=9)
    table.add_column("Control", style="grey70")
    table.add_column("What's wrong", style="grey54")

    for r in shown:
        detail = r.get("detail", "")
        if len(detail) > 44:
            detail = detail[:43] + "…"
        table.add_row("✘", r["id"], r["title"], detail)

    console.print(table)
    console.print()


def print_warns_table(results: list[dict]):
    warns = [r for r in results if r["status"] == "warn"]
    if not warns:
        return

    table = Table(
        title=f"[bold dark_orange]Warnings ({len(warns)})[/]",
        border_style="dark_orange",
        box=box.SIMPLE_HEAVY,
        show_lines=False,
        padding=(0, 1),
    )
    table.add_column("ID", style="bold dark_orange", width=10)
    table.add_column("Control", style="grey70")
    table.add_column("Detail", style="grey50")

    for r in warns:
        detail = r.get("detail", "")
        if len(detail) > 40:
            detail = detail[:37] + "..."
        table.add_row(r["id"], r["title"], detail)

    console.print(table)
    console.print()


def print_manuals_table(results: list[dict]):
    """Render the 'Needs Manual Action' table for `manual`-status controls.

    Distinct from fails: these aren't broken — `lss harden` deliberately
    won't touch them (PAM stack edits, audit log volume opt-in, etc.).
    Detail is shown wider than fails/warns because the remediation note
    *is* the operator instruction; truncation defeats the point.
    """
    manuals = [r for r in results if r["status"] == "manual"]
    if not manuals:
        return

    table = Table(
        title=f"[bold orange1]Needs manual review[/]  [grey54]({len(manuals)})[/]",
        title_justify="left",
        caption="[grey50]LSS won't auto-apply these — review and apply by hand.[/]",
        caption_justify="left",
        border_style="grey30",
        box=box.SIMPLE,
        show_lines=True,
        padding=(0, 1),
    )
    table.add_column("", style="orange1", width=1)
    table.add_column("ID", style="bold grey82", width=9)
    table.add_column("Control", style="grey70", width=34)
    table.add_column("How to remediate", style="grey58")

    for r in manuals:
        table.add_row("◐", r["id"], r["title"], r.get("detail", ""))

    console.print(table)
    console.print()


# ---------------------------------------------------------------------------
# Legacy helpers (used by harden.py, rollback.py, cli.py)
# ---------------------------------------------------------------------------
def info(msg: str):
    console.print(f"  [grey50]▸[/] {msg}")

def err(msg: str):
    err_console.print(f"  [red1]✗[/] {msg}")

def warn(msg: str):
    err_console.print(f"  [yellow]![/] {msg}")

def header(msg: str):
    console.print(f"\n  [bold]{msg}[/]")

def rule():
    console.print(Rule(style="grey30"))

def heavy_rule():
    console.print(Rule(style="bright_cyan"))

def double_rule():
    console.print(Rule(style="blue", characters="═"))
