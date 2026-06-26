"""Rich terminal output for the Linux Security Suite.

Theme matches the LSS launch/social cards: a dark acid-green terminal
aesthetic — green #00d75f / #3df58a primary, cyan #58d1eb secondary,
gold/amber for warnings, with `>_` lockup and [*]/[+]/[!]/[x] log markers.
Only presentation lives here; audit/harden/rollback behavior is unchanged.
"""

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

# ---------------------------------------------------------------------------
# Card-matched palette (the X / launch banners). Truecolor hex — rich renders
# these directly; they degrade gracefully on 256-color terminals.
# ---------------------------------------------------------------------------
C_GREEN   = "#00d75f"   # primary acid green
C_GREEN_B = "#3df58a"   # bright green (glow / verdict)
C_CYAN    = "#58d1eb"   # secondary
C_GOLD    = "#ffd700"   # highlight
C_AMBER   = "#ffaf00"   # warning / manual
C_RED     = "#ff5f57"   # fail
C_TEXT    = "#e8edf2"   # bright text
C_MUTE    = "#c5c8c6"   # body text
C_DIM     = "#808080"   # dim
C_FAINT   = "#5a6066"   # fainter
C_LINE    = "#1c2530"   # hairlines / borders

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

# Disciplined on-brand cycle (green / cyan / bright-green / gold) instead of a
# scattered rainbow — keeps the scan reading as one designed surface.
_SECTION_STYLES = [
    C_GREEN, C_CYAN, C_GREEN_B, C_GOLD,
    C_GREEN, C_CYAN, C_GREEN_B, C_GOLD,
    C_GREEN, C_CYAN, C_GREEN_B,
]
_section_idx = 0


# ---------------------------------------------------------------------------
# Banner — the `>_` LSS lockup from the cards
# ---------------------------------------------------------------------------
def _banner_line(accent, dim):
    """One frame of the wordmark: a green accent rail + `>_` mark, the LSS
    lockup, and the spelled-out suite name, with the version right-aligned."""
    from lss import __version__
    grid = Table.grid(expand=True, padding=(0, 0))
    grid.add_column(justify="left")
    grid.add_column(justify="right")

    left = Text()
    left.append("  ▌ ", style=f"bold {accent}")
    left.append(">_", style=f"bold {accent}")
    left.append("   ", style=accent)
    left.append("LSS", style=f"bold {C_TEXT}")
    left.append("\n  ▌      ", style=f"bold {accent}")
    left.append("LINUX SECURITY SUITE", style=dim)

    ver = Text(f"v{__version__}  ", style=dim)
    grid.add_row(left, ver)
    return grid


def print_banner_art():
    """Static one-shot lockup (non-animated / non-TTY)."""
    console.print()
    console.print(_banner_line(C_GREEN_B, C_DIM))
    console.print(Rule(style=C_GREEN))


def banner_fade(subtitle=None):
    """Fade the lockup in with a dark→acid green brightness ramp."""
    if not console.is_terminal:
        print_banner_art()
        if subtitle:
            console.print(f"  [{C_DIM}]{subtitle}[/]")
            console.print()
        return
    import time
    ramp = ["#0e3a22", "#11633a", "#1a8f50", "#2bbf6e", "#34e07e", "#3df58a"]
    console.print()
    with Live(console=console, refresh_per_second=30, transient=False) as live:
        for style in ramp:
            live.update(_banner_line(style, "#3a4048"))
            time.sleep(0.08)
    console.print(Rule(style=C_GREEN))
    if subtitle:
        console.print(f"  [{C_CYAN}]{subtitle}[/]")
        console.print()


# ---------------------------------------------------------------------------
# Marker legend — Prowler-style one-line key so the status tags read instantly
# ---------------------------------------------------------------------------
def print_legend():
    t = Text("  ")
    t.append("key  ", style=C_FAINT)
    for marker, mstyle, label in (
        ("[+]", C_GREEN_B, "pass"),
        ("[x]", C_RED, "fixable"),
        ("[!]", C_AMBER, "warn"),
        ("[~]", C_GOLD, "manual"),
        ("[-]", C_DIM, "n/a"),
    ):
        t.append(f"{marker} ", style=f"bold {mstyle}")
        t.append(f"{label}   ", style=C_MUTE)
    console.print(t)
    console.print()


# ---------------------------------------------------------------------------
# Host info panel
# ---------------------------------------------------------------------------
def print_host_info(host_name: str, hostname: str, kernel: str, uptime: str, control_count: int):
    grid = Table.grid(padding=(0, 3))
    grid.add_column(style=C_DIM, justify="right")
    grid.add_column()

    grid.add_row("Profile", f"[bold {C_CYAN}]CIS {host_name}[/]")
    grid.add_row("Host", f"[bold {C_GREEN_B}]{hostname}[/]")
    grid.add_row("Kernel", f"[{C_MUTE}]{kernel}[/]")
    grid.add_row("Uptime", f"[{C_MUTE}]{uptime}[/]")
    grid.add_row("Controls", f"[bold {C_GREEN}]{control_count}[/] [{C_MUTE}]loaded[/]")
    grid.add_row("Mode", f"[{C_CYAN}]audit (read-only)[/] [{C_DIM}]— no changes will be made[/]")

    console.print(Panel(grid, border_style=C_GREEN, title=f"[bold {C_TEXT}]System Info[/]",
                        title_align="left", box=box.ROUNDED, padding=(0, 1)))


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
# Control result formatting — bracketed log markers, card palette
# ---------------------------------------------------------------------------
_RESULT_MARKERS = {
    "pass":   ("[+]", C_GREEN_B),
    "warn":   ("[!]", C_AMBER),
    "manual": ("[~]", C_GOLD),
    "skip":   ("[-]", C_DIM),
    "fail":   ("[x]", C_RED),
}


def print_result(control_id: str, title: str, status: str, detail: str = ""):
    marker, mstyle = _RESULT_MARKERS.get(status, _RESULT_MARKERS["fail"])
    t = Text("  ")
    t.append(f"{marker} ", style=f"bold {mstyle}")
    t.append(f"{control_id:<8s} ", style=f"bold {mstyle}")
    t.append(title, style=C_MUTE)
    if detail:
        t.append(f"   ({detail})", style=C_DIM)
    console.print(t)


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
    bar.append("░" * (width - f), style=C_LINE)
    return bar


def _verdict(score: int) -> tuple[str, str]:
    if score >= 90:
        return "HARDENED", C_GREEN_B
    if score >= 70:
        return "NEEDS WORK", C_GOLD
    return "AT RISK", C_RED


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
    head.add_row(Text("  SECURITY POSTURE", style=f"bold {C_TEXT}"),
                 Text(f"{ctx}  ", style=C_DIM))
    console.print(head)
    console.print()

    score = Text("  ")
    score.append(f"{hardened}%  ", style=f"bold {vstyle}")
    score.append_text(_bar(hardened / 100, 34, vstyle))
    score.append(f"   {verdict}", style=f"bold {vstyle}")
    console.print(score)
    console.print(
        Text("  hardened", style=C_DIM),
        Text(f"   ·   {compliance}% full compliance (incl. manual review)", style=C_FAINT),
    )
    console.print()

    tiles = Text("  ")
    for label, n, style, sym in (
        ("pass", passes, C_GREEN_B, "✔"),
        ("warn", warns, C_AMBER, "▲"),
        ("fail", fails, C_RED, "✘"),
        ("manual", manuals, C_GOLD, "◐"),
        ("skip", skips, C_DIM, "·"),
    ):
        tiles.append(f"{sym} ", style=style)
        tiles.append(f"{n} ", style=f"bold {style}")
        tiles.append(f"{label}    ", style=C_MUTE)
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
    console.print(Text("  BY SECTION", style=f"bold {C_TEXT}"))
    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="left", style=C_MUTE, min_width=24)
    grid.add_column()
    grid.add_column(justify="right", style=C_FAINT)
    for sec, p, t in rows:
        frac = p / t if t else 0
        style = C_GREEN_B if frac >= 0.9 else C_GOLD if frac >= 0.6 else C_RED
        grid.add_row(f"  {_SECTION_LABELS.get(sec, sec.title())}",
                     _bar(frac, 18, style), f"{p}/{t}")
    console.print(grid)
    console.print()


# ---------------------------------------------------------------------------
# Next steps — hand the operator the exact command
# ---------------------------------------------------------------------------
def print_next_steps(fails: int, manuals: int, report_uri: str = ""):
    nxt = Table.grid(padding=(0, 2))
    nxt.add_column(min_width=30)
    nxt.add_column(style=C_FAINT)
    if fails:
        cmd = Text(" sudo lss harden ", style=f"bold {C_GREEN_B}")
        cmd.append("--confirm", style=f"bold {C_AMBER}")
        nxt.add_row(cmd, f"apply {fails} fixes · every change is reversible")
        nxt.add_row(Text(" sudo lss harden --dry-run", style=C_CYAN),
                    "preview the plan, change nothing")
    nxt.add_row(Text(" sudo lss rollback --last", style=C_CYAN),
                "undo the last harden run instantly")
    console.print(Panel(nxt, title=f"[bold {C_TEXT}]NEXT[/]", title_align="left",
                        border_style=C_GREEN, box=box.ROUNDED, padding=(1, 2)))
    if report_uri:
        console.print(Text(f"  report → {report_uri}", style=C_DIM))
    console.print()


# ---------------------------------------------------------------------------
# Live scan progress — transient bar that clears when the scan finishes
# ---------------------------------------------------------------------------
def audit_progress() -> Progress:
    return Progress(
        SpinnerColumn(style=C_CYAN),
        TextColumn(f"[{C_TEXT}]Auditing[/]"),
        BarColumn(bar_width=30, complete_style=C_GREEN_B,
                  finished_style=C_GREEN, pulse_style=C_LINE),
        TextColumn(f"[bold {C_GREEN_B}]{{task.percentage:>3.0f}}%[/]"),
        TextColumn(f"[{C_FAINT}]{{task.fields[cur]}}[/]"),
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
        title=f"[bold {C_RED}]Failing controls[/]  [{C_FAINT}]({len(fails)} · all auto-fixable)[/]",
        title_justify="left",
        caption=(f"[{C_DIM}]+ {extra} more — full list in the report[/]" if extra else None),
        caption_justify="left",
        border_style=C_LINE,
        box=box.SIMPLE,
        show_lines=False,
        padding=(0, 1),
    )
    table.add_column("", style=C_RED, width=1)
    table.add_column("ID", style=f"bold {C_TEXT}", width=9)
    table.add_column("Control", style=C_MUTE)
    table.add_column("What's wrong", style=C_FAINT)

    for r in shown:
        detail = r.get("detail", "")
        if len(detail) > 44:
            detail = detail[:43] + "…"
        table.add_row("x", r["id"], r["title"], detail)

    console.print(table)
    console.print()


def print_warns_table(results: list[dict]):
    warns = [r for r in results if r["status"] == "warn"]
    if not warns:
        return

    table = Table(
        title=f"[bold {C_AMBER}]Warnings ({len(warns)})[/]",
        border_style=C_AMBER,
        box=box.SIMPLE_HEAVY,
        show_lines=False,
        padding=(0, 1),
    )
    table.add_column("ID", style=f"bold {C_AMBER}", width=10)
    table.add_column("Control", style=C_MUTE)
    table.add_column("Detail", style=C_DIM)

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
        title=f"[bold {C_GOLD}]Needs manual review[/]  [{C_FAINT}]({len(manuals)})[/]",
        title_justify="left",
        caption=f"[{C_DIM}]LSS won't auto-apply these — review and apply by hand.[/]",
        caption_justify="left",
        border_style=C_LINE,
        box=box.SIMPLE,
        show_lines=True,
        padding=(0, 1),
    )
    table.add_column("", style=C_GOLD, width=1)
    table.add_column("ID", style=f"bold {C_TEXT}", width=9)
    table.add_column("Control", style=C_MUTE, width=34)
    table.add_column("How to remediate", style=C_FAINT)

    for r in manuals:
        table.add_row("~", r["id"], r["title"], r.get("detail", ""))

    console.print(table)
    console.print()


# ---------------------------------------------------------------------------
# Legacy helpers (used by harden.py, rollback.py, cli.py)
# ---------------------------------------------------------------------------
def info(msg: str):
    t = Text("  ")
    t.append("[*] ", style=C_CYAN)
    t.append(msg, style=C_MUTE)
    console.print(t)

def ok(msg: str):
    t = Text("  ")
    t.append("[+] ", style=f"bold {C_GREEN_B}")
    t.append(msg, style=C_MUTE)
    console.print(t)

def err(msg: str):
    t = Text("  ")
    t.append("[x] ", style=f"bold {C_RED}")
    t.append(msg, style=C_MUTE)
    err_console.print(t)

def warn(msg: str):
    t = Text("  ")
    t.append("[!] ", style=C_AMBER)
    t.append(msg, style=C_MUTE)
    err_console.print(t)

def header(msg: str):
    console.print(f"\n  [bold {C_TEXT}]{msg}[/]")

def rule():
    console.print(Rule(style=C_LINE))

def heavy_rule():
    console.print(Rule(style=C_GREEN))

def double_rule():
    console.print(Rule(style=C_GREEN, characters="═"))
