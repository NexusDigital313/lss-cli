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
def print_banner_art():
    logo = Text()
    logo.append("    ██╗     ███████╗███████╗\n", style="bold dodger_blue2")
    logo.append("    ██║     ██╔════╝██╔════╝\n", style="bold bright_cyan")
    logo.append("    ██║     ███████╗███████╗\n", style="bold deep_sky_blue1")
    logo.append("    ██║     ╚════██║╚════██║\n", style="bold bright_cyan")
    logo.append("    ███████╗███████║███████║\n", style="bold dodger_blue2")
    logo.append("    ╚══════╝╚══════╝╚══════╝\n", style="dim blue")
    logo.append("\n    T H E   L I N U X   S E C U R I T Y   S U I T E", style="bold grey70")

    console.print()
    console.print(Panel(
        logo,
        border_style="blue",
        box=box.DOUBLE_EDGE,
        padding=(0, 2),
    ))


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


# ---------------------------------------------------------------------------
# Score gauge
# ---------------------------------------------------------------------------
def _score_bar(score: int, width: int = 50) -> Text:
    filled = round(score / 100 * width)
    empty = width - filled

    if score >= 90:
        fill_style = "on green"
        text_style = "bold spring_green3"
    elif score >= 70:
        fill_style = "on dark_orange"
        text_style = "bold dark_orange"
    else:
        fill_style = "on red1"
        text_style = "bold red1"

    bar = Text()
    bar.append("█" * filled, style=fill_style.replace("on ", ""))
    bar.append("░" * empty, style="grey30")
    bar.append(f"  {score}%", style=text_style)
    return bar


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
def print_summary(passes: int, warns: int, fails: int, skips: int = 0, manuals: int = 0):
    total = passes + warns + fails + skips + manuals

    # Two scores so the operator can see both sides:
    #   Hardened — passes / (pass+warn+fail) — what LSS auto-hardened
    #   Compliance — passes / (pass+warn+fail+manual) — full CIS posture
    # Manuals deliberately don't count against the hardened score: they're
    # controls LSS won't auto-fix by design (operator opt-in required), and
    # punishing the score for that restraint creates the wrong incentive.
    hardened_applicable = passes + warns + fails
    compliance_applicable = passes + warns + fails + manuals
    hardened_score = round(passes / hardened_applicable * 100) if hardened_applicable else 0
    compliance_score = round(passes / compliance_applicable * 100) if compliance_applicable else 0

    console.print()

    # Two score bars, labeled
    score_panel = Table.grid(padding=(0, 0))
    score_panel.add_column(justify="right", style="grey70", min_width=12)
    score_panel.add_column()
    score_panel.add_row("[bold]Hardened[/]  ", _score_bar(hardened_score, width=50))
    score_panel.add_row("[bold]Compliance[/]  ", _score_bar(compliance_score, width=50))

    # Stats — six columns now (added manual)
    stats = Table.grid(padding=(0, 3))
    for _ in range(6):
        stats.add_column(justify="center")

    stats.add_row(
        f"[bold spring_green3]{passes}[/]\n[grey50]pass[/]",
        f"[bold dark_orange]{warns}[/]\n[grey50]warn[/]",
        f"[bold red1]{fails}[/]\n[grey50]fail[/]",
        f"[bold gold1]{manuals}[/]\n[grey50]manual[/]",
        f"[bold grey50]{skips}[/]\n[grey50]skip[/]",
        f"[bold grey70]{total}[/]\n[grey50]total[/]",
    )

    # Combined panel
    inner = Table.grid(padding=(1, 0))
    inner.add_column()
    inner.add_row(Align.center(score_panel))
    inner.add_row(Align.center(stats))

    console.print(Panel(
        inner,
        title="[bold bright_cyan]Security Score[/]",
        border_style="blue",
        box=box.ROUNDED,
        padding=(1, 4),
    ))
    console.print()


# ---------------------------------------------------------------------------
# Fails and warns summary tables
# ---------------------------------------------------------------------------
def print_fails_table(results: list[dict]):
    fails = [r for r in results if r["status"] == "fail"]
    if not fails:
        return

    table = Table(
        title=f"[bold red1]Failing Controls ({len(fails)})[/]",
        border_style="red",
        box=box.SIMPLE_HEAVY,
        show_lines=False,
        padding=(0, 1),
    )
    table.add_column("ID", style="bold red1", width=10)
    table.add_column("Control", style="grey70")
    table.add_column("Detail", style="dark_orange")

    for r in fails:
        detail = r.get("detail", "")
        if len(detail) > 40:
            detail = detail[:37] + "..."
        table.add_row(r["id"], r["title"], detail)

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
        title=f"[bold gold1]Needs Manual Action ({len(manuals)})[/]",
        caption="[grey50]These require operator action — `lss harden` will not auto-apply them.[/]",
        border_style="gold1",
        box=box.SIMPLE_HEAVY,
        show_lines=True,
        padding=(0, 1),
    )
    table.add_column("ID", style="bold gold1", width=10)
    table.add_column("Control", style="grey70", width=40)
    table.add_column("How to remediate", style="grey70")

    for r in manuals:
        table.add_row(r["id"], r["title"], r.get("detail", ""))

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
