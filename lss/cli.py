"""CLI entry point for the Linux Security Suite."""

import argparse
import sys

from lss import __version__
from lss.lib.output import RESET, BLUE, CYAN, BOLD, DIM, YELLOW, GREEN, RED, err


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lss",
        description="The Linux Security Suite — audit, harden, and rollback Linux hosts against the CIS Benchmark.",
    )
    p.add_argument("-V", "--version", action="version", version=f"lss {__version__}")
    p.add_argument("--json", action="store_true", help="output results as JSON")
    p.add_argument("--no-color", action="store_true", help="disable colored output")

    sub = p.add_subparsers(dest="command")

    # --- audit ---
    audit = sub.add_parser("audit", help="run CIS checks in read-only mode")
    audit.add_argument(
        "--profile",
        choices=["server", "workstation", "hardened"],
        default="server",
        help="CIS profile to audit against (default: server)",
    )
    audit.add_argument(
        "--control",
        metavar="ID",
        action="append",
        help="run only specific control(s), e.g. --control 1.1.1 --control 5.2.5",
    )

    # --- harden ---
    harden = sub.add_parser("harden", help="apply remediations for failing controls")
    harden_group = harden.add_mutually_exclusive_group(required=True)
    harden_group.add_argument("--confirm", action="store_true", help="apply changes to the system")
    harden_group.add_argument("--dry-run", action="store_true", help="show what would be fixed without making any changes")
    harden.add_argument(
        "--control",
        metavar="ID",
        action="append",
        help="harden only specific control(s)",
    )

    # --- rollback ---
    rollback = sub.add_parser("rollback", help="undo previous hardening changes")
    roll_group = rollback.add_mutually_exclusive_group(required=True)
    roll_group.add_argument("--last", action="store_true", help="rollback the most recent harden run")
    roll_group.add_argument("--run-id", metavar="ID", help="rollback a specific run by ID")
    roll_group.add_argument("--control", metavar="ID", help="rollback a specific control from the last run")

    # --- report ---
    report = sub.add_parser("report", help="generate HTML report from last audit")
    report.add_argument(
        "-o", "--output",
        metavar="PATH",
        help="output path for the report (default: /var/log/lss/report-<timestamp>.html)",
    )

    # --- list ---
    sub.add_parser("list", help="list all 204 controls with descriptions")

    # --- help-all ---
    sub.add_parser("help-all", help="show all commands with full descriptions and consequences")

    return p


def banner():
    print(f"{BOLD}{BLUE}  ▸ Linux Security Suite{RESET} v{__version__}")


def _print_help_all():
    """Print every command with full plain-English descriptions and consequences."""
    banner()
    print(f"""
{BOLD}{CYAN}COMMANDS{RESET}

{BOLD}  lss audit{RESET}
    What it does:   Scans your system against 204 CIS Benchmark security controls.
                    Checks things like firewall rules, SSH settings, password policies,
                    file permissions, running services, and kernel hardening.
    Changes made:   {BOLD}None.{RESET} This is completely read-only. Nothing is modified.
    Output:         Colored terminal report + JSON file saved to /var/log/lss/.
    When to use:    Anytime you want to see how secure your system is.

    Options:
      --control ID    Only check specific control(s).  Example: --control 5.2.5
      --json          Also print results as machine-readable JSON.
      --profile X     Choose server, workstation, or hardened profile.

{BOLD}  lss harden --confirm{RESET}
    What it does:   Fixes every failing control that has an automatic fix.
                    For example: tightens SSH settings, enables firewall rules,
                    sets password policies, disables unnecessary services.
    Changes made:   {BOLD}{YELLOW}Yes — modifies system configuration files.{RESET}
                    Every single change is recorded in a rollback journal.
    Consequences:   Some changes can affect daily use:
                    - Firewall rules may block services you're running
                    - SSH settings may disconnect idle sessions
                    - Disabled kernel modules won't load until you undo it
    Safety:         {GREEN}Fully reversible.{RESET} Run {BOLD}lss rollback --last{RESET} to undo everything.
    When to use:    After running {BOLD}lss audit{RESET} and reviewing what's failing.

    Options:
      --control ID    Only fix specific control(s).  Lets you pick and choose.
                      Example: --control 5.2.3 --control 5.4.1.1

{BOLD}  lss rollback --last{RESET}
    What it does:   Undoes the most recent harden run. Every change is reversed
                    in the opposite order it was applied.
    Changes made:   {BOLD}{YELLOW}Yes — restores previous configuration.{RESET}
    Consequences:   Your system goes back to exactly how it was before the
                    last harden. Security fixes are removed.
    When to use:    Something broke after hardening and you need to undo it {BOLD}now{RESET}.

    Options:
      --last          Undo the most recent harden run (most common).
      --run-id ID     Undo a specific past run by its ID.
      --control ID    Undo just one control from the last run.

{BOLD}  lss report{RESET}
    What it does:   Generates a styled HTML report from the last audit.
                    Shows every control with pass/warn/fail status, a score,
                    and a summary you can print or email to a client.
    Changes made:   {BOLD}None.{RESET} Just writes an HTML file.
    When to use:    When you need proof of your security posture for a client,
                    an auditor, or your own records.

    Options:
      -o PATH         Save the report to a specific file path.

{BOLD}  lss list{RESET}
    What it does:   Shows all 204 controls with their ID, section, title,
                    and whether they have an automatic fix available.
    Changes made:   {BOLD}None.{RESET} Just prints a list.
    When to use:    When you want to see everything LSS checks for.

{BOLD}{CYAN}GLOBAL OPTIONS{RESET}

    --no-color      Turn off colored output (for piping to files or scripts).
    --json          Output results as JSON (works with audit).
    -V, --version   Show version number.

{BOLD}{CYAN}EXAMPLES{RESET}

    {DIM}# See how secure your system is (no changes){RESET}
    sudo lss audit

    {DIM}# Fix everything that's failing (with undo available){RESET}
    sudo lss harden --confirm

    {DIM}# Fix only SSH and password issues{RESET}
    sudo lss harden --confirm --control 5.2.3 --control 5.4.1.1

    {DIM}# Something broke? Undo it all{RESET}
    sudo lss rollback --last

    {DIM}# Undo just one specific control{RESET}
    sudo lss rollback --control 5.2.3

    {DIM}# Generate a report you can print{RESET}
    sudo lss report -o ~/my-audit.html

    {DIM}# See all 204 controls{RESET}
    sudo lss list
""")



def main(argv: list[str] | None = None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.no_color:
        import lss.lib.output as out
        out.disable_color()

    if not args.command:
        banner()
        parser.print_help()
        sys.exit(0)

    # help-all and list don't need root
    if args.command == "help-all":
        _print_help_all()
        sys.exit(0)

    if args.command == "list":
        from lss.list_controls import run_list
        banner()
        sys.exit(run_list())

    # Everything else needs root
    import os
    if os.geteuid() != 0:
        err("lss must be run as root")
        sys.exit(1)

    banner()

    if args.command == "audit":
        from lss.audit import run_audit
        sys.exit(run_audit(args))

    elif args.command == "harden":
        from lss.harden import run_harden
        sys.exit(run_harden(args))

    elif args.command == "rollback":
        from lss.rollback import run_rollback
        sys.exit(run_rollback(args))

    elif args.command == "report":
        from lss.report import run_report
        sys.exit(run_report(args))

