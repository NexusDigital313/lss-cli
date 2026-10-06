# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file, 
# via any medium, is strictly prohibited without explicit written authorization.

"""CLI entry point for the Linux Security Suite."""

import argparse
import sys

from lss import __version__
from lss.lib.output import RESET, BLUE, CYAN, BOLD, DIM, YELLOW, GREEN, RED, err, info


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lss",
        description="The Linux Security Suite — audit, harden, and rollback Linux hosts against the CIS Benchmark.",
    )
    p.add_argument("-V", "--version", action="version", version=f"lss {__version__}")
    p.add_argument("--json", action="store_true", help="output results as JSON")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("--license-key", metavar="KEY", help="LSS license key (overrides LSS_LICENSE_KEY env and /etc/lss/license.key)")

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
    audit.add_argument(
        "--no-report",
        action="store_true",
        help="skip the HTML report (HTML default is ~/.local/share/lss/reports/; JSON always lands in /var/log/lss/). Implied by --json.",
    )
    audit.add_argument(
        "--open",
        action="store_true",
        help="open the HTML report in the default browser when finished",
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
    harden.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="prompt y/N before applying each fix (default: apply all without prompting)",
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
        help="output path for the report (default: ~/.local/share/lss/reports/report-<timestamp>.html for the invoking user)",
    )
    report.add_argument(
        "--baseline",
        metavar="PATH",
        help="path to a previous audit JSON; report renders a before/after delta against it",
    )
    report.add_argument(
        "--open",
        action="store_true",
        help="open the report in the default browser after writing",
    )

    # --- list ---
    sub.add_parser("list", help="list all 206 controls with descriptions")

    # --- help-all ---
    sub.add_parser("help-all", help="show all commands with full descriptions and consequences")

    # --- license ---
    lic = sub.add_parser("license", help="activate / check / remove your LSS license (needed for harden + rollback)")
    lic_sub = lic.add_subparsers(dest="license_cmd")
    lic_act = lic_sub.add_parser("activate", help="activate a license key on this host")
    lic_act.add_argument("key", metavar="KEY", help="your LSS license key (from your purchase email)")
    lic_sub.add_parser("status", help="show this host's license status")
    lic_sub.add_parser("deactivate", help="release this host's activation (frees a seat)")

    return p


def banner():
    from lss.lib.output import print_banner_art
    print_banner_art()


def _print_help_all():
    """Print every command with full plain-English descriptions and consequences."""
    banner()
    print(f"""
{BOLD}{CYAN}COMMANDS{RESET}

{BOLD}  lss audit{RESET}
    What it does:   Scans your system against 206 CIS Benchmark security controls.
                    Checks things like firewall rules, SSH settings, password policies,
                    file permissions, running services, and kernel hardening.
    Changes made:   {BOLD}None.{RESET} This is completely read-only. Nothing is modified.
    Output:         Colored terminal report,
                    JSON audit log saved to /var/log/lss/ (root-only),
                    HTML report saved to ~/.local/share/lss/reports/ (readable by you).
    When to use:    Anytime you want to see how secure your system is.

    Options:
      --control ID    Only check specific control(s).  Example: --control 5.2.5
      --json          Also print results as machine-readable JSON.
      --profile X     Choose server, workstation, or hardened profile.
      --open          Open the HTML report in your default browser when finished.
      --no-report     Skip the HTML report. Implied by --json. JSON always lands
                      in /var/log/lss/; HTML default is ~/.local/share/lss/reports/.

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
      -i, --interactive
                      Prompt y/N before each fix is applied. Use this on a
                      live customer box where you want to review every
                      change in context before it lands. Default is N
                      (skip) so a held breath of stdin doesn't apply a fix.

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
                    {DIM}(lss audit already emits this report — use this command
                    when you want to regenerate, render against a baseline,
                    or save to a custom path.){RESET}
    Changes made:   {BOLD}None.{RESET} Just writes an HTML file.
    Default path:   ~/.local/share/lss/reports/report-<timestamp>.html
                    (owned by the user who ran sudo, mode 0640)
    When to use:    When you need proof of your security posture for a client,
                    an auditor, or your own records.

    Options:
      -o PATH         Save the report to a specific file path.
      --open          Open the report in your default browser after writing.
      --baseline PATH Render a before/after delta against a previous audit
                      JSON (e.g. /var/log/lss/audit-<earlier-ts>.json).
                      Adds Before/After/Change columns and a delta summary
                      block showing how many controls were Fixed,
                      Regressed, Still failing, or Unchanged.

{BOLD}  lss list{RESET}
    What it does:   Shows all 206 controls with their ID, section, title,
                    and whether they have an automatic fix available.
    Changes made:   {BOLD}None.{RESET} Just prints a list.
    When to use:    When you want to see everything LSS checks for.

{BOLD}  lss license{RESET} {DIM}activate <KEY> | status | deactivate{RESET}
    What it does:   Manages your paid license. {BOLD}audit{RESET}, {BOLD}report{RESET}, {BOLD}list{RESET}, and
                    {BOLD}harden --dry-run{RESET} are free; applying changes with
                    {BOLD}harden --confirm{RESET} needs an activated key. {BOLD}rollback{RESET} is
                    always free — undo is never withheld.
    Activate once:  {BOLD}sudo lss license activate <YOUR-KEY>{RESET}  (one online check, then
                    cached — works offline afterward).
    Changes made:   {BOLD}None{RESET} to the system; writes the license cache to /etc/lss/.

{BOLD}{CYAN}GLOBAL OPTIONS{RESET}

    --no-color      Turn off colored output (for piping to files or scripts).
    --json          Output results as JSON (works with audit).
    -V, --version   Show version number.

{BOLD}{CYAN}EXAMPLES{RESET}

    {DIM}# See how secure your system is (no changes) and open the report{RESET}
    sudo lss audit --open

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

    {DIM}# See all 206 controls{RESET}
    sudo lss list
""")



def _run_license(args) -> int:
    """Handle `lss license activate|status|deactivate`."""
    from lss.lib import license as lic
    sub = getattr(args, "license_cmd", None)
    if sub == "activate":
        st = lic.activate(args.key)
    elif sub == "deactivate":
        st = lic.deactivate()
    else:  # default: status
        st = lic.status()

    if st.valid:
        bits = [b for b in (st.product, st.purchase_email, st.key_masked) if b]
        suffix = ("  (" + " · ".join(bits) + ")") if bits else ""
        info(f"{st.detail}{suffix}")
        return 0
    err(f"license: {st.detail}")
    if sub != "deactivate":
        info("Activate with:  sudo lss license activate <YOUR-KEY>")
    return 1


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

    # license management doesn't need root (cache falls back to ~/.config/lss)
    if args.command == "license":
        banner()
        sys.exit(_run_license(args))

    # Everything else needs root
    import os
    if os.geteuid() != 0:
        err("lss must be run as root")
        sys.exit(1)

    # Banner is decorative — suppress in --json so stdout stays parseable.
    # audit renders its own animated banner inside run_audit (banner_fade);
    # everything else gets the static ASCII wordmark via banner().
    if not getattr(args, "json", False) and args.command != "audit":
        banner()

    # License gate — only applying hardening (`harden --confirm`) is paid.
    # Free, by design: `audit`, `report`, `list`, `harden --dry-run` (preview),
    # and `rollback` — rollback is the safety net and must never be withheld, or
    # a lapsed license could trap a box in a hardened state. Enforcement is on by
    # default; a valid Lemon Squeezy key (or LSS_ENFORCE_LICENSE=0) satisfies it.
    if args.command == "harden" and not getattr(args, "dry_run", False):
        from lss.lib.license import check_license
        lic_status = check_license(getattr(args, "license_key", None))
        if not lic_status.valid:
            err(f"applying hardening requires a license — {lic_status.detail}")
            info("Preview for free:    sudo lss harden --dry-run")
            info("Buy a license, then: sudo lss license activate <YOUR-KEY>")
            info("Already activated?   sudo lss license status")
            info("Self-hosting / dev?  set LSS_ENFORCE_LICENSE=0")
            sys.exit(2)

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

