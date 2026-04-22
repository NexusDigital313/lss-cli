"""List all registered controls in a readable format."""

from __future__ import annotations

from lss.lib.output import BOLD, RESET, DIM, CYAN, GREEN, YELLOW, RED, rule, section_header
from lss.lib.registry import get_controls
from lss.lib.output import _SECTION_LABELS

# Import all controls so they register
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


def run_list() -> int:
    """Print all controls grouped by section."""
    controls = get_controls()

    print()
    rule()
    print(f"  {BOLD}All CIS Benchmark Controls{RESET}   {DIM}({len(controls)} total){RESET}")
    rule()

    current_section = ""
    seen_sections: set[str] = set()
    fixable = 0
    audit_only = 0

    for ctrl in controls:
        if ctrl.section != current_section:
            current_section = ctrl.section
            if current_section not in seen_sections:
                seen_sections.add(current_section)
                label = _SECTION_LABELS.get(current_section, current_section.title())
                print(f"\n  {CYAN}{BOLD}┌ {label}{RESET}")

        has_fix = ctrl.fix is not None
        if has_fix:
            fixable += 1
            fix_tag = f"{GREEN}[auto-fix]{RESET}"
        else:
            audit_only += 1
            fix_tag = f"{DIM}[audit-only]{RESET}"

        print(f"    {BOLD}{ctrl.id:<10s}{RESET} {ctrl.title}  {fix_tag}")

    print()
    rule()
    print(
        f"  {BOLD}{len(controls)}{RESET} controls   "
        f"{GREEN}{fixable} auto-fixable{RESET}   "
        f"{DIM}{audit_only} audit-only{RESET}"
    )
    print()

    return 0
