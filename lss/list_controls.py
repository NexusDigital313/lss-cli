"""List all registered controls — streamed by section, matching the audit flow."""

from __future__ import annotations

import os
import time

from lss.lib.output import console, section_header, _SECTION_LABELS
from lss.lib.registry import get_controls

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
    """Stream every control grouped under colored section headers — the same
    visual language as `lss audit`. Cascades on a TTY; instant when piped.
    """
    controls = get_controls()
    fixable = sum(1 for c in controls if c.fix is not None)
    audit_only = len(controls) - fixable

    animate = console.is_terminal and not os.environ.get("LSS_NO_ANIM")
    order = {s: i for i, s in enumerate(_SECTION_LABELS)}
    ordered = sorted(controls, key=lambda c: (order.get(c.section, len(order)), c.id))

    console.print()
    console.print(f"  [bold grey93]All CIS-aligned controls[/]   "
                  f"[grey50]({len(controls)} · {fixable} auto-fix · {audit_only} audit-only)[/]")

    last = None
    for ctrl in ordered:
        if ctrl.section != last:
            if last is not None and animate:
                time.sleep(0.12)
            section_header(ctrl.section)
            last = ctrl.section
        if ctrl.fix is not None:
            mark, idc, tag = "[spring_green3]●[/]", "spring_green3", "[spring_green3]auto-fix[/]"
        else:
            mark, idc, tag = "[grey42]○[/]", "grey58", "[grey42]audit-only[/]"
        console.print(f"  {mark} [{idc} bold]{ctrl.id:<9s}[/] [grey74]{ctrl.title}[/]   {tag}")
        if animate:
            time.sleep(0.016)

    console.print()
    console.print(f"  [bold]{len(controls)}[/] controls   "
                  f"[spring_green3]{fixable} auto-fixable[/]   "
                  f"[grey50]{audit_only} audit-only[/]")
    console.print()
    return 0
