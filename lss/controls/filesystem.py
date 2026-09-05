# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized reproduction, copying, modification, distribution,
# redistribution, publication, reverse engineering, decompilation, or
# disassembly of this file, in whole or in part, via any medium, is
# strictly prohibited without explicit prior written authorization.

"""CIS Section 1.1 — Filesystem configuration."""

import subprocess
from pathlib import Path

from lss.lib.modules import module_is_disabled, module_is_loaded
from lss.lib.registry import Control, CheckResult, RollbackEntry, register

# Kernel modules that should be disabled per CIS 1.1.1.x
DISABLED_MODULES = [
    ("1.1.1.1", "cramfs"),
    ("1.1.1.2", "freevxfs"),
    ("1.1.1.3", "jffs2"),
    ("1.1.1.4", "hfs"),
    ("1.1.1.5", "hfsplus"),
    ("1.1.1.6", "udf"),
]


def _disable_module(mod: str) -> list[RollbackEntry]:
    """Disable a kernel module by blacklisting and install-nulling it."""
    from pathlib import Path
    from lss.lib import journal

    conf_path = f"/etc/modprobe.d/lss-{mod}.conf"
    bkp = journal.backup_file(conf_path)
    Path(conf_path).write_text(f"install {mod} /bin/true\nblacklist {mod}\n")

    # Unload if currently loaded
    subprocess.run(["rmmod", mod], capture_output=True)

    return [RollbackEntry(
        action=f"disabled kernel module {mod}",
        path=conf_path,
        backup=bkp,
        undo=[] if bkp else [["rm", "-f", conf_path]],
    )]


# Register each filesystem module control
for _id, _mod in DISABLED_MODULES:
    mod = _mod  # capture for closure

    def _make_check(m):
        def check():
            if module_is_disabled(m):
                return CheckResult("pass")
            return CheckResult("fail", f"{m} is not disabled")
        return check

    def _make_fix(m):
        def fix():
            return _disable_module(m)
        return fix

    register(Control(
        id=_id,
        title=f"Ensure mounting of {mod} is disabled",
        section="filesystem",
        check=_make_check(mod),
        fix=_make_fix(mod),
    ))
