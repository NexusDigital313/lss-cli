# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file, 
# via any medium, is strictly prohibited without explicit written authorization.

"""CIS Section 1.1 — Filesystem configuration."""

import subprocess
from pathlib import Path

from lss.lib import kmod
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


# Register each filesystem module control
for _id, _mod in DISABLED_MODULES:
    mod = _mod  # capture for closure

    def _make_check(m):
        def check():
            # Shared CIS "not available" test: install-nulled AND
            # blacklisted AND not loaded, or absent from the kernel tree.
            return kmod.check_disabled(m)
        return check

    def _make_fix(m):
        def fix():
            return kmod.disable_module(m)
        return fix

    register(Control(
        id=_id,
        title=f"Ensure mounting of {mod} is disabled",
        section="filesystem",
        check=_make_check(mod),
        fix=_make_fix(mod),
    ))
