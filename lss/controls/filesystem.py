"""CIS Section 1.1 — Filesystem configuration."""

import subprocess

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


def _module_is_disabled(mod: str) -> bool:
    """Check if a kernel module is disabled via modprobe."""
    try:
        result = subprocess.run(
            ["modprobe", "-n", "--show-depends", mod],
            capture_output=True, text=True,
        )
        # If modprobe says "install /bin/true" or "install /bin/false", it's disabled
        if "/bin/true" in result.stdout or "/bin/false" in result.stdout:
            return True
    except FileNotFoundError:
        pass

    # Also check if it's currently loaded
    try:
        result = subprocess.run(
            ["lsmod"], capture_output=True, text=True,
        )
        if mod in result.stdout:
            return False
    except FileNotFoundError:
        pass

    # Check blacklist
    try:
        result = subprocess.run(
            ["grep", "-r", f"blacklist {mod}", "/etc/modprobe.d/"],
            capture_output=True, text=True,
        )
        if result.returncode == 0 and result.stdout.strip():
            return True
    except FileNotFoundError:
        pass

    return False


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
            if _module_is_disabled(m):
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
