# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file, 
# via any medium, is strictly prohibited without explicit written authorization.

"""CIS Section 1.1 — Filesystem configuration."""

import subprocess
from pathlib import Path

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


def _module_is_loaded(mod: str) -> bool:
    """True if `mod` is currently loaded, matching the module name EXACTLY.

    A substring test would misclassify a prefix module: checking `hfs` while
    `hfsplus` is loaded would (wrongly) report `hfs` as present."""
    try:
        result = subprocess.run(["lsmod"], capture_output=True, text=True)
    except FileNotFoundError:
        return False
    for line in result.stdout.splitlines()[1:]:  # skip the "Module ..." header
        parts = line.split()
        if parts and parts[0] == mod:
            return True
    return False


def _module_blacklisted(mod: str) -> bool:
    """True if an UNCOMMENTED modprobe.d directive disables exactly `mod`.

    Reads the files directly and token-matches so that a `blacklist hfsplus`
    line does not satisfy a check for `hfs`, and a commented-out example line
    is ignored."""
    d = Path("/etc/modprobe.d")
    if not d.is_dir():
        return False
    for conf in d.glob("*"):
        try:
            text = conf.read_text()
        except OSError:
            continue
        for line in text.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            toks = s.split()
            if len(toks) >= 2 and toks[0] == "blacklist" and toks[1] == mod:
                return True
            if (len(toks) >= 3 and toks[0] == "install" and toks[1] == mod
                    and toks[2] in ("/bin/true", "/bin/false")):
                return True
    return False


def _module_is_disabled(mod: str) -> bool:
    """Check if a kernel module is disabled via modprobe install-nulling or a
    blacklist directive, using exact matching throughout."""
    try:
        result = subprocess.run(
            ["modprobe", "-n", "--show-depends", mod],
            capture_output=True, text=True,
        )
        # modprobe emits "install /bin/true" (or /bin/false) for a nulled module.
        for line in result.stdout.splitlines():
            toks = line.split()
            if len(toks) >= 2 and toks[0] == "install" and toks[1] in ("/bin/true", "/bin/false"):
                return True
    except FileNotFoundError:
        pass

    # A currently-loaded module is not disabled, whatever the config says.
    if _module_is_loaded(mod):
        return False

    return _module_blacklisted(mod)


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
