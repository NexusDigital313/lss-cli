# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file,
# via any medium, is strictly prohibited without explicit written authorization.

"""Shared kernel-module "not available" logic for the CIS module controls.

CIS treats a module as not available when either
  - it is not present in the running kernel's module tree at all, or
  - modprobe config carries BOTH `install <mod> /bin/false|/bin/true` AND
    `blacklist <mod>`, and the module is not loaded.

A blacklist alone only stops alias-based autoload; a dependency or an explicit
`modprobe` still loads the module (the DCCP socket alias belongs to dccp_ipv4,
which pulls in dccp). So blacklist-only is NOT disabled.

modprobe treats '-' and '_' as the same character (lsmod prints underscores),
so every name is normalised before comparison. The merged config comes from
`modprobe --showconfig` when it works; otherwise the *.conf files are parsed
the way kmod reads them (only *.conf, earlier directory overrides a same-named
file in a later one, files applied in basename order). State that cannot be
read is reported as unknown, never as disabled.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from lss.lib import journal
from lss.lib.registry import CheckResult, RollbackEntry

# kmod's search order; a file in an earlier directory masks a same-named file
# in a later one.
MODPROBE_DIRS = [
    "/etc/modprobe.d",
    "/run/modprobe.d",
    "/usr/local/lib/modprobe.d",
    "/usr/lib/modprobe.d",
    "/lib/modprobe.d",
]
MODULES_ROOT = "/lib/modules"
PROC_MODULES = "/proc/modules"

NULL_INSTALL = ("/bin/false", "/bin/true", "/usr/bin/false", "/usr/bin/true")


def normalize(name: str) -> str:
    """modprobe's name equivalence: '-' and '_' are the same."""
    return name.replace("-", "_")


def _kernel_release() -> str:
    return os.uname().release


def loaded_modules() -> set[str] | None:
    """Normalised names of loaded modules, or None if that can't be read."""
    try:
        r = subprocess.run(["lsmod"], capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            return {normalize(line.split()[0])
                    for line in r.stdout.splitlines()[1:] if line.split()}
    except (FileNotFoundError, OSError):
        pass
    # lsmod is a thin reader of /proc/modules; read it directly as a fallback.
    try:
        text = Path(PROC_MODULES).read_text()
    except OSError:
        return None
    return {normalize(line.split()[0]) for line in text.splitlines() if line.split()}


def module_present(mod: str) -> str | None:
    """Where `mod` lives in the running kernel's tree.

    Returns "module" (a loadable .ko exists), "builtin" (compiled in, so it
    can never be disabled), "absent" (not in the tree at all), or None when
    the tree can't be read.
    """
    want = normalize(mod)
    tree = Path(MODULES_ROOT) / _kernel_release()
    if not tree.is_dir():
        return None

    def _stem(path: str) -> str:
        base = path.strip().rsplit("/", 1)[-1]
        i = base.find(".ko")
        return normalize(base[:i] if i >= 0 else base)

    try:
        builtin = tree / "modules.builtin"
        if builtin.is_file():
            if any(_stem(l) == want for l in builtin.read_text().splitlines() if l.strip()):
                return "builtin"
        dep = tree / "modules.dep"
        if dep.is_file():
            names = {_stem(l.split(":", 1)[0]) for l in dep.read_text().splitlines() if ":" in l}
        else:
            names = {_stem(p.name) for p in tree.rglob("*.ko*")}
    except OSError:
        return None
    return "module" if want in names else "absent"


def _parse_lines(lines, blacklist: set[str], install: dict[str, str]) -> None:
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        toks = s.split()
        if toks[0] == "blacklist" and len(toks) >= 2:
            blacklist.add(normalize(toks[1]))
        elif toks[0] == "install" and len(toks) >= 3:
            # kmod uses the FIRST install command that matches a module.
            install.setdefault(normalize(toks[1]), " ".join(toks[2:]))


def _conf_files() -> list[Path] | None:
    """*.conf files kmod would read, in the order it applies them."""
    chosen: dict[str, Path] = {}
    for d in MODPROBE_DIRS:
        p = Path(d)
        try:
            if not p.is_dir():
                continue
            for f in p.iterdir():
                if f.name.endswith(".conf") and f.name not in chosen:
                    chosen[f.name] = f
        except OSError:
            return None
    return [chosen[n] for n in sorted(chosen)]


def modprobe_config() -> tuple[set[str], dict[str, str]] | None:
    """(blacklisted modules, {module: install command}) with normalised names,
    or None if the config can't be read."""
    blacklist: set[str] = set()
    install: dict[str, str] = {}
    try:
        r = subprocess.run(["modprobe", "--showconfig"], capture_output=True, text=True)
        if r.returncode == 0:
            _parse_lines(r.stdout.splitlines(), blacklist, install)
            return blacklist, install
    except (FileNotFoundError, OSError):
        pass
    files = _conf_files()
    if files is None:
        return None
    for f in files:
        try:
            text = f.read_text()
        except OSError:
            return None
        _parse_lines(text.splitlines(), blacklist, install)
    return blacklist, install


def module_state(mod: str) -> tuple[bool | None, str]:
    """(True, why) if `mod` is not available, (False, why) if it is, and
    (None, why) when the state can't be determined."""
    name = normalize(mod)
    loaded = loaded_modules()
    if loaded is None:
        return None, f"cannot verify {mod}: loaded modules unreadable"
    if name in loaded:
        return False, f"{mod} is loaded"

    present = module_present(mod)
    if present == "builtin":
        return False, f"{mod} is built into the kernel and cannot be disabled"
    if present == "absent":
        return True, f"{mod} is not present in the kernel"

    cfg = modprobe_config()
    if cfg is None:
        return None, f"cannot verify {mod}: modprobe config unreadable"
    blacklist, install = cfg
    cmd = install.get(name, "")
    nulled = bool(cmd) and cmd.split()[0] in NULL_INSTALL
    missing = []
    if not nulled:
        missing.append(f"install {mod} /bin/false")
    if name not in blacklist:
        missing.append(f"blacklist {mod}")
    if missing:
        return False, f"{mod} is not disabled (missing: {', '.join(missing)})"
    return True, f"{mod} is install-nulled and blacklisted"


def check_disabled(mod: str) -> CheckResult:
    ok, why = module_state(mod)
    if ok is True:
        return CheckResult("pass")
    if ok is None:
        return CheckResult("warn", why)
    return CheckResult("fail", why)


def disable_module(mod: str) -> list[RollbackEntry]:
    """Write both CIS directives for `mod` and unload it."""
    conf_path = str(Path(MODPROBE_DIRS[0]) / f"lss-{mod}.conf")
    bkp = journal.backup_file(conf_path)
    Path(conf_path).write_text(f"install {mod} /bin/false\nblacklist {mod}\n")
    subprocess.run(["rmmod", mod], capture_output=True)
    return [RollbackEntry(
        action=f"disabled kernel module {mod}",
        path=conf_path,
        backup=bkp,
        undo=[] if bkp else [["rm", "-f", conf_path]],
    )]
