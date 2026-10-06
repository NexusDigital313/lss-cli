# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file,
# via any medium, is strictly prohibited without explicit written authorization.

"""Readers for PAM stacks, pwquality and login.defs that follow the real
parsers' rules, so the auth checks see what PAM and shadow-utils enforce.

- Linux-PAM drops everything from '#' to the end of a line, anywhere on it.
- libpwquality reads /etc/security/pwquality.conf.d/*.conf in ASCII order,
  THEN pwquality.conf; a later value overrides an earlier one
  (pwquality.conf(5)). Arguments on the pam_pwquality.so line override both.
- shadow-utils lets the LAST uncommented occurrence of a login.defs key win.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path


# ---- PAM ----

@dataclass
class PamLine:
    type: str           # auth / account / password / session / @include
    control: str        # required, requisite, [success=1 default=ignore], ...
    module: str         # basename, e.g. pam_unix.so
    args: list[str] = field(default_factory=list)

    def arg(self, key: str) -> str | None:
        """Value of the last `key=value` argument, or None."""
        val = None
        for a in self.args:
            if a.startswith(key + "="):
                val = a[len(key) + 1:]
        return val


def pam_lines(text: str) -> list[PamLine]:
    """Parse a PAM config file into its effective (uncommented) lines."""
    out: list[PamLine] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"(\S+)\s+(\[[^\]]*\]|\S+)\s*(.*)$", line)
        if not m:
            continue
        typ, control, rest = m.group(1).lstrip("-").lower(), m.group(2), m.group(3)
        toks = rest.split()
        module = os.path.basename(toks[0]) if toks else ""
        out.append(PamLine(typ, control.strip(), module, toks[1:]))
    return out


def control_enforces(control: str) -> bool:
    """True if a failure from the module fails the stack (required/requisite,
    or a bracketed control whose auth_err/default action is die/bad)."""
    c = control.strip().lower()
    if c in ("required", "requisite"):
        return True
    if c.startswith("[") and c.endswith("]"):
        acts = dict(kv.split("=", 1) for kv in c[1:-1].split() if "=" in kv)
        return acts.get("auth_err", acts.get("default")) in ("die", "bad")
    return False


# ---- pwquality ----

def _conf_values(text: str, key: str) -> list[str]:
    vals = []
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(rf"^{re.escape(key)}\s*=\s*(\S+)", s)
        if m:
            vals.append(m.group(1))
    return vals


def pwquality_conf_value(key: str, conf: Path, conf_d: Path) -> tuple[str | None, str]:
    """(value, source) after libpwquality's conf.d-then-pwquality.conf order.
    Raises OSError if a file that exists cannot be read."""
    files = sorted(conf_d.glob("*.conf"), key=lambda p: p.name) if conf_d.is_dir() else []
    files.append(conf)
    value, source = None, ""
    for f in files:
        if not f.exists():
            continue
        vals = _conf_values(f.read_text(), key)
        if vals:
            value, source = vals[-1], str(f)
    return value, source


PWQ_MODULES = ("pam_pwquality.so", "pam_cracklib.so")


def pwquality_effective(key: str, conf: Path, conf_d: Path,
                        stacks: list[Path]) -> tuple[list[tuple[str, str | None]], bool]:
    """Effective `key` for each password stack that loads pam_pwquality (or
    pam_cracklib) with an enforcing control: ([(where, value)], True).
    A module argument overrides the conf files; pam_cracklib reads no conf.
    If no stack loads the module: ([(where, conf value)], False).
    Raises OSError when an existing file cannot be read."""
    out: list[tuple[str, str | None]] = []
    for p in stacks:
        if not p.exists():
            continue
        line = next((ln for ln in pam_lines(p.read_text())
                     if ln.type == "password" and ln.module in PWQ_MODULES
                     and control_enforces(ln.control)), None)
        if line is None:
            continue
        arg = line.arg(key)
        if arg is not None:
            out.append((f"{key}={arg} on {line.module} in {p}", arg))
        elif line.module == "pam_cracklib.so":
            out.append((f"{key} not set on pam_cracklib.so in {p}", None))
        else:
            val, src = pwquality_conf_value(key, conf, conf_d)
            out.append((f"{key}={val} in {src}" if val is not None else f"{key} not set", val))
    if out:
        return out, True
    val, src = pwquality_conf_value(key, conf, conf_d)
    return [(f"{key}={val} in {src}" if val is not None else f"{key} not set", val)], False


def set_conf_key(path: Path, key: str, line: str) -> None:
    """Make `line` the only uncommented setting of `key` in a KEY=/KEY VALUE
    file: replace the first uncommented occurrence, drop later ones, append if
    none. Comment lines are never touched."""
    lines = path.read_text().splitlines(keepends=True) if path.exists() else []
    out, done = [], False
    for ln in lines:
        s = ln.strip()
        if s and not s.startswith("#") and re.match(rf"^{re.escape(key)}(\s|=|$)", s):
            if not done:
                out.append(line + "\n")
                done = True
            continue
        out.append(ln)
    if not done:
        if out and not out[-1].endswith("\n"):
            out.append("\n")
        out.append(line + "\n")
    path.write_text("".join(out))


# ---- login.defs ----

def login_defs_value(text: str, key: str) -> str | None:
    """Value of `key` as shadow-utils sees it: the last uncommented occurrence."""
    val = None
    for raw in text.splitlines():
        parts = raw.strip().split()
        if not parts or parts[0].startswith("#"):
            continue
        if parts[0] == key and len(parts) >= 2:
            val = parts[1].strip('"')
    return val


# ---- umask ----

def parse_umask(value: str) -> int | None:
    """Octal or symbolic (u=rwx,g=rx,o=) umask -> mask bits, or None."""
    v = value.strip().strip("\"'")
    if re.fullmatch(r"[0-7]{1,4}", v):
        return int(v, 8)
    if re.fullmatch(r"([ugoa]+=[rwx]*)(,[ugoa]+=[rwx]*)*", v):
        perms = 0o777
        for clause in v.split(","):
            who, _, what = clause.partition("=")
            bits = (4 if "r" in what else 0) | (2 if "w" in what else 0) | (1 if "x" in what else 0)
            for w in ("ugo" if "a" in who else who):
                shift = {"u": 6, "g": 3, "o": 0}[w]
                perms = (perms & ~(7 << shift)) | (bits << shift)
        return 0o777 & ~perms
    return None


def umask_ok(mask: int) -> bool:
    """Compliant when at least 027 is masked (bitwise, not numeric)."""
    return (mask & 0o027) == 0o027
