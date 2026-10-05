# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file, 
# via any medium, is strictly prohibited without explicit written authorization.

"""Shared sshd_config helpers for control fixes."""

from __future__ import annotations

import glob
import re
import shutil
import socket
import subprocess
from pathlib import Path

from lss.lib import journal
from lss.lib.registry import CheckResult, RollbackEntry

# Legacy shared drop-in — kept only so rollback of pre-1.0.2 journals (which
# recorded this path) still resolves. New writes use a per-key file (see
# _conf_path_for) so rolling back one SSH control never disturbs another's.
LSS_SSHD_CONF = "/etc/ssh/sshd_config.d/80-lss.conf"
SSHD_CONFIG = "/etc/ssh/sshd_config"
SSHD_CONFIG_D = "/etc/ssh/sshd_config.d"


def _conf_path_for(key: str) -> str:
    """Per-key LSS drop-in path, e.g. PermitRootLogin -> 80-lss-permitrootlogin.conf.

    One directive per file means each SSH control owns exactly one file, so its
    backup/restore/remove on rollback can't clobber another control's setting.
    """
    safe = re.sub(r"[^a-z0-9]", "", key.lower())
    return f"{SSHD_CONFIG_D}/80-lss-{safe}.conf"


def _sshd_dump(args: list[str]) -> str | None:
    try:
        r = subprocess.run(["sshd", "-T", *args], capture_output=True, text=True)
    except (FileNotFoundError, OSError):
        return None
    return r.stdout if r.returncode == 0 else None


def get_sshd_setting(key: str) -> str | None:
    """Return the effective sshd setting via `sshd -T`. None if unavailable.

    Plain `sshd -T` applies no Match blocks at all, so a `Match User root` /
    `Match Address ...` block re-enabling a setting was invisible. Resolve with
    a connection spec for a local root login (older OpenSSH needs user, host
    and addr together); Match blocks keyed on other users/addresses can't be
    hit by one spec, so checks also scan the config with `match_override_result`.
    Falls back to plain `sshd -T` only if `-C` is rejected; a failing `sshd -T`
    returns None, never a value.
    """
    spec = f"user=root,host={socket.gethostname() or 'localhost'},addr=127.0.0.1"
    out = _sshd_dump(["-C", spec])
    if out is None:
        out = _sshd_dump([])
    if out is None:
        return None
    for line in out.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and parts[0].lower() == key.lower():
            return parts[1]
    return None


def _include_targets(token: str) -> list[Path]:
    base = Path(SSHD_CONFIG).parent
    pattern = token if token.startswith("/") else str(base / token)
    return [Path(p) for p in sorted(glob.glob(pattern)) if Path(p).is_file()]


def match_block_settings(key: str) -> list[tuple[str, str]] | None:
    """Every value `key` is given inside a Match block, as (criteria, value).

    Follows sshd_config and its Include'd files (an Include inside a Match
    block inherits that Match; a Match ends at the next Match or end of file,
    `Match all` returns to global scope). Without a main config, falls back to
    the drop-in dir. Returns None if a config file could not be read.
    """
    key_l = key.lower()
    found: list[tuple[str, str]] = []
    seen: set[str] = set()

    def walk(path: Path, ctx: str | None, depth: int) -> bool:
        if depth > 16 or str(path) in seen:
            return True
        seen.add(str(path))
        try:
            text = path.read_text()
        except OSError:
            return False
        cur = ctx
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = re.split(r"[\s=]+", line, maxsplit=1)
            kw = parts[0].lower()
            arg = parts[1].strip() if len(parts) > 1 else ""
            if kw == "match":
                cur = None if arg.lower() == "all" else arg
            elif kw == "include":
                for tok in arg.split():
                    for inc in _include_targets(tok.strip('"')):
                        if not walk(inc, cur, depth + 1):
                            return False
            elif kw == key_l and cur is not None:
                found.append((cur, arg.strip('"')))
        return True

    main = Path(SSHD_CONFIG)
    if main.exists():
        roots = [main]
    else:
        d = Path(SSHD_CONFIG_D)
        roots = sorted(d.glob("*.conf")) if d.is_dir() else []
    for f in roots:
        if not walk(f, None, 0):
            return None
    return found


def match_override_result(key: str, evaluate) -> CheckResult | None:
    """Run a check's value test over every Match-block value of `key`.

    Returns a fail (or warn) naming the Match block that sets a non-compliant
    value, a warn if the config could not be read, or None when every
    Match-scoped value of `key` passes.
    """
    overrides = match_block_settings(key)
    if overrides is None:
        return CheckResult("warn", f"could not read sshd config files to check Match blocks for {key}")
    soft = None
    for crit, val in overrides:
        r = evaluate(val)
        if r.status == "pass":
            continue
        msg = f"Match {crit}: {key} {val}" + (f" ({r.detail})" if r.detail else "")
        if r.status == "fail":
            return CheckResult("fail", msg)
        soft = soft or CheckResult(r.status, msg)
    return soft


def sshd_seconds(val: str) -> int | None:
    """Parse an sshd_config time value ("300", "5m", "1h30m") to seconds."""
    v = val.strip().lower()
    if v.isdigit():
        return int(v)
    parts = re.findall(r"(\d+)([smhdw]?)", v)
    if not parts or "".join(n + u for n, u in parts) != v:
        return None
    mult = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    return sum(int(n) * mult[u] for n, u in parts)


def audit_sshd(key: str, value: str | None, evaluate) -> CheckResult:
    """Evaluate an effective `sshd -T` value, then every Match-block value."""
    if value is None:
        return CheckResult("warn", "could not read sshd config")
    res = evaluate(value)
    if res.status != "pass":
        return res
    return match_override_result(key, evaluate) or res


def setting_in_global_scope(key: str) -> bool | None:
    """Check whether `key` is set in the global (non-Match) section of any
    sshd config file.

    Returns:
        True   — key has a global setting (whatever the value)
        False  — key is only set inside Match blocks (or not set at all)
        None   — sshd config files unreadable / non-existent

    A control that finds the effective value is correct via `get_sshd_setting`
    but `setting_in_global_scope` returns False should warn the operator that
    the value only applies to the matched scope, not all users.
    """
    files: list[Path] = []
    main = Path(SSHD_CONFIG)
    if main.exists():
        files.append(main)
    d = Path(SSHD_CONFIG_D)
    if d.is_dir():
        files.extend(sorted(d.glob("*.conf")))

    if not files:
        return None

    found_global = False
    key_l = key.lower()
    for f in files:
        try:
            in_match = False
            for raw in f.read_text().splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.lower().startswith("match "):
                    in_match = True
                    continue
                if in_match:
                    continue
                first = line.split(None, 1)[0].lower()
                if first == key_l:
                    found_global = True
                    break
            if found_global:
                break
        except OSError:
            continue

    return found_global


# ---------------------------------------------------------------------------
# SSH safety layer.  UNVERIFIED on a live host — verify on a throwaway Debian
# VM (see PRE_LAUNCH_TEST_PLAN.md) before trusting on any real server.
# ---------------------------------------------------------------------------
def validate_sshd() -> tuple[bool, str]:
    """Run `sshd -t`. Returns (ok, message). ok=True if sshd is absent (we
    simply can't validate then) so non-Linux/dev environments don't error."""
    try:
        r = subprocess.run(["sshd", "-t"], capture_output=True, text=True)
        if r.returncode == 0:
            return True, "ok"
        msg = (r.stderr or r.stdout or "sshd -t failed").strip()
        return False, msg.splitlines()[-1] if msg else "sshd -t failed"
    except FileNotFoundError:
        return True, "sshd not found — validation skipped"


def reload_sshd() -> bool:
    """Best-effort reload so the change takes effect on the running daemon.
    Reload (not restart) preserves existing SSH sessions. Debian unit is `ssh`,
    RHEL is `sshd`."""
    for unit in ("ssh", "sshd"):
        try:
            r = subprocess.run(["systemctl", "reload", unit], capture_output=True, text=True)
            if r.returncode == 0:
                return True
        except FileNotFoundError:
            break
    return False


def _include_present() -> bool:
    """True if sshd_config actually Includes the drop-in dir (else 80-lss.conf
    is silently ignored). True when there's no main config to gate it."""
    main = Path(SSHD_CONFIG)
    try:
        if not main.exists():
            return True
        for raw in main.read_text().splitlines():
            s = raw.strip()
            if s and not s.startswith("#") and s.lower().startswith("include ") and "sshd_config.d" in s:
                return True
    except OSError:
        return True
    return False


def _shadow_password_usable(name: str) -> bool:
    """True if `name` has a usable password hash in /etc/shadow.

    A locked (`!`/`*`-prefixed), empty, or absent field means the account
    cannot log in by password. Parses /etc/shadow directly rather than via the
    `spwd` module, which was removed in Python 3.13. Returns False if the file
    is unreadable (we then fall back to the SSH-key check)."""
    try:
        for line in Path("/etc/shadow").read_text().splitlines():
            parts = line.split(":")
            if parts and parts[0] == name:
                h = parts[1] if len(parts) > 1 else ""
                # "" = no password (login blocked unless PermitEmptyPasswords);
                # "!"/"*" prefixes = locked. Only a real hash is usable.
                return bool(h) and not h.startswith("!") and not h.startswith("*")
    except OSError:
        pass
    return False


def _has_authorized_keys(home: str) -> bool:
    """True if `home` has a non-empty SSH authorized_keys file."""
    if not home:
        return False
    for fname in ("authorized_keys", "authorized_keys2"):
        akf = Path(home) / ".ssh" / fname
        try:
            if akf.is_file() and akf.read_text().strip():
                return True
        except OSError:
            continue
    return False


def has_non_root_admin() -> bool:
    """True if a non-root account is in the sudo/wheel group, has a real login
    shell, AND can actually authenticate (a usable password hash OR SSH
    authorized_keys). Used to refuse `PermitRootLogin no` when root is the only
    way in (cloud root-only images) — applying it there is a permanent lockout.

    Group membership and a login shell alone are NOT enough: a stock image may
    ship an `admin`/`deploy` account in sudo with a valid shell but a locked
    password and no SSH keys, which cannot log in — disabling root SSH would
    still strand the operator."""
    try:
        import grp
        import pwd
    except ImportError:
        return False
    members: set[str] = set()
    for group in ("sudo", "wheel"):
        try:
            members |= set(grp.getgrnam(group).gr_mem)
        except KeyError:
            continue
    bad_shells = {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", ""}
    for name in members:
        if name == "root":
            continue
        try:
            pw = pwd.getpwnam(name)
        except KeyError:
            continue
        if pw.pw_shell in bad_shells:
            continue
        # Must be able to authenticate by SOME means, or it's not a real way in.
        if _shadow_password_usable(name) or _has_authorized_keys(pw.pw_dir):
            return True
    return False


def set_sshd_setting(key: str, value: str) -> RollbackEntry:
    """Set an sshd config value via the LSS drop-in, validated before it sticks.

    Writes the value, runs `sshd -t`, and if validation FAILS reverts the
    drop-in and raises — so a malformed config never persists or gets reloaded
    (the old behaviour left a broken file that bricked sshd at next reboot and
    reported only a soft warning). On success, reloads sshd so the change
    actually takes effect (live sessions are preserved). Warns if sshd_config
    doesn't Include the drop-in dir, since the setting would otherwise be a
    silent no-op.

    UNVERIFIED on a live host — verify on a throwaway Debian VM.
    """
    from lss.lib.output import warn

    # One directive per file: rolling back this control removes/restores only
    # its own file, never a shared file holding every SSH control's settings.
    p = Path(_conf_path_for(key))
    p.parent.mkdir(parents=True, exist_ok=True)
    bkp = journal.backup_file(str(p))

    p.write_text(f"{key} {value}\n")
    p.chmod(0o600)

    ok, msg = validate_sshd()
    if not ok:
        # Revert so a bad config never survives this call.
        if bkp:
            shutil.copy2(bkp, str(p))
        else:
            p.unlink(missing_ok=True)
        raise RuntimeError(f"sshd config invalid after setting {key}={value} — reverted ({msg})")

    if _include_present():
        # If the reload fails, the on-disk config is right but the RUNNING
        # daemon still enforces the old value. The post-fix verify reads
        # `sshd -T` (on-disk config), so it would report success while the live
        # daemon is unchanged — surface the gap instead of hiding it.
        if not reload_sshd():
            warn(f"wrote and validated '{key} {value}' but could not reload sshd — "
                 f"the running daemon keeps the old value until you run "
                 f"`sudo systemctl reload ssh` (or reboot).")
    else:
        warn(f"sshd_config does not Include {SSHD_CONFIG_D}/*.conf — '{key} {value}' "
             f"is written but won't take effect until you add "
             f"'Include /etc/ssh/sshd_config.d/*.conf' to {SSHD_CONFIG}.")

    return RollbackEntry(
        action=f"set sshd {key} = {value}",
        path=str(p),
        backup=bkp,
        undo=[] if bkp else [["rm", "-f", str(p)]],
    )
