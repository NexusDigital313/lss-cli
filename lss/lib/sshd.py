"""Shared sshd_config helpers for control fixes."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from lss.lib import journal
from lss.lib.registry import RollbackEntry

LSS_SSHD_CONF = "/etc/ssh/sshd_config.d/80-lss.conf"
SSHD_CONFIG = "/etc/ssh/sshd_config"
SSHD_CONFIG_D = "/etc/ssh/sshd_config.d"


def get_sshd_setting(key: str) -> str | None:
    """Return the effective sshd setting via `sshd -T`. None if unavailable.

    `sshd -T` resolves Match blocks against the *invoking user* (root by
    default), so the result is the value that would apply to a root login. For
    detecting whether the global default is correct vs only the Match-scoped
    value, see `setting_in_global_scope`.
    """
    try:
        r = subprocess.run(["sshd", "-T"], capture_output=True, text=True)
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) == 2 and parts[0].lower() == key.lower():
                    return parts[1]
    except FileNotFoundError:
        pass
    return None


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


def has_non_root_admin() -> bool:
    """True if a non-root account is in the sudo/wheel group AND has a real
    login shell. Used to refuse `PermitRootLogin no` when root is the only way
    in (cloud root-only images) — applying it there is a permanent lockout."""
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
            if pwd.getpwnam(name).pw_shell not in bad_shells:
                return True
        except KeyError:
            continue
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

    p = Path(LSS_SSHD_CONF)
    p.parent.mkdir(parents=True, exist_ok=True)
    bkp = journal.backup_file(str(p))

    existing = p.read_text() if p.exists() else ""
    entry = f"{key} {value}\n"
    lines = existing.splitlines(keepends=True)
    found = False
    for i, line in enumerate(lines):
        # whole-token match — a prefix match would clobber the wrong directive
        # (e.g. setting "MACs" must not overwrite a "MaxAuthTries" line).
        toks = line.strip().split(None, 1)
        if toks and toks[0].lower() == key.lower():
            lines[i] = entry
            found = True
            break
    if not found:
        if lines and not lines[-1].endswith("\n"):
            lines.append("\n")
        lines.append(entry)
    p.write_text("".join(lines))
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
        reload_sshd()
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
