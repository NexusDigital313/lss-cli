# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file, 
# via any medium, is strictly prohibited without explicit written authorization.

"""CIS Section 1.4 / 2.1 — Boot settings and time synchronization."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

from lss.lib.registry import Control, CheckResult, RollbackEntry, register


# ---- CIS 1.4.2: Ensure bootloader password is set ----

_GRUB_CFGS = ("/boot/grub/grub.cfg", "/boot/grub2/grub.cfg")


def _grub_var_value(user_cfg: Path, name: str) -> str:
    """Value of `name` as assigned in GRUB's user.cfg (last assignment wins,
    as `source` runs it top to bottom). Raises OSError if unreadable."""
    value = ""
    for line in user_cfg.read_text().splitlines():
        s = line.strip()
        if s.startswith("set "):
            s = s[4:].lstrip()
        key, sep, val = s.partition("=")
        if sep and key.strip() == name:
            value = val.strip().strip("'\"")
    return value


def _check_bootloader_password() -> CheckResult:
    # GRUB2 check
    for grub_cfg in _GRUB_CFGS:
        p = Path(grub_cfg)
        if p.exists():
            try:
                text = p.read_text()
            except OSError:
                return CheckResult("warn", f"{grub_cfg} exists but could not be read")
            # A real GRUB password needs BOTH a password directive AND a
            # superusers line. Substring-matching "password" false-passes on
            # comments/help text in grub.cfg (a security control reporting
            # compliant when it isn't), so match the actual directives.
            lines = [l.strip() for l in text.splitlines()]
            has_superusers = any(l.startswith("set superusers") for l in lines)
            pw_values = [
                toks[2] for toks in (l.split() for l in lines)
                if len(toks) >= 3 and toks[0] in ("password_pbkdf2", "password")
            ]
            fail = CheckResult(
                "fail",
                "no bootloader password in grub.cfg. Run `grub-mkpasswd-pbkdf2`, "
                "add the hash to /etc/grub.d/40_custom as `password_pbkdf2 root <hash>` "
                "with a `set superusers=\"root\"` line above it, then `update-grub` "
                "(RHEL: `grub2-setpassword`).",
            )
            if not (has_superusers and pw_values):
                return fail
            if any(not v.startswith("$") for v in pw_values):
                return CheckResult("pass")
            # Every password is a variable reference. RHEL's /etc/grub.d/01_users
            # writes `password_pbkdf2 root ${GRUB2_PASSWORD}` and
            # `set superusers="root"` into EVERY grub.cfg, guarded at boot by
            # `if [ -n "${GRUB2_PASSWORD}" ]` after sourcing user.cfg; the
            # password only exists if user.cfg sets that variable.
            user_cfg = p.parent / "user.cfg"
            if not user_cfg.exists():
                return CheckResult(
                    "fail",
                    f"{grub_cfg} references a password variable but {user_cfg} does not exist "
                    "— no bootloader password is set. Run `grub2-setpassword`.",
                )
            for v in pw_values:
                name = v.lstrip("$").strip("{}")
                try:
                    value = _grub_var_value(user_cfg, name)
                except OSError:
                    return CheckResult("warn", f"{user_cfg} could not be read — cannot verify bootloader password")
                if value:
                    return CheckResult("pass")
            return CheckResult(
                "fail",
                f"{user_cfg} does not set the password variable grub.cfg references "
                "— no bootloader password is set. Run `grub2-setpassword`.",
            )
    return CheckResult("warn", "grub.cfg not found")


register(Control(
    id="1.4.2",
    title="Ensure bootloader password is set",
    section="boot",
    level=1,
    check=_check_bootloader_password,
    fix=None,  # Interactive — requires grub-mkpasswd-pbkdf2
))


# ---- CIS 1.4.3: Ensure permissions on bootloader config are configured ----

# Root's uid/gid; module-level so tests can point them at the test user.
_ROOT_UID = 0
_ROOT_GID = 0


def _grub_perm_files(grub_cfg: str) -> list[str]:
    """grub.cfg plus, when present, the user.cfg beside it. On RHEL user.cfg
    holds the GRUB2_PASSWORD hash and CIS requires it 0600 root:root too."""
    files = [grub_cfg]
    user_cfg = Path(grub_cfg).parent / "user.cfg"
    if user_cfg.exists():
        files.append(str(user_cfg))
    return files


def _check_grub_perms() -> CheckResult:
    for grub_cfg in _GRUB_CFGS:
        p = Path(grub_cfg)
        if p.exists():
            for f in _grub_perm_files(grub_cfg):
                try:
                    st = os.stat(f)
                except OSError:
                    return CheckResult("warn", f"{f} exists but could not be stat'd")
                mode = stat.S_IMODE(st.st_mode)
                if mode & ~0o600:
                    return CheckResult("fail", f"{f} mode={oct(mode)}, expected: 0600 or stricter")
                if st.st_uid != _ROOT_UID or st.st_gid != _ROOT_GID:
                    return CheckResult("fail", f"{f} owner={st.st_uid}:{st.st_gid}")
            return CheckResult("pass")
    return CheckResult("warn", "grub.cfg not found")


def _fix_grub_perms() -> list[RollbackEntry]:
    for grub_cfg in _GRUB_CFGS:
        p = Path(grub_cfg)
        if p.exists():
            entries = []
            for f in _grub_perm_files(grub_cfg):
                st = os.stat(f)
                old_mode_str = f"{stat.S_IMODE(st.st_mode):04o}"
                old_uid = st.st_uid
                old_gid = st.st_gid
                os.chmod(f, 0o600)
                os.chown(f, _ROOT_UID, _ROOT_GID)
                entries.append(RollbackEntry(
                    action=f"set {f} to 0600 root:root",
                    undo=[
                        ["chmod", old_mode_str, f],
                        ["chown", f"{old_uid}:{old_gid}", f],
                    ],
                    path=f,
                ))
            return entries
    return []


register(Control(
    id="1.4.3",
    title="Ensure permissions on bootloader config are configured",
    section="boot",
    check=_check_grub_perms,
    fix=_fix_grub_perms,
))


# ---- CIS 1.4.4: Ensure authentication required for single user mode ----

_SHADOW = "/etc/shadow"


def _check_single_user_auth() -> CheckResult:
    # Check if root has a password set
    shadow = Path(_SHADOW)
    if not shadow.exists():
        return CheckResult("warn", "/etc/shadow not found")
    try:
        shadow_text = shadow.read_text()
    except OSError:
        return CheckResult("warn", "/etc/shadow could not be read — cannot verify root password")
    for line in shadow_text.splitlines():
        parts = line.split(":")
        if parts[0] == "root":
            pw = parts[1] if len(parts) > 1 else ""
            # CIS audit: `grep -Eq '^root:\$(y|[0-9])' /etc/shadow`. Only a
            # crypt hash is a password; a deny-list of "*", "!", "!!" passed
            # other locked forms such as "!*" and the `passwd -l` "!$6$...".
            if pw.startswith("$"):
                return CheckResult("pass")
            return CheckResult(
                "fail",
                "root has no password (single-user mode would drop to a root shell with no challenge). "
                "Set one with `sudo passwd root` — or lock the account and rely on sulogin by editing "
                "/usr/lib/systemd/system/rescue.service to `ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue`.",
            )
    return CheckResult("fail", "root not found in /etc/shadow")


register(Control(
    id="1.4.4",
    title="Ensure authentication required for single user mode",
    section="boot",
    check=_check_single_user_auth,
    fix=None,  # Interactive — requires passwd
))


# ---- CIS 2.1.1: Ensure time synchronization is in use ----

_TIME_SYNC_SERVICES = ("chronyd", "chrony", "systemd-timesyncd", "ntpd", "ntp", "ntpsec")


def _systemctl(verb: str, svc: str) -> str:
    """stdout of `systemctl <verb> <svc>`, stripped. FileNotFoundError
    propagates when systemctl is missing."""
    r = subprocess.run(["systemctl", verb, svc], capture_output=True, text=True)
    return r.stdout.strip()


def _time_sync_state() -> tuple[str | None, str | None]:
    """(enabled_and_active, active_only): the first time-sync unit that is
    both active and enabled at boot, else the first that is merely active.

    Every candidate name is queried because Debian's chrony.service carries
    the alias chronyd.service: `is-active chronyd` reports the real unit's
    state, but `is-enabled chronyd` prints "alias", not "enabled"."""
    active_only = None
    for svc in _TIME_SYNC_SERVICES:
        if _systemctl("is-active", svc) != "active":
            continue
        if _systemctl("is-enabled", svc) == "enabled":
            return svc, None
        active_only = active_only or svc
    return None, active_only


def _check_time_sync() -> CheckResult:
    # CIS (chrony / systemd-timesyncd "is enabled and running") requires the
    # daemon to be BOTH active now and enabled at boot. Checking is-active
    # alone passed a daemon started by hand but disabled, which stops at the
    # next reboot and leaves the clock unsynchronised.
    try:
        ok, active_only = _time_sync_state()
    except FileNotFoundError:
        return CheckResult("warn", "systemctl not found — cannot verify time synchronization")
    if ok:
        return CheckResult("pass", f"{ok} is active and enabled")
    if active_only:
        return CheckResult(
            "fail",
            f"{active_only} is active but not enabled at boot — run `systemctl enable {active_only}`",
        )
    return CheckResult("fail", "no time synchronization service running")


def _fix_time_sync() -> list[RollbackEntry]:
    entries = []
    try:
        ok, active_only = _time_sync_state()
    except FileNotFoundError:
        return entries
    if ok:
        return entries
    if active_only:
        # A daemon is already running but disabled at boot: enable that one
        # rather than starting systemd-timesyncd, which conflicts with it.
        r = subprocess.run(["systemctl", "enable", active_only],
                           capture_output=True, text=True)
        if r.returncode == 0:
            entries.append(RollbackEntry(
                action=f"enabled {active_only} at boot",
                undo=[["systemctl", "disable", active_only]],
            ))
        return entries
    # Try to enable systemd-timesyncd (most universally available)
    r = subprocess.run(["systemctl", "enable", "--now", "systemd-timesyncd"],
                       capture_output=True, text=True)
    if r.returncode == 0:
        entries.append(RollbackEntry(
            action="enabled systemd-timesyncd",
            undo=[["systemctl", "disable", "--now", "systemd-timesyncd"]],
        ))
    return entries


register(Control(
    id="2.1.1",
    title="Ensure time synchronization is in use",
    section="boot",
    check=_check_time_sync,
    fix=_fix_time_sync,
))


# ---- CIS 2.1.2: Ensure chrony is configured (if chrony is in use) ----

def _chrony_conf_path() -> Path | None:
    for conf in ["/etc/chrony/chrony.conf", "/etc/chrony.conf"]:
        p = Path(conf)
        if p.exists():
            return p
    return None


def _has_ntp_source(text: str) -> bool:
    """True iff chrony.conf has an UNCOMMENTED `server` or `pool` directive
    with a value — the CIS 2.1.2 audit's `^\\h*(server|pool)\\h+[^#\\n\\r]+`.

    The old `"server" in text or "pool" in text` substring test false-passed
    on commented examples like `# pool 2.debian.pool.ntp.org iburst`, which
    are ubiquitous in shipped chrony.conf, and on any prose comment mentioning
    a server — reporting a time source configured when chrony had none.
    Matching the first token exactly also rejects chrony's other comment
    leaders (`!`, `;`, `%`)."""
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        toks = s.split()
        if len(toks) >= 2 and toks[0] in ("server", "pool") and not toks[1].startswith("#"):
            return True
    return False


def _check_chrony_config() -> CheckResult:
    # Only relevant if chrony is the active time sync
    try:
        r = subprocess.run(["systemctl", "is-active", "chronyd"], capture_output=True, text=True)
        if r.stdout.strip() != "active":
            r2 = subprocess.run(["systemctl", "is-active", "chrony"], capture_output=True, text=True)
            if r2.stdout.strip() != "active":
                return CheckResult("pass", "chrony not in use")
    except FileNotFoundError:
        return CheckResult("warn", "systemctl not found — cannot verify chrony status")

    p = _chrony_conf_path()
    if p is None:
        return CheckResult("warn", "chrony config not found")
    try:
        text = p.read_text()
    except OSError:
        return CheckResult("warn", f"{p} could not be read")
    if _has_ntp_source(text):
        return CheckResult("pass")
    return CheckResult("fail", f"no server/pool configured in {p}")


_CHRONY_DEFAULT_POOLS = """\

# Added by LSS to satisfy CIS 2.1.2 — NTP sources are required for chrony to
# steer the clock. Replace with organizationally-approved servers if needed.
pool 2.pool.ntp.org iburst
pool time.nist.gov iburst
"""


def _fix_chrony_config() -> list[RollbackEntry]:
    """Append public NTP pool entries if chrony.conf has none.

    Operators with internal time sources should replace these with their own
    servers — the default is a safe starting point, not a policy statement.
    """
    p = _chrony_conf_path()
    if p is None:
        return []
    from lss.lib import journal as _j
    bkp = _j.backup_file(str(p))
    text = p.read_text()
    # Same predicate as the check: commented `# pool` examples must not stop
    # the fix from appending real sources.
    if _has_ntp_source(text):
        return []
    p.write_text(text.rstrip() + _CHRONY_DEFAULT_POOLS)
    return [RollbackEntry(
        action=f"appended default NTP pool entries to {p}",
        path=str(p),
        backup=bkp,
    )]


register(Control(
    id="2.1.2",
    title="Ensure chrony is configured",
    section="boot",
    check=_check_chrony_config,
    fix=_fix_chrony_config,
))
