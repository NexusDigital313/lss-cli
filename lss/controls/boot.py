"""CIS Section 1.4 / 2.1 — Boot settings and time synchronization."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

from lss.lib.registry import Control, CheckResult, RollbackEntry, register


# ---- CIS 1.4.2: Ensure bootloader password is set ----

def _check_bootloader_password() -> CheckResult:
    # GRUB2 check
    for grub_cfg in ["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"]:
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
            has_pw = any(
                l.strip().startswith(("password_pbkdf2 ", "password "))
                for l in text.splitlines()
            )
            has_superusers = any(
                l.strip().startswith("set superusers") for l in text.splitlines()
            )
            if has_pw and has_superusers:
                return CheckResult("pass")
            return CheckResult(
                "fail",
                "no bootloader password in grub.cfg. Run `grub-mkpasswd-pbkdf2`, "
                "add the hash to /etc/grub.d/40_custom as `password_pbkdf2 root <hash>` "
                "with a `set superusers=\"root\"` line above it, then `update-grub`.",
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

def _check_grub_perms() -> CheckResult:
    for grub_cfg in ["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"]:
        p = Path(grub_cfg)
        if p.exists():
            try:
                st = p.stat()
            except OSError:
                return CheckResult("warn", f"{grub_cfg} exists but could not be stat'd")
            mode = stat.S_IMODE(st.st_mode)
            if mode & ~0o600:
                return CheckResult("fail", f"{grub_cfg} mode={oct(mode)}, expected: 0600 or stricter")
            if st.st_uid != 0 or st.st_gid != 0:
                return CheckResult("fail", f"{grub_cfg} owner={st.st_uid}:{st.st_gid}")
            return CheckResult("pass")
    return CheckResult("warn", "grub.cfg not found")


def _fix_grub_perms() -> list[RollbackEntry]:
    for grub_cfg in ["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"]:
        p = Path(grub_cfg)
        if p.exists():
            st = p.stat()
            old_mode_str = f"{stat.S_IMODE(st.st_mode):04o}"
            old_uid = st.st_uid
            old_gid = st.st_gid
            os.chmod(grub_cfg, 0o600)
            os.chown(grub_cfg, 0, 0)
            return [RollbackEntry(
                action=f"set {grub_cfg} to 0600 root:root",
                undo=[
                    ["chmod", old_mode_str, grub_cfg],
                    ["chown", f"{old_uid}:{old_gid}", grub_cfg],
                ],
                path=grub_cfg,
            )]
    return []


register(Control(
    id="1.4.3",
    title="Ensure permissions on bootloader config are configured",
    section="boot",
    check=_check_grub_perms,
    fix=_fix_grub_perms,
))


# ---- CIS 1.4.4: Ensure authentication required for single user mode ----

def _check_single_user_auth() -> CheckResult:
    # Check if root has a password set
    shadow = Path("/etc/shadow")
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
            if pw and pw not in ("*", "!", "!!"):
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

def _check_time_sync() -> CheckResult:
    # Check for chrony, systemd-timesyncd, or ntpd
    for svc in ["chronyd", "chrony", "systemd-timesyncd", "ntpd", "ntp"]:
        try:
            r = subprocess.run(["systemctl", "is-active", svc], capture_output=True, text=True)
        except FileNotFoundError:
            return CheckResult("warn", "systemctl not found — cannot verify time synchronization")
        if r.stdout.strip() == "active":
            return CheckResult("pass", f"{svc} is active")
    return CheckResult("fail", "no time synchronization service running")


def _fix_time_sync() -> list[RollbackEntry]:
    # Try to enable systemd-timesyncd (most universally available)
    entries = []
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
    if "server" in text or "pool" in text:
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
    if "server" in text or "pool" in text:
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
