# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file, 
# via any medium, is strictly prohibited without explicit written authorization.

"""Miscellaneous CIS controls — SSH extras, USB storage, prelink, sysrq, etc."""

from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path

from lss.lib import journal
from lss.lib.registry import Control, CheckResult, RollbackEntry, register
from lss.lib.sshd import get_sshd_setting as _get_sshd_setting, set_sshd_setting as _set_sshd_setting, LSS_SSHD_CONF


# ---- CIS 5.2.1: Ensure permissions on /etc/ssh/sshd_config are configured ----

def _check_sshd_config_perms() -> CheckResult:
    import stat
    p = Path("/etc/ssh/sshd_config")
    try:
        st = p.stat()
    except FileNotFoundError:
        return CheckResult("warn", "sshd_config not found")
    except OSError as e:
        return CheckResult("warn", f"could not stat sshd_config: {e}")
    mode = stat.S_IMODE(st.st_mode)
    if mode & ~0o600:
        return CheckResult("fail", f"mode={oct(mode)}, expected: 0600 or stricter")
    if st.st_uid != 0:
        return CheckResult("fail", f"uid={st.st_uid}, expected: 0")
    return CheckResult("pass")


def _fix_sshd_config_perms() -> list[RollbackEntry]:
    import os
    import stat
    p = "/etc/ssh/sshd_config"
    st = Path(p).stat()
    old_mode_str = f"{stat.S_IMODE(st.st_mode):04o}"
    old_uid = st.st_uid
    old_gid = st.st_gid
    os.chmod(p, 0o600)
    os.chown(p, 0, 0)
    return [RollbackEntry(
        action="set /etc/ssh/sshd_config to 0600 root:root",
        undo=[
            ["chmod", old_mode_str, p],
            ["chown", f"{old_uid}:{old_gid}", p],
        ],
        path=p,
    )]


register(Control(
    id="5.2.1",
    title="Ensure permissions on /etc/ssh/sshd_config are configured",
    section="ssh",
    check=_check_sshd_config_perms,
    fix=_fix_sshd_config_perms,
))


# ---- CIS 5.2.10: Ensure SSH UsePAM is enabled ----

def _check_use_pam() -> CheckResult:
    val = _get_sshd_setting("usepam")
    if val is None:
        return CheckResult("warn", "could not read sshd config")
    if val.lower() == "yes":
        return CheckResult("pass")
    return CheckResult("fail", f"UsePAM={val}, recommended: yes")


def _fix_use_pam() -> list[RollbackEntry]:
    return [_set_sshd_setting("UsePAM", "yes")]


register(Control(
    id="5.2.10",
    title="Ensure SSH UsePAM is enabled",
    section="ssh",
    check=_check_use_pam,
    fix=_fix_use_pam,
))


# ---- CIS 5.2.12: Ensure SSH Idle Timeout is not 0 ----

def _eval_ssh_alive_not_zero(interval: str, count: str) -> CheckResult:
    # ClientAliveCountMax 0 disables termination of unresponsive sessions
    # (OpenSSH >= 8.2), so a 0 count is as disabled as a 0 interval.
    from lss.lib.sshd import sshd_seconds
    iv = sshd_seconds(interval)
    try:
        cm = int(count)
    except ValueError:
        cm = None
    if iv is None or cm is None:
        return CheckResult("fail", f"ClientAliveInterval={interval}, ClientAliveCountMax={count}")
    if iv <= 0:
        return CheckResult("fail", "ClientAliveInterval=0 (no timeout)")
    if cm <= 0:
        return CheckResult("fail", "ClientAliveCountMax=0 (idle sessions are never terminated)")
    return CheckResult("pass")


def _check_ssh_alive_not_zero() -> CheckResult:
    from lss.lib.sshd import match_override_result
    interval = _get_sshd_setting("clientaliveinterval")
    count = _get_sshd_setting("clientalivecountmax")
    if interval is None or count is None:
        return CheckResult("warn", "could not read sshd config")
    res = _eval_ssh_alive_not_zero(interval, count)
    if res.status != "pass":
        return res
    return (match_override_result("ClientAliveInterval", lambda v: _eval_ssh_alive_not_zero(v, count))
            or match_override_result("ClientAliveCountMax", lambda v: _eval_ssh_alive_not_zero(interval, v))
            or res)


def _fix_ssh_alive_not_zero() -> list[RollbackEntry]:
    """Restore the CIS-recommended 300s interval / count 3 where either is 0 or unset."""
    from lss.lib.sshd import sshd_seconds
    entries = []
    val = _get_sshd_setting("clientaliveinterval")
    iv = sshd_seconds(val) if val is not None else None
    if not iv:
        entries.append(_set_sshd_setting("ClientAliveInterval", "300"))
    count = _get_sshd_setting("clientalivecountmax")
    try:
        cm = int(count) if count is not None else 0
    except ValueError:
        cm = 0
    if cm <= 0:
        entries.append(_set_sshd_setting("ClientAliveCountMax", "3"))
    return entries


register(Control(
    id="5.2.12",
    title="Ensure SSH idle timeout is not disabled",
    section="ssh",
    check=_check_ssh_alive_not_zero,
    fix=_fix_ssh_alive_not_zero,
))


# ---- CIS 5.2.20: Ensure SSH key exchange algorithms are strong ----

WEAK_KEX = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"}
STRONG_KEX = "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256"


def _check_kex() -> CheckResult:
    val = _get_sshd_setting("kexalgorithms")
    if val is None:
        return CheckResult("warn", "could not read sshd config")
    active = set(val.split(","))
    weak = active & WEAK_KEX
    if weak:
        return CheckResult("fail", f"weak KEX: {','.join(sorted(weak))}")
    return CheckResult("pass")


def _fix_kex() -> list[RollbackEntry]:
    return [_set_sshd_setting("KexAlgorithms", STRONG_KEX)]


register(Control(
    id="5.2.20",
    title="Ensure only strong Key Exchange algorithms are used",
    section="ssh",
    check=_check_kex,
    fix=_fix_kex,
))


# ---- CIS 5.2.21: Ensure SSH GatewayPorts is disabled ----

def _check_gateway_ports() -> CheckResult:
    val = _get_sshd_setting("gatewayports")
    if val is None:
        return CheckResult("warn", "could not read sshd config")
    if val.lower() == "no":
        return CheckResult("pass")
    return CheckResult("fail", f"GatewayPorts={val}")


def _fix_gateway_ports() -> list[RollbackEntry]:
    return [_set_sshd_setting("GatewayPorts", "no")]


register(Control(
    id="5.2.21",
    title="Ensure SSH GatewayPorts is disabled",
    section="ssh",
    check=_check_gateway_ports,
    fix=_fix_gateway_ports,
))


# ---- CIS 1.1.15: Ensure USB storage is disabled ----

def _check_usb_storage() -> CheckResult:
    # Shared CIS "not available" test (lss.lib.kmod): usb-storage must be
    # install-nulled AND blacklisted AND not loaded (lsmod prints it as
    # usb_storage), or absent from the kernel tree. Blacklist alone only stops
    # alias autoload, so it does not count.
    from lss.lib import kmod
    ok, why = kmod.module_state("usb-storage")
    if ok is True:
        return CheckResult("pass")
    if ok is None:
        return CheckResult("warn", why)
    return CheckResult(
        "manual",
        f"{why}. Disable by hand (printf 'install usb-storage /bin/false\\n"
        "blacklist usb-storage\\n' > /etc/modprobe.d/usb-storage.conf). "
        "DO NOT do this on a USB-booted host (e.g. Kali Live) — it can strand the "
        "running filesystem and leave the box unbootable.",
    )


def _fix_usb_storage() -> list[RollbackEntry]:
    from lss.lib import kmod
    return kmod.disable_module("usb-storage")


register(Control(
    id="1.1.15",
    title="Ensure USB storage is disabled",
    section="filesystem",
    check=_check_usb_storage,
    fix=None,  # DEFANGED: rmmod + blacklist usb-storage bricks USB-booted hosts (Kali Live is the flagship target). Apply by hand only on non-USB-booted machines.
))


# ---- CIS 1.3.1: Ensure AIDE is installed ----

def _check_aide_installed() -> CheckResult:
    try:
        r = subprocess.run(["which", "aide"], capture_output=True, text=True)
        if r.returncode == 0:
            return CheckResult("pass")
    except FileNotFoundError:
        pass
    try:
        # -f=${Status} is required: plain `dpkg-query -W` prints only name and
        # version, so the "install ok installed" guard below could never match.
        r2 = subprocess.run(["dpkg-query", "-W", "-f=${Status}", "aide"],
                            capture_output=True, text=True)
        if r2.returncode == 0 and "install ok installed" in r2.stdout:
            return CheckResult("pass")
    except FileNotFoundError:
        pass
    # RHEL
    try:
        r3 = subprocess.run(["rpm", "-q", "aide"], capture_output=True, text=True)
        if r3.returncode == 0:
            return CheckResult("pass")
    except FileNotFoundError:
        pass
    return CheckResult("warn", "AIDE not installed — no file integrity monitoring")


register(Control(
    id="1.3.1",
    title="Ensure AIDE is installed",
    section="filesystem",
    check=_check_aide_installed,
    fix=lambda: _pkg_lib.install("aide"),
))


# ---- CIS 1.3.2: Ensure filesystem integrity is regularly checked ----

# Cron locations scanned for a scheduled AIDE run. Directories named cron.d
# hold crontab-format files read by cron; the others are run-parts
# directories (cron.daily / cron.weekly).
_AIDE_CRON_PATHS = ("/etc/crontab", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.d")

# Debian run-parts (without --lsbsysinit) only runs files named entirely
# [A-Za-z0-9_-]; Debian cron applies the same rule to /etc/cron.d. So
# aide.sh, aide.dpkg-old and aide.bak never run.
_RUN_PARTS_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
# RHEL's run-parts script and cronie skip only backup/package-manager names.
_RHEL_CRON_SKIP_RE = re.compile(r"(^\.|~$|,$|\.(rpmsave|rpmorig|rpmnew|swp|cfsaved)$)")

# systemd timers that run AIDE: RHEL/CIS aidecheck.timer, Debian 12+
# aide-common's dailyaidecheck.timer.
_AIDE_TIMERS = ("aidecheck.timer", "dailyaidecheck.timer")


def _cron_would_run(f: Path, crond: bool) -> bool:
    """True iff cron (crond=True) or run-parts would actually use file `f`."""
    if _distro.is_rhel_family():
        if _RHEL_CRON_SKIP_RE.search(f.name):
            return False
    elif not _RUN_PARTS_NAME_RE.match(f.name):
        return False
    if crond:
        return True
    try:
        return bool(f.stat().st_mode & 0o111)
    except OSError:
        return False


def _text_runs_aide(text: str) -> bool:
    """True iff an UNCOMMENTED line names `aide` as a whole word.

    The old `grep -r aide` matched commented lines (`# run aide nightly`) and
    substrings of other words (`maidenhead`, `unaided`), so a cron file that
    never runs AIDE false-passed."""
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if re.search(r"\baide\b", s):
            return True
    return False


def _cron_runs_aide() -> bool:
    """True if a file in _AIDE_CRON_PATHS (the file itself, or each regular file
    directly inside a directory that cron / run-parts would actually run) has
    an uncommented line that runs aide.

    Unreadable, root-only, or non-UTF-8 files are skipped rather than allowed
    to crash the audit — a file we can't read can't prove AIDE is scheduled."""
    for target in _AIDE_CRON_PATHS:
        p = Path(target)
        try:
            if p.is_dir():
                crond = p.name == "cron.d"
                files = sorted(f for f in p.iterdir()
                               if f.is_file() and _cron_would_run(f, crond))
            else:
                files = [p]
        except OSError:
            continue
        for f in files:
            try:
                text = f.read_text(errors="replace")
            except OSError:
                continue
            if _text_runs_aide(text):
                return True
    return False


def _check_aide_cron() -> CheckResult:
    # Check for AIDE in crontab or systemd timers
    if _cron_runs_aide():
        return CheckResult("pass")
    for timer in _AIDE_TIMERS:
        try:
            r2 = subprocess.run(["systemctl", "is-enabled", timer],
                                capture_output=True, text=True)
        except FileNotFoundError:
            break
        if r2.stdout.strip() == "enabled":
            return CheckResult("pass")
    return CheckResult("warn", "no periodic AIDE check scheduled")


_AIDE_CRON_DAILY = """#!/bin/sh
# Installed by LSS to satisfy CIS 1.3.2 — periodic filesystem integrity check.
if command -v aide >/dev/null 2>&1; then
    /usr/bin/aide --check --config=/etc/aide/aide.conf | /usr/bin/logger -t aide
fi
"""


_AIDE_CRON_DAILY_PATH = "/etc/cron.daily/aide"


def _fix_aide_cron() -> list[RollbackEntry]:
    """Install /etc/cron.daily/aide so cron runs `aide --check` once per day.

    No-op if AIDE is not installed (pkg.install AIDE via control 1.3.1 first,
    or expect this fix to be a no-op that leaves the check still warning).
    """
    r = subprocess.run(["which", "aide"], capture_output=True, text=True)
    if r.returncode != 0:
        return []
    p = Path(_AIDE_CRON_DAILY_PATH)
    bkp = journal.backup_file(str(p))
    p.write_text(_AIDE_CRON_DAILY)
    os.chmod(str(p), 0o755)  # nosec B103 — a /etc/cron.daily script must be executable (0755)
    return [RollbackEntry(
        action="installed /etc/cron.daily/aide for periodic integrity check",
        path=str(p),
        backup=bkp,
        undo=[] if bkp else [["rm", "-f", str(p)]],
    )]


register(Control(
    id="1.3.2",
    title="Ensure filesystem integrity is regularly checked",
    section="filesystem",
    check=_check_aide_cron,
    fix=_fix_aide_cron,
))


# ---- CIS 1.6.1: Ensure AppArmor is installed ----

def _check_apparmor_installed() -> CheckResult:
    try:
        r = subprocess.run(["which", "apparmor_status"], capture_output=True, text=True)
        if r.returncode == 0:
            return CheckResult("pass")
    except FileNotFoundError:
        pass
    try:
        # -f=${Status} is required: plain `dpkg-query -W` prints only name and
        # version, so the "install ok installed" guard below could never match.
        r2 = subprocess.run(["dpkg-query", "-W", "-f=${Status}", "apparmor"],
                            capture_output=True, text=True)
        if r2.returncode == 0 and "install ok installed" in r2.stdout:
            return CheckResult("pass")
    except FileNotFoundError:
        pass
    return CheckResult("warn", "AppArmor not installed")


def _fix_apparmor_installed() -> list[RollbackEntry]:
    entries = _pkg_lib.install("apparmor")
    entries.extend(_pkg_lib.install("apparmor-utils"))
    return entries


register(Control(
    id="1.6.1",
    title="Ensure AppArmor is installed",
    section="kernel",
    check=_check_apparmor_installed,
    fix=_fix_apparmor_installed,
))


# ---- CIS 1.6.2: Ensure AppArmor is enabled in bootloader ----

def _check_apparmor_enabled() -> CheckResult:
    try:
        r = subprocess.run(["aa-status", "--enabled"], capture_output=True, text=True)
        if r.returncode == 0:
            return CheckResult("pass")
    except FileNotFoundError:
        pass
    try:
        r2 = subprocess.run(["cat", "/sys/module/apparmor/parameters/enabled"],
                            capture_output=True, text=True)
        if r2.stdout.strip() == "Y":
            return CheckResult("pass")
    except FileNotFoundError:
        pass
    return CheckResult(
        "warn",
        "AppArmor not enabled in the running kernel. Add `apparmor=1 security=apparmor` to "
        "GRUB_CMDLINE_LINUX in /etc/default/grub, run update-grub and reboot. LSS does not "
        "auto-edit GRUB because a bad kernel param can leave the host unbootable.",
    )


register(Control(
    id="1.6.2",
    title="Ensure AppArmor is enabled in the bootloader configuration",
    section="kernel",
    check=_check_apparmor_enabled,
    fix=None,
))


# ---- CIS 1.6.3: Ensure all AppArmor profiles are in enforce or complain mode ----

_AA_UNCONFINED_RE = re.compile(r"^\s*(\d+) processes are unconfined", re.MULTILINE)
_AA_LOADED_RE = re.compile(r"^\s*(\d+) profiles are loaded", re.MULTILINE)


def _check_apparmor_profiles() -> CheckResult:
    """CIS 1.6.3 audit: profiles are loaded and no process that has a profile
    defined is running unconfined.

    The count is parsed from its own line: the old substring test for
    "0 processes are unconfined" also matched "10 processes are unconfined",
    and output with no recognisable count fell through to pass."""
    r = None
    for cmd in ("aa-status", "apparmor_status"):
        try:
            r = subprocess.run([cmd], capture_output=True, text=True)
            break
        except FileNotFoundError:
            continue
    if r is None:
        return CheckResult(
            "warn",
            "aa-status not found — install apparmor-utils (control 1.6.1) before running this check.",
        )
    if r.returncode != 0:
        return CheckResult("warn", "aa-status failed — is AppArmor enabled (and is the audit running as root)?")
    loaded = _AA_LOADED_RE.search(r.stdout)
    m = _AA_UNCONFINED_RE.search(r.stdout)
    if not loaded or not m:
        return CheckResult("warn", "could not read the AppArmor profile/process counts from aa-status — review `aa-status` manually")
    if int(loaded.group(1)) == 0:
        return CheckResult("fail", "no AppArmor profiles are loaded — load profiles in enforce or complain mode")
    if int(m.group(1)) == 0:
        return CheckResult("pass")
    line = r.stdout[m.start():].splitlines()[0].strip()
    return CheckResult(
        "warn",
        f"{line} — review each with `aa-status` and run `aa-enforce "
        "/etc/apparmor.d/<profile>` after confirming the profile won't break the app.",
    )


register(Control(
    id="1.6.3",
    title="Ensure all AppArmor profiles are in enforce or complain mode",
    section="kernel",
    check=_check_apparmor_profiles,
    fix=None,
))


# ---- CIS 1.2.1: Ensure package manager repositories are configured ----

def _has_uncommented_line(text: str) -> bool:
    """True iff `text` has at least one non-blank, non-comment line."""
    for line in text.splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            return True
    return False


def _check_repos() -> CheckResult:
    sources = Path("/etc/apt/sources.list")
    sources_d = Path("/etc/apt/sources.list.d")
    # Require a real (uncommented) entry. The old `.strip()` test passed on a
    # comment-only sources.list — e.g. Ubuntu's "# Ubuntu sources have moved to
    # /etc/apt/sources.list.d/ubuntu.sources" stub — that configures no repo.
    try:
        if sources.exists() and _has_uncommented_line(sources.read_text(errors="replace")):
            return CheckResult("pass")
    except OSError:
        pass
    if sources_d.exists() and list(sources_d.glob("*.list")) + list(sources_d.glob("*.sources")):
        return CheckResult("pass")
    # RHEL
    yum_d = Path("/etc/yum.repos.d")
    if yum_d.exists() and list(yum_d.glob("*.repo")):
        return CheckResult("pass")
    return CheckResult("warn", "no package repositories configured")


register(Control(
    id="1.2.1",
    title="Ensure package manager repositories are configured",
    section="filesystem",
    check=_check_repos,
    fix=None,
))


# ---- CIS 1.2.2: Ensure GPG keys are configured ----

def _sources_have_signed_by(dirpath: Path) -> bool:
    """True iff an apt source file directly in `dirpath` has an UNCOMMENTED line
    carrying a signed-by option, matched case-insensitively.

    One-line `.list` entries use `deb [signed-by=/path/key.gpg] ...`; deb822
    `.sources` files use a `Signed-By:` field. The old case-sensitive
    `grep -r signed-by` missed the deb822 form and matched commented example
    lines (`# deb [signed-by=...] ...`), a false pass. Only `*.list` and
    `*.sources` are read, because apt ignores every other file there (e.g.
    `*.list.save` / `*.distUpgrade` left by release upgrades). Unreadable or
    non-UTF-8 files are skipped rather than allowed to crash the audit."""
    try:
        files = sorted(
            f for f in dirpath.iterdir()
            if f.is_file() and f.suffix in (".list", ".sources")
        )
    except OSError:
        return False
    for f in files:
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if "signed-by" in s.lower():
                return True
    return False


def _check_gpg_keys() -> CheckResult:
    # Modern apt uses trusted.gpg.d or signed-by in sources
    gpg_d = Path("/etc/apt/trusted.gpg.d")
    if gpg_d.exists() and (list(gpg_d.glob("*.gpg")) + list(gpg_d.glob("*.asc"))):
        return CheckResult("pass")
    # Signed-by in sources
    if _sources_have_signed_by(Path("/etc/apt/sources.list.d")):
        return CheckResult("pass")
    # Legacy trusted.gpg
    if Path("/etc/apt/trusted.gpg").exists():
        return CheckResult("pass")
    # RHEL
    try:
        r2 = subprocess.run(["rpm", "-qa", "gpg-pubkey*"], capture_output=True, text=True)
        if r2.returncode == 0 and r2.stdout.strip():
            return CheckResult("pass")
    except FileNotFoundError:
        pass
    return CheckResult("warn", "no GPG keys found for package verification")


register(Control(
    id="1.2.2",
    title="Ensure GPG keys are configured",
    section="filesystem",
    check=_check_gpg_keys,
    fix=None,
))


# ---- CIS 1.9: Ensure updates, patches, and additional security software are installed ----

_APT_LISTS_DIR = "/var/lib/apt/lists"
_APT_UPDATE_STAMP = "/var/lib/apt/periodic/update-success-stamp"
_APT_LISTS_MAX_AGE_DAYS = 7


def _apt_lists_age_days() -> float | None:
    """Days since the apt package lists were last refreshed, or None if there
    are no lists. Uses the newest of the update-success stamp and the list
    files themselves (apt dates list files with the server's Last-Modified, so
    the stamp, when present, is the better witness of a recent `apt update`)."""
    newest = None
    candidates = [Path(_APT_UPDATE_STAMP)]
    try:
        candidates += [f for f in Path(_APT_LISTS_DIR).iterdir()
                       if f.is_file() and f.name != "lock"]
    except OSError:
        pass
    for f in candidates:
        try:
            m = f.stat().st_mtime
        except OSError:
            continue
        newest = m if newest is None else max(newest, m)
    if newest is None:
        return None
    return max(0.0, (time.time() - newest) / 86400)


def _check_updates() -> CheckResult:
    # apt. `apt list --upgradable` only compares against the local package
    # lists, so empty output on missing or stale lists proves nothing. The
    # audit does not run `apt update` itself.
    try:
        r = subprocess.run(["apt", "list", "--upgradable"], capture_output=True, text=True)
    except FileNotFoundError:
        return CheckResult("warn", "could not check for updates — ensure apt or dnf is available and sources configured")
    if r.returncode == 0:
        upgradable = [l for l in r.stdout.splitlines() if "/" in l and "Listing..." not in l]
        if upgradable:
            return CheckResult(
                "warn",
                f"{len(upgradable)} package(s) have available updates — run `apt-get update && apt-get upgrade -y` after reviewing the changelogs",
            )
        age = _apt_lists_age_days()
        if age is None:
            return CheckResult(
                "warn",
                f"no apt package lists found in {_APT_LISTS_DIR} — cannot tell whether updates are pending; "
                "run `apt-get update` and re-audit",
            )
        if age > _APT_LISTS_MAX_AGE_DAYS:
            return CheckResult(
                "warn",
                f"apt package lists were last refreshed {int(age)} days ago — pending updates may not be visible; "
                "run `apt-get update` (or enable unattended-upgrades) and re-audit",
            )
        return CheckResult("pass")
    return CheckResult("warn", "could not check for updates — ensure apt or dnf is available and sources configured")


register(Control(
    id="1.9",
    title="Ensure updates, patches, and security software are installed",
    section="filesystem",
    check=_check_updates,
    fix=None,
))


# ---- CIS 2.3: Ensure nonessential services are removed or masked ----

# (id, title, Debian/Ubuntu package names, RHEL-family package names).
# Every package that ships the client binary is listed: Debian 12 / Ubuntu
# 24.04 ship telnet and talk from inetutils-telnet / inetutils-talk (telnet
# is a transitional package), and RHEL names NIS, rsh and LDAP clients
# ypbind, rsh and openldap-clients.
_LEGACY_CLIENTS = [
    ("2.3.1", "Ensure NIS Client is not installed", ("nis",), ("ypbind",)),
    ("2.3.2", "Ensure rsh client is not installed", ("rsh-client", "rsh-redone-client"), ("rsh",)),
    ("2.3.3", "Ensure talk client is not installed", ("talk", "inetutils-talk"), ("talk",)),
    ("2.3.4", "Ensure telnet client is not installed", ("telnet", "inetutils-telnet"), ("telnet",)),
    ("2.3.5", "Ensure LDAP client is not installed", ("ldap-utils",), ("openldap-clients",)),
]


def _client_pkg_names(deb: tuple[str, ...], rhel: tuple[str, ...]) -> list[str]:
    """Package names to check on this host; both families' names when the
    family is unknown, so an unrecognised host is never waved through."""
    if _distro.is_debian_family():
        return list(deb)
    if _distro.is_rhel_family():
        return list(rhel)
    return list(dict.fromkeys(deb + rhel))


def _pkg_installed(name: str) -> bool:
    try:
        r = subprocess.run(["dpkg-query", "-W", "-f=${Status}", name], capture_output=True, text=True)
        if r.returncode == 0 and "install ok installed" in r.stdout:
            return True
    except FileNotFoundError:
        pass
    try:
        r2 = subprocess.run(["rpm", "-q", name], capture_output=True, text=True)
        return r2.returncode == 0
    except FileNotFoundError:
        # No package manager present → the package cannot be installed.
        return False


from lss.lib import distro as _distro
from lss.lib import pkg as _pkg_lib


for _id, _title, _deb, _rhel in _LEGACY_CLIENTS:

    def _make_check(deb, rhel):
        def check():
            present = [p for p in _client_pkg_names(deb, rhel) if _pkg_installed(p)]
            if present:
                return CheckResult("fail", f"{', '.join(present)} installed")
            return CheckResult("pass", "not installed")
        return check

    def _make_fix(deb, rhel):
        def fix():
            entries = []
            for p in _client_pkg_names(deb, rhel):
                entries += _pkg_lib.remove(p)
            return entries
        return fix

    register(Control(
        id=_id,
        title=_title,
        section="services",
        check=_make_check(_deb, _rhel),
        fix=_make_fix(_deb, _rhel),
    ))
