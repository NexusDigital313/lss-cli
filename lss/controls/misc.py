"""Miscellaneous CIS controls — SSH extras, USB storage, prelink, sysrq, etc."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from lss.lib import journal
from lss.lib.registry import Control, CheckResult, RollbackEntry, register
from lss.lib.sshd import get_sshd_setting as _get_sshd_setting, set_sshd_setting as _set_sshd_setting, LSS_SSHD_CONF


# ---- CIS 5.2.1: Ensure permissions on /etc/ssh/sshd_config are configured ----

def _check_sshd_config_perms() -> CheckResult:
    import stat
    p = Path("/etc/ssh/sshd_config")
    if not p.exists():
        return CheckResult("warn", "sshd_config not found")
    st = p.stat()
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

def _check_ssh_alive_not_zero() -> CheckResult:
    val = _get_sshd_setting("clientaliveinterval")
    if val is None:
        return CheckResult("warn", "could not read sshd config")
    try:
        n = int(val)
    except ValueError:
        return CheckResult("fail", f"ClientAliveInterval={val}")
    if n > 0:
        return CheckResult("pass")
    return CheckResult("fail", "ClientAliveInterval=0 (no timeout)")


def _fix_ssh_alive_not_zero() -> list[RollbackEntry]:
    """If ClientAliveInterval is 0 or unset, restore the CIS-recommended 300s."""
    val = _get_sshd_setting("clientaliveinterval")
    if val is not None:
        try:
            if int(val) > 0:
                return []
        except ValueError:
            pass
    return [_set_sshd_setting("ClientAliveInterval", "300")]


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
    try:
        r = subprocess.run(["modprobe", "-n", "--show-depends", "usb-storage"],
                           capture_output=True, text=True)
        if "/bin/true" in r.stdout or "/bin/false" in r.stdout:
            return CheckResult("pass")
    except FileNotFoundError:
        pass
    r2 = subprocess.run(["grep", "-r", "blacklist usb-storage", "/etc/modprobe.d/"],
                        capture_output=True, text=True)
    if r2.returncode == 0 and r2.stdout.strip():
        return CheckResult("pass")
    return CheckResult("fail", "usb-storage module is not disabled")


def _fix_usb_storage() -> list[RollbackEntry]:
    conf = "/etc/modprobe.d/lss-usb-storage.conf"
    bkp = journal.backup_file(conf)
    Path(conf).write_text("install usb-storage /bin/true\nblacklist usb-storage\n")
    subprocess.run(["rmmod", "usb-storage"], capture_output=True)
    return [RollbackEntry(
        action="disabled usb-storage module",
        path=conf,
        backup=bkp,
        undo=[] if bkp else [["rm", "-f", conf]],
    )]


register(Control(
    id="1.1.15",
    title="Ensure USB storage is disabled",
    section="filesystem",
    check=_check_usb_storage,
    fix=_fix_usb_storage,
))


# ---- CIS 1.3.1: Ensure AIDE is installed ----

def _check_aide_installed() -> CheckResult:
    r = subprocess.run(["which", "aide"], capture_output=True, text=True)
    if r.returncode == 0:
        return CheckResult("pass")
    r2 = subprocess.run(["dpkg-query", "-W", "aide"], capture_output=True, text=True)
    if r2.returncode == 0 and "install ok installed" in r2.stdout:
        return CheckResult("pass")
    # RHEL
    r3 = subprocess.run(["rpm", "-q", "aide"], capture_output=True, text=True)
    if r3.returncode == 0:
        return CheckResult("pass")
    return CheckResult("warn", "AIDE not installed — no file integrity monitoring")


register(Control(
    id="1.3.1",
    title="Ensure AIDE is installed",
    section="filesystem",
    check=_check_aide_installed,
    fix=lambda: _pkg_lib.install("aide"),
))


# ---- CIS 1.3.2: Ensure filesystem integrity is regularly checked ----

def _check_aide_cron() -> CheckResult:
    # Check for AIDE in crontab or systemd timers
    r = subprocess.run(["grep", "-r", "aide", "/etc/cron.daily/", "/etc/cron.weekly/",
                        "/etc/crontab"], capture_output=True, text=True)
    if r.returncode == 0 and r.stdout.strip():
        return CheckResult("pass")
    r2 = subprocess.run(["systemctl", "is-enabled", "aidecheck.timer"],
                        capture_output=True, text=True)
    if r2.stdout.strip() == "enabled":
        return CheckResult("pass")
    return CheckResult("warn", "no periodic AIDE check scheduled")


_AIDE_CRON_DAILY = """#!/bin/sh
# Installed by LSS to satisfy CIS 1.3.2 — periodic filesystem integrity check.
if command -v aide >/dev/null 2>&1; then
    /usr/bin/aide --check --config=/etc/aide/aide.conf | /usr/bin/logger -t aide
fi
"""


def _fix_aide_cron() -> list[RollbackEntry]:
    """Install /etc/cron.daily/aide so cron runs `aide --check` once per day.

    No-op if AIDE is not installed (pkg.install AIDE via control 1.3.1 first,
    or expect this fix to be a no-op that leaves the check still warning).
    """
    r = subprocess.run(["which", "aide"], capture_output=True, text=True)
    if r.returncode != 0:
        return []
    p = Path("/etc/cron.daily/aide")
    bkp = journal.backup_file(str(p))
    p.write_text(_AIDE_CRON_DAILY)
    os.chmod(str(p), 0o755)
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
    r = subprocess.run(["which", "apparmor_status"], capture_output=True, text=True)
    if r.returncode == 0:
        return CheckResult("pass")
    r2 = subprocess.run(["dpkg-query", "-W", "apparmor"], capture_output=True, text=True)
    if r2.returncode == 0 and "install ok installed" in r2.stdout:
        return CheckResult("pass")
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
    r = subprocess.run(["aa-status", "--enabled"], capture_output=True, text=True)
    if r.returncode == 0:
        return CheckResult("pass")
    r2 = subprocess.run(["cat", "/sys/module/apparmor/parameters/enabled"],
                        capture_output=True, text=True)
    if r2.stdout.strip() == "Y":
        return CheckResult("pass")
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

def _check_apparmor_profiles() -> CheckResult:
    try:
        r = subprocess.run(["aa-status"], capture_output=True, text=True)
        if r.returncode != 0:
            return CheckResult("warn", "aa-status failed — is AppArmor enabled?")
        if "0 processes are unconfined" in r.stdout:
            return CheckResult("pass")
        for line in r.stdout.splitlines():
            if "unconfined" in line.lower():
                return CheckResult(
                    "warn",
                    f"{line.strip()} — review each with `aa-status` and run `aa-enforce "
                    "/etc/apparmor.d/<profile>` after confirming the profile won't break the app.",
                )
        return CheckResult("pass")
    except FileNotFoundError:
        return CheckResult(
            "warn",
            "aa-status not found — install apparmor-utils (control 1.6.1) before running this check.",
        )


register(Control(
    id="1.6.3",
    title="Ensure all AppArmor profiles are in enforce or complain mode",
    section="kernel",
    check=_check_apparmor_profiles,
    fix=None,
))


# ---- CIS 1.2.1: Ensure package manager repositories are configured ----

def _check_repos() -> CheckResult:
    sources = Path("/etc/apt/sources.list")
    sources_d = Path("/etc/apt/sources.list.d")
    if sources.exists() and sources.read_text().strip():
        return CheckResult("pass")
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

def _check_gpg_keys() -> CheckResult:
    # Modern apt uses trusted.gpg.d or signed-by in sources
    gpg_d = Path("/etc/apt/trusted.gpg.d")
    if gpg_d.exists() and (list(gpg_d.glob("*.gpg")) + list(gpg_d.glob("*.asc"))):
        return CheckResult("pass")
    # Signed-by in sources
    r = subprocess.run(["grep", "-r", "signed-by", "/etc/apt/sources.list.d/"],
                       capture_output=True, text=True)
    if r.returncode == 0 and r.stdout.strip():
        return CheckResult("pass")
    # Legacy trusted.gpg
    if Path("/etc/apt/trusted.gpg").exists():
        return CheckResult("pass")
    # RHEL
    r2 = subprocess.run(["rpm", "-qa", "gpg-pubkey*"], capture_output=True, text=True)
    if r2.returncode == 0 and r2.stdout.strip():
        return CheckResult("pass")
    return CheckResult("warn", "no GPG keys found for package verification")


register(Control(
    id="1.2.2",
    title="Ensure GPG keys are configured",
    section="filesystem",
    check=_check_gpg_keys,
    fix=None,
))


# ---- CIS 1.9: Ensure updates, patches, and additional security software are installed ----

def _check_updates() -> CheckResult:
    # apt
    r = subprocess.run(["apt", "list", "--upgradable"], capture_output=True, text=True)
    if r.returncode == 0:
        upgradable = [l for l in r.stdout.splitlines() if "/" in l and "Listing..." not in l]
        if len(upgradable) == 0:
            return CheckResult("pass")
        return CheckResult(
            "warn",
            f"{len(upgradable)} package(s) have available updates — run `apt-get update && apt-get upgrade -y` after reviewing the changelogs",
        )
    return CheckResult("warn", "could not check for updates — ensure apt or dnf is available and sources configured")


register(Control(
    id="1.9",
    title="Ensure updates, patches, and security software are installed",
    section="filesystem",
    check=_check_updates,
    fix=None,
))


# ---- CIS 2.3: Ensure nonessential services are removed or masked ----

_LEGACY_CLIENTS = [
    ("2.3.1", "Ensure NIS Client is not installed", "nis"),
    ("2.3.2", "Ensure rsh client is not installed", "rsh-client"),
    ("2.3.3", "Ensure talk client is not installed", "talk"),
    ("2.3.4", "Ensure telnet client is not installed", "telnet"),
    ("2.3.5", "Ensure LDAP client is not installed", "ldap-utils"),
]


def _pkg_installed(name: str) -> bool:
    r = subprocess.run(["dpkg-query", "-W", "-f=${Status}", name], capture_output=True, text=True)
    if r.returncode == 0 and "install ok installed" in r.stdout:
        return True
    r2 = subprocess.run(["rpm", "-q", name], capture_output=True, text=True)
    return r2.returncode == 0


from lss.lib import pkg as _pkg_lib


for _id, _title, _pkg in _LEGACY_CLIENTS:
    pkg = _pkg

    def _make_check(p):
        def check():
            if _pkg_installed(p):
                return CheckResult("fail", f"{p} is installed")
            return CheckResult("pass", "not installed")
        return check

    def _make_fix(p):
        def fix():
            return _pkg_lib.remove(p)
        return fix

    register(Control(
        id=_id,
        title=_title,
        section="services",
        check=_make_check(pkg),
        fix=_make_fix(pkg),
    ))
