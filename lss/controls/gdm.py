"""CIS Section 1.8 — GNOME Display Manager (GDM) configuration."""

from __future__ import annotations

import subprocess
from pathlib import Path

from lss.lib.registry import Control, CheckResult, RollbackEntry, register


def _gdm_installed() -> bool:
    r = subprocess.run(["dpkg-query", "-W", "gdm3"], capture_output=True, text=True)
    if r.returncode == 0 and "install ok installed" in r.stdout:
        return True
    r2 = subprocess.run(["rpm", "-q", "gdm"], capture_output=True, text=True)
    return r2.returncode == 0


# ---- CIS 1.8.1: Ensure GNOME Display Manager is removed (server) ----

def _check_gdm_removed() -> CheckResult:
    if not _gdm_installed():
        return CheckResult("pass", "GDM not installed")
    return CheckResult("warn", "GDM is installed — appropriate for workstation, not server")


register(Control(
    id="1.8.1",
    title="Ensure GDM is removed or login is configured (server profile)",
    section="boot",
    check=_check_gdm_removed,
    fix=None,  # Package removal
))


# ---- CIS 1.8.2: Ensure GDM login banner is configured ----

def _check_gdm_banner() -> CheckResult:
    if not _gdm_installed():
        return CheckResult("pass", "GDM not installed")
    banner_conf = Path("/etc/gdm3/greeter.dconf-defaults")
    if not banner_conf.exists():
        banner_conf = Path("/etc/dconf/db/gdm.d/01-banner-message")
    if banner_conf.exists():
        text = banner_conf.read_text()
        if "banner-message-enable" in text and "true" in text.lower():
            return CheckResult("pass")
    return CheckResult("fail", "GDM login banner not configured")


register(Control(
    id="1.8.2",
    title="Ensure GDM login banner is configured",
    section="boot",
    check=_check_gdm_banner,
    fix=None,  # Site-specific
))


# ---- CIS 1.8.3: Ensure GDM disable-user-list option is enabled ----

def _check_gdm_user_list() -> CheckResult:
    if not _gdm_installed():
        return CheckResult("pass", "GDM not installed")
    for conf_path in [
        "/etc/gdm3/greeter.dconf-defaults",
        "/etc/dconf/db/gdm.d/00-login-screen",
    ]:
        p = Path(conf_path)
        if p.exists():
            text = p.read_text()
            if "disable-user-list" in text and "true" in text.lower():
                return CheckResult("pass")
    return CheckResult("fail", "GDM user list not disabled")


register(Control(
    id="1.8.3",
    title="Ensure GDM disable-user-list option is enabled",
    section="boot",
    check=_check_gdm_user_list,
    fix=None,
))


# ---- CIS 1.8.4: Ensure GDM screen locks when idle ----

def _check_gdm_screenlock() -> CheckResult:
    if not _gdm_installed():
        return CheckResult("pass", "GDM not installed")
    # Check for screen lock settings in dconf
    for conf_path in [
        "/etc/dconf/db/local.d/00-screensaver",
        "/etc/dconf/db/gdm.d/00-screensaver",
    ]:
        p = Path(conf_path)
        if p.exists():
            text = p.read_text()
            if "lock-enabled" in text:
                return CheckResult("pass")
    return CheckResult("warn", "GDM screen lock not explicitly configured")


register(Control(
    id="1.8.4",
    title="Ensure GDM screen locks when the user is idle",
    section="boot",
    check=_check_gdm_screenlock,
    fix=None,
))


# ---- CIS 1.8.5: Ensure GDM screen locks cannot be overridden ----

def _check_gdm_lock_override() -> CheckResult:
    if not _gdm_installed():
        return CheckResult("pass", "GDM not installed")
    locks_dir = Path("/etc/dconf/db/local.d/locks")
    if locks_dir.exists():
        for f in locks_dir.glob("*"):
            text = f.read_text()
            if "screensaver" in text.lower() or "lock" in text.lower():
                return CheckResult("pass")
    return CheckResult("warn", "GDM screen lock override protection not configured")


register(Control(
    id="1.8.5",
    title="Ensure GDM screen locks cannot be overridden",
    section="boot",
    check=_check_gdm_lock_override,
    fix=None,
))


# ---- CIS 1.8.6: Ensure GDM automatic mounting is disabled ----

def _check_gdm_automount() -> CheckResult:
    if not _gdm_installed():
        return CheckResult("pass", "GDM not installed")
    # Check dconf for automount setting
    for conf_path in [
        "/etc/dconf/db/local.d/00-media-automount",
    ]:
        p = Path(conf_path)
        if p.exists():
            text = p.read_text()
            if "automount" in text and "false" in text.lower():
                return CheckResult("pass")

    # Check gsettings if available
    r = subprocess.run(
        ["gsettings", "get", "org.gnome.desktop.media-handling", "automount"],
        capture_output=True, text=True,
    )
    if r.returncode == 0 and r.stdout.strip() == "false":
        return CheckResult("pass")

    return CheckResult("warn", "GDM automatic mounting not explicitly disabled")


register(Control(
    id="1.8.6",
    title="Ensure GDM automatic mounting of removable media is disabled",
    section="boot",
    check=_check_gdm_automount,
    fix=None,
))


# ---- CIS 1.8.7: Ensure GDM disabling automatic mounting cannot be overridden ----

def _check_gdm_automount_lock() -> CheckResult:
    if not _gdm_installed():
        return CheckResult("pass", "GDM not installed")
    locks_dir = Path("/etc/dconf/db/local.d/locks")
    if locks_dir.exists():
        for f in locks_dir.glob("*"):
            text = f.read_text()
            if "automount" in text.lower():
                return CheckResult("pass")
    return CheckResult("warn", "GDM automount override protection not configured")


register(Control(
    id="1.8.7",
    title="Ensure GDM disabling automatic mounting cannot be overridden",
    section="boot",
    check=_check_gdm_automount_lock,
    fix=None,
))


# ---- CIS 1.8.8: Ensure GDM autorun-never is enabled ----

def _check_gdm_autorun() -> CheckResult:
    if not _gdm_installed():
        return CheckResult("pass", "GDM not installed")
    r = subprocess.run(
        ["gsettings", "get", "org.gnome.desktop.media-handling", "autorun-never"],
        capture_output=True, text=True,
    )
    if r.returncode == 0 and r.stdout.strip() == "true":
        return CheckResult("pass")
    return CheckResult("warn", "GDM autorun-never not set")


register(Control(
    id="1.8.8",
    title="Ensure GDM autorun-never is enabled",
    section="boot",
    check=_check_gdm_autorun,
    fix=None,
))