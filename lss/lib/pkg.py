"""Shared package-manager helpers for install/remove fixes.

Picks the right tool for the distro family. Package removal uses `remove`
rather than `purge` so that rollback via `install` preserves the original
configuration files on Debian family systems.
"""

from __future__ import annotations

import subprocess

from lss.lib import distro
from lss.lib.registry import RollbackEntry


_NONINTERACTIVE_ENV = {
    "DEBIAN_FRONTEND": "noninteractive",
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
}


_PKG_TIMEOUT = 300  # apt-get / dnf install or remove


def is_installed(pkg: str) -> bool:
    """Return True if `pkg` is installed on the running distro family.

    Dispatches on distro family first so we never spawn `rpm` on a host
    that doesn't have it (FileNotFoundError would crash the caller).
    """
    if distro.is_debian_family():
        r = subprocess.run(
            ["dpkg-query", "-W", "-f=${Status}", pkg],
            capture_output=True, text=True,
        )
        return r.returncode == 0 and "install ok installed" in r.stdout
    if distro.is_rhel_family():
        try:
            r = subprocess.run(["rpm", "-q", pkg], capture_output=True, text=True)
        except FileNotFoundError:
            return False
        return r.returncode == 0
    return False


def install(pkg: str) -> list[RollbackEntry]:
    """Install `pkg`. Returns a RollbackEntry whose undo removes it.

    No-op if already installed, or if the distro family is neither Debian
    nor RHEL (returns an empty list so the caller can surface a no-op).
    """
    if is_installed(pkg):
        return []
    if distro.is_debian_family():
        cmd = ["apt-get", "install", "-y", pkg]
        undo = [["apt-get", "remove", "-y", pkg]]
    elif distro.is_rhel_family():
        cmd = ["dnf", "install", "-y", pkg]
        undo = [["dnf", "remove", "-y", pkg]]
    else:
        return []
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            env=_NONINTERACTIVE_ENV, timeout=_PKG_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"{' '.join(cmd)} timed out after {_PKG_TIMEOUT}s")
    if r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed: {r.stderr.strip()}")
    return [RollbackEntry(action=f"installed package {pkg}", undo=undo)]


def remove(pkg: str) -> list[RollbackEntry]:
    """Remove `pkg` (not purge — configs preserved). Rollback reinstalls it."""
    if not is_installed(pkg):
        return []
    if distro.is_debian_family():
        cmd = ["apt-get", "remove", "-y", pkg]
        undo = [["apt-get", "install", "-y", pkg]]
    elif distro.is_rhel_family():
        cmd = ["dnf", "remove", "-y", pkg]
        undo = [["dnf", "install", "-y", pkg]]
    else:
        return []
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            env=_NONINTERACTIVE_ENV, timeout=_PKG_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"{' '.join(cmd)} timed out after {_PKG_TIMEOUT}s")
    if r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed: {r.stderr.strip()}")
    return [RollbackEntry(action=f"removed package {pkg}", undo=undo)]
