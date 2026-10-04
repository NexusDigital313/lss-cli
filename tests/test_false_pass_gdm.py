# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file, 
# via any medium, is strictly prohibited without explicit written authorization.

"""False-pass regression tests for lss/controls/gdm.py (CIS 1.8.x).

Each test pins a case where a GDM check reported "pass" on evidence that
does not hold:
  - _gdm_installed: `dpkg-query -W` without `-f=${Status}` never prints the
    package status, so the "install ok installed" guard never matched and
    every 1.8.x check vacuously passed as "GDM not installed" on Debian.
  - 1.8.2 / 1.8.3 / 1.8.4: dconf keyfile tests matched commented
    `# key=true` lines, or the key name plus "true" anywhere in the file.
  - 1.8.5 / 1.8.7: locks-file substring tests matched commented lines and
    unrelated keys ("lock" is in /org/gnome/desktop/interface/clock-format),
    and 1.8.7 accepted a lock on automount-open alone.
  - 1.8.2 read only greeter.dconf-defaults when it existed (always, on
    Debian), so once its false pass on the stock commented example is gone it
    must also read the file `lss harden` writes.
"""

from __future__ import annotations

import pathlib
import subprocess

import pytest

from lss.controls import gdm


# --- _dconf_key_is: an uncommented line setting THIS key's own value ---

@pytest.mark.parametrize("text", [
    "banner-message-enable=true",
    "  banner-message-enable = true  ",
    "[org/gnome/login-screen]\nbanner-message-enable=true\n",
])
def test_dconf_key_is_accepts_uncommented_key(text):
    assert gdm._dconf_key_is(text, "banner-message-enable", "true")


@pytest.mark.parametrize("text", [
    "# banner-message-enable=true",
    "#banner-message-enable=true",
    "banner-message-enable=false",
    "banner-message-enable=trueish",
    # The old 1.8.2 false pass: banner off, but another key is "true".
    "banner-message-enable=false\ndisable-user-list=true",
])
def test_dconf_key_is_rejects_commented_or_wrong_value(text):
    assert not gdm._dconf_key_is(text, "banner-message-enable", "true")


# --- _locks_file_locks: uncommented, exact key paths only ---

SCREENLOCK_KEYS = (
    "/org/gnome/desktop/screensaver/lock-enabled",
    "/org/gnome/desktop/screensaver/lock-delay",
    "/org/gnome/desktop/session/idle-delay",
)
AUTOMOUNT_KEYS = ("/org/gnome/desktop/media-handling/automount",)


@pytest.mark.parametrize("text, keys, expected", [
    ("/org/gnome/desktop/screensaver/lock-enabled\n", SCREENLOCK_KEYS, True),
    # CIS's form: lock the session idle-delay.
    ("/org/gnome/desktop/session/idle-delay\n", SCREENLOCK_KEYS, True),
    ("# /org/gnome/desktop/screensaver/lock-enabled\n", SCREENLOCK_KEYS, False),
    ("#/org/gnome/desktop/screensaver/lock-enabled\n", SCREENLOCK_KEYS, False),
    # "clock-format" contains "lock": the old substring test passed on it.
    ("/org/gnome/desktop/interface/clock-format\n", SCREENLOCK_KEYS, False),
    # A real lock on a screensaver key that doesn't govern locking.
    ("/org/gnome/desktop/screensaver/picture-uri\n", SCREENLOCK_KEYS, False),
    ("/org/gnome/desktop/media-handling/automount\n", AUTOMOUNT_KEYS, True),
    ("# /org/gnome/desktop/media-handling/automount\n", AUTOMOUNT_KEYS, False),
    # A comment that merely mentions automount locks nothing.
    ("# TODO: lock automount here\n", AUTOMOUNT_KEYS, False),
    # Locking only automount-open leaves automount itself overridable.
    ("/org/gnome/desktop/media-handling/automount-open\n", AUTOMOUNT_KEYS, False),
])
def test_locks_file_locks(text, keys, expected):
    assert gdm._locks_file_locks(text, keys) is expected


# --- _gdm_installed: dpkg-query must be asked for ${Status} ---

def _fake_run(dpkg_status: str, calls: list[list[str]]):
    """subprocess.run stand-in: dpkg-query prints `dpkg_status`; rpm is absent."""
    def fake_run(argv, *args, **kwargs):
        calls.append(list(argv))
        if argv[0] == "dpkg-query":
            assert "-f=${Status}" in argv, f"dpkg-query without -f=${{Status}}: {argv}"
            return subprocess.CompletedProcess(argv, 0, stdout=dpkg_status, stderr="")
        if argv[0] == "rpm":
            raise FileNotFoundError(argv[0])
        raise AssertionError(f"unexpected command: {argv}")
    return fake_run


def test_gdm_installed_true_when_dpkg_reports_installed(monkeypatch):
    calls: list[list[str]] = []
    monkeypatch.setattr(gdm.subprocess, "run", _fake_run("install ok installed", calls))
    assert gdm._gdm_installed() is True
    assert [c[0] for c in calls] == ["dpkg-query"]


def test_gdm_installed_false_when_only_config_files_remain(monkeypatch):
    """Removed but not purged: dpkg-query still exits 0, so the status decides."""
    calls: list[list[str]] = []
    monkeypatch.setattr(gdm.subprocess, "run", _fake_run("deinstall ok config-files", calls))
    assert gdm._gdm_installed() is False
    assert [c[0] for c in calls] == ["dpkg-query", "rpm"]


# --- End to end: the old false-pass inputs must no longer reach "pass" ---

def _gdm_with_files(monkeypatch, mapping):
    """Pretend GDM is installed and redirect gdm.Path from /etc to tmp files.

    Callers map every path the check under test touches, so the test host's
    real /etc never leaks in.
    """
    monkeypatch.setattr(gdm, "_gdm_installed", lambda: True)
    real_Path = pathlib.Path
    monkeypatch.setattr(gdm, "Path", lambda p: real_Path(mapping.get(str(p), p)))


_GREETER = "/etc/gdm3/greeter.dconf-defaults"
_BANNER_DB = "/etc/dconf/db/gdm.d/01-banner-message"
_LOCKS_DIR = "/etc/dconf/db/local.d/locks"


def _banner_mapping(tmp_path, conf_path, content):
    """Put `content` at `conf_path`; the other banner file does not exist."""
    conf = tmp_path / "banner.conf"
    conf.write_text(content)
    mapping = {_GREETER: tmp_path / "absent", _BANNER_DB: tmp_path / "absent"}
    mapping[conf_path] = conf
    return mapping


@pytest.mark.parametrize("conf_path", [_GREETER, _BANNER_DB])
@pytest.mark.parametrize("content", [
    # Banner off while another key is true: the old test saw the key name
    # and "true" somewhere in the file.
    "[org/gnome/login-screen]\nbanner-message-enable=false\ndisable-user-list=true\n",
    # Only a commented example line.
    "[org/gnome/login-screen]\n# banner-message-enable=true\n",
])
def test_banner_check_rejects_old_false_pass_inputs(tmp_path, monkeypatch, conf_path, content):
    _gdm_with_files(monkeypatch, _banner_mapping(tmp_path, conf_path, content))
    assert gdm._check_gdm_banner().status != "pass"


@pytest.mark.parametrize("conf_path", [_GREETER, _BANNER_DB])
def test_banner_check_passes_when_banner_enabled(tmp_path, monkeypatch, conf_path):
    # Exactly what `lss harden` writes for 1.8.2.
    mapping = _banner_mapping(tmp_path, conf_path, gdm._GDM_BANNER_CONTENT)
    _gdm_with_files(monkeypatch, mapping)
    assert gdm._check_gdm_banner().status == "pass"


@pytest.mark.parametrize("content", [
    # The only screensaver line is a commented example.
    "# /org/gnome/desktop/screensaver/lock-enabled\n",
    # ...plus a real lock on an unrelated key whose name contains "lock".
    "# /org/gnome/desktop/screensaver/lock-enabled\n"
    "/org/gnome/desktop/interface/clock-format\n",
    # A real lock on a screensaver key that doesn't govern locking.
    "/org/gnome/desktop/screensaver/picture-uri\n",
])
def test_lock_override_check_rejects_old_false_pass_inputs(tmp_path, monkeypatch, content):
    locks = tmp_path / "locks"
    locks.mkdir()
    (locks / "00-screensaver").write_text(content)
    _gdm_with_files(monkeypatch, {_LOCKS_DIR: locks})
    assert gdm._check_gdm_lock_override().status != "pass"


def test_lock_override_check_passes_with_real_screensaver_lock(tmp_path, monkeypatch):
    locks = tmp_path / "locks"
    locks.mkdir()
    # Exactly what `lss harden` writes for 1.8.5.
    (locks / "00-screensaver").write_text(gdm._GDM_SCREENLOCK_LOCK_CONTENT)
    _gdm_with_files(monkeypatch, {_LOCKS_DIR: locks})
    assert gdm._check_gdm_lock_override().status == "pass"


def test_automount_lock_check_requires_the_automount_key(tmp_path, monkeypatch):
    locks = tmp_path / "locks"
    locks.mkdir()
    lock_file = locks / "00-media-automount"
    _gdm_with_files(monkeypatch, {_LOCKS_DIR: locks})
    # Locking only automount-open leaves automount itself overridable.
    lock_file.write_text("/org/gnome/desktop/media-handling/automount-open\n")
    assert gdm._check_gdm_automount_lock().status != "pass"
    # Exactly what `lss harden` writes for 1.8.7.
    lock_file.write_text(gdm._GDM_AUTOMOUNT_LOCK_CONTENT)
    assert gdm._check_gdm_automount_lock().status == "pass"


# Debian's gdm3 ships greeter.dconf-defaults with the login-screen keys
# commented out, so the file exists on every Debian host that has GDM.
_STOCK_GREETER = (
    "[org/gnome/login-screen]\n"
    "# - Disable user list\n"
    "# disable-user-list=true\n"
    "# - Show a login welcome message\n"
    "# banner-message-enable=true\n"
    "# banner-message-text='Welcome'\n"
)


def test_banner_check_reads_the_harden_file_when_greeter_defaults_exist(tmp_path, monkeypatch):
    """1.8.2 used to read only greeter.dconf-defaults when it existed, so it
    never saw 01-banner-message, the file `lss harden` writes. With the false
    pass on the stock commented example gone, harden must still turn it green."""
    greeter = tmp_path / "greeter.dconf-defaults"
    greeter.write_text(_STOCK_GREETER)
    banner_db = tmp_path / "01-banner-message"
    _gdm_with_files(monkeypatch, {_GREETER: greeter, _BANNER_DB: banner_db})
    assert gdm._check_gdm_banner().status == "fail"
    banner_db.write_text(gdm._GDM_BANNER_CONTENT)  # what `lss harden` writes
    assert gdm._check_gdm_banner().status == "pass"
