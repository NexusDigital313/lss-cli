# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file,
# via any medium, is strictly prohibited without explicit written authorization.

"""Round-2 false-pass regression tests for lss/controls/misc.py.

Each test pins a case where a check reported "pass" while the control was
not enforced:
  - 1.6.3: the substring "0 processes are unconfined" also matched
    "10 processes are unconfined", and aa-status output with no recognisable
    process count fell through to pass.
  - 2.3.x: only the Debian package name was checked, so Debian 12's
    inetutils-telnet / inetutils-talk and RHEL's ypbind, rsh and
    openldap-clients passed as "not installed".
  - 1.3.2: an aide line in a cron file that run-parts never runs
    (non-executable, or a name such as aide.sh / aide.dpkg-old) counted as
    scheduled, and Debian 12's dailyaidecheck.timer was not recognised.
  - 1.9: `apt list --upgradable` against missing or stale package lists
    lists nothing, which passed as "fully patched".
"""

from __future__ import annotations

import os
import subprocess
import time

import pytest

from lss.controls import misc
from lss.lib import distro
from lss.lib.registry import get_control


def _cp(argv, rc=0, out="", err=""):
    return subprocess.CompletedProcess(argv, rc, stdout=out, stderr=err)


# --- 1.6.3: AppArmor unconfined-process count -----------------------------

_AA_HEAD = (
    "apparmor module is loaded.\n"
    "34 profiles are loaded.\n"
    "34 profiles are in enforce mode.\n"
    "0 profiles are in complain mode.\n"
    "5 processes have profiles defined.\n"
    "5 processes are in enforce mode.\n"
    "0 processes are in complain mode.\n"
)


def _aa(stdout, rc=0):
    def run(argv, *a, **k):
        assert argv[0] in ("aa-status", "apparmor_status"), argv
        return _cp(argv, rc, stdout)
    return run


def test_apparmor_ten_unconfined_is_not_a_pass(monkeypatch):
    monkeypatch.setattr(misc.subprocess, "run",
                        _aa(_AA_HEAD + "10 processes are unconfined but have a profile defined.\n"))
    r = misc._check_apparmor_profiles()
    assert r.status != "pass"
    assert "10 processes" in r.detail


def test_apparmor_zero_unconfined_passes(monkeypatch):
    monkeypatch.setattr(misc.subprocess, "run",
                        _aa(_AA_HEAD + "0 processes are unconfined but have a profile defined.\n"))
    assert misc._check_apparmor_profiles().status == "pass"


def test_apparmor_unparseable_output_is_not_a_pass(monkeypatch):
    monkeypatch.setattr(misc.subprocess, "run", _aa("apparmor module is loaded.\n"))
    assert misc._check_apparmor_profiles().status != "pass"


def test_apparmor_no_profiles_loaded_is_not_a_pass(monkeypatch):
    out = ("apparmor module is loaded.\n0 profiles are loaded.\n"
           "0 processes have profiles defined.\n0 processes are unconfined but have a profile defined.\n")
    monkeypatch.setattr(misc.subprocess, "run", _aa(out))
    assert misc._check_apparmor_profiles().status != "pass"


def test_apparmor_status_failure_is_not_a_pass(monkeypatch):
    monkeypatch.setattr(misc.subprocess, "run", _aa("", rc=4))
    assert misc._check_apparmor_profiles().status != "pass"


# --- 2.3.x: every package name that provides the client --------------------

def _pkg_host(monkeypatch, family, installed):
    """Fake dpkg/rpm/apt-get/dnf over a mutable `installed` set."""
    monkeypatch.setattr(distro, "is_debian_family", lambda: family == "debian")
    monkeypatch.setattr(distro, "is_rhel_family", lambda: family == "rhel")

    def run(argv, *a, **k):
        if argv[0] == "dpkg-query":
            if family != "debian":
                raise FileNotFoundError(argv[0])
            name = argv[-1]
            ok = name in installed
            return _cp(argv, 0 if ok else 1, "install ok installed" if ok else "")
        if argv[0] == "rpm":
            if family != "rhel":
                raise FileNotFoundError(argv[0])
            return _cp(argv, 0 if argv[-1] in installed else 1)
        if argv[:2] in (["apt-get", "remove"], ["dnf", "remove"]):
            installed.discard(argv[-1])
            return _cp(argv)
        raise AssertionError(f"unexpected command: {argv}")
    monkeypatch.setattr(misc.subprocess, "run", run)
    from lss.lib import pkg
    monkeypatch.setattr(pkg.subprocess, "run", run)


@pytest.mark.parametrize("cid,family,pkgname", [
    ("2.3.4", "debian", "inetutils-telnet"),
    ("2.3.3", "debian", "inetutils-talk"),
    ("2.3.1", "rhel", "ypbind"),
    ("2.3.2", "rhel", "rsh"),
    ("2.3.5", "rhel", "openldap-clients"),
])
def test_client_alternate_package_name_is_not_a_pass(monkeypatch, cid, family, pkgname):
    _pkg_host(monkeypatch, family, {pkgname})
    r = get_control(cid).check()
    assert r.status == "fail"
    assert pkgname in r.detail


@pytest.mark.parametrize("cid,family,names", [
    ("2.3.4", "debian", {"telnet", "inetutils-telnet"}),
    ("2.3.1", "rhel", {"ypbind"}),
    ("2.3.5", "rhel", {"openldap-clients"}),
])
def test_client_fix_removes_every_provider_round_trip(monkeypatch, cid, family, names):
    installed = set(names)
    _pkg_host(monkeypatch, family, installed)
    c = get_control(cid)
    assert c.check().status == "fail"
    c.fix()
    assert installed == set()
    assert c.check().status == "pass"


def test_client_absent_passes(monkeypatch):
    _pkg_host(monkeypatch, "debian", set())
    assert get_control("2.3.4").check().status == "pass"


# --- 1.3.2: only cron files cron/run-parts actually execute count ---------

def _no_timers(argv, *a, **k):
    assert argv[:2] == ["systemctl", "is-enabled"], argv
    return _cp(argv, 1, "disabled\n")


def _aide_layout(tmp_path, monkeypatch, *, daily=None, crond=None):
    """daily / crond: {filename: (content, mode)}"""
    crontab = tmp_path / "crontab"
    crontab.write_text("17 * * * * root cd / && run-parts --report /etc/cron.hourly\n")
    dirs = {}
    for name, files in (("cron.daily", daily), ("cron.weekly", None), ("cron.d", crond)):
        d = tmp_path / name
        d.mkdir()
        for fname, (content, mode) in (files or {}).items():
            f = d / fname
            f.write_text(content)
            os.chmod(f, mode)
        dirs[name] = str(d)
    monkeypatch.setattr(misc, "_AIDE_CRON_PATHS",
                        (str(crontab), dirs["cron.daily"], dirs["cron.weekly"], dirs["cron.d"]))
    monkeypatch.setattr(distro, "is_rhel_family", lambda: False)


@pytest.mark.parametrize("fname,mode", [
    ("aide", 0o644),            # not executable: run-parts skips it
    ("aide.sh", 0o755),         # '.' in name: run-parts skips it
    ("aide.dpkg-old", 0o755),
    ("aide.bak", 0o755),
])
def test_aide_cron_daily_file_run_parts_skips_is_not_a_pass(tmp_path, monkeypatch, fname, mode):
    _aide_layout(tmp_path, monkeypatch, daily={fname: (misc._AIDE_CRON_DAILY, mode)})
    monkeypatch.setattr(misc.subprocess, "run", _no_timers)
    assert misc._check_aide_cron().status != "pass"


def test_aide_cron_d_file_with_dot_is_not_a_pass(tmp_path, monkeypatch):
    _aide_layout(tmp_path, monkeypatch,
                 crond={"aide.disabled": ("0 5 * * * root /usr/bin/aide --check\n", 0o644)})
    monkeypatch.setattr(misc.subprocess, "run", _no_timers)
    assert misc._check_aide_cron().status != "pass"


def test_aide_cron_d_valid_file_passes(tmp_path, monkeypatch):
    _aide_layout(tmp_path, monkeypatch,
                 crond={"aide": ("0 5 * * * root /usr/bin/aide --check\n", 0o644)})
    monkeypatch.setattr(misc.subprocess, "run", _no_timers)
    assert misc._check_aide_cron().status == "pass"


def test_aide_executable_cron_daily_passes(tmp_path, monkeypatch):
    _aide_layout(tmp_path, monkeypatch, daily={"aide": (misc._AIDE_CRON_DAILY, 0o755)})
    monkeypatch.setattr(misc.subprocess, "run", _no_timers)
    assert misc._check_aide_cron().status == "pass"


def test_aide_debian12_dailyaidecheck_timer_passes(tmp_path, monkeypatch):
    _aide_layout(tmp_path, monkeypatch)

    def run(argv, *a, **k):
        assert argv[:2] == ["systemctl", "is-enabled"], argv
        return _cp(argv, 0, "enabled\n") if argv[-1] == "dailyaidecheck.timer" else _cp(argv, 1, "disabled\n")
    monkeypatch.setattr(misc.subprocess, "run", run)
    assert misc._check_aide_cron().status == "pass"


def test_aide_fix_round_trip(tmp_path, monkeypatch):
    """The 1.3.2 fix's cron script must be one run-parts runs, so the check passes."""
    _aide_layout(tmp_path, monkeypatch)
    target = tmp_path / "cron.daily" / "aide"

    def run(argv, *a, **k):
        if argv[0] == "which":
            return _cp(argv, 0, "/usr/bin/aide\n")
        return _no_timers(argv)
    monkeypatch.setattr(misc, "_AIDE_CRON_DAILY_PATH", str(target))
    monkeypatch.setattr(misc.journal, "backup_file", lambda p: None)
    monkeypatch.setattr(misc.subprocess, "run", run)
    assert misc._check_aide_cron().status != "pass"
    misc._fix_aide_cron()
    assert misc._check_aide_cron().status == "pass"


# --- 1.9: stale or missing apt lists are not "fully patched" --------------

def _apt_empty(argv, *a, **k):
    assert argv[:2] == ["apt", "list"], argv
    return _cp(argv, 0, "Listing...\n")


def _apt_state(tmp_path, monkeypatch, age_days=None, stamp_age_days=None):
    lists = tmp_path / "lists"
    lists.mkdir()
    (lists / "partial").mkdir()
    (lists / "lock").write_text("")
    stamp = tmp_path / "update-success-stamp"
    now = time.time()
    old = now - 60 * 86400
    if age_days is not None:
        f = lists / "deb.debian.org_debian_dists_bookworm_InRelease"
        f.write_text("x")
        os.utime(f, (now - age_days * 86400,) * 2)
    for p in (lists, lists / "partial", lists / "lock"):
        os.utime(p, (old, old))
    if stamp_age_days is not None:
        stamp.write_text("")
        os.utime(stamp, (now - stamp_age_days * 86400,) * 2)
    monkeypatch.setattr(misc, "_APT_LISTS_DIR", str(lists))
    monkeypatch.setattr(misc, "_APT_UPDATE_STAMP", str(stamp))
    monkeypatch.setattr(misc.subprocess, "run", _apt_empty)


def test_updates_missing_lists_is_not_a_pass(tmp_path, monkeypatch):
    _apt_state(tmp_path, monkeypatch)
    r = misc._check_updates()
    assert r.status != "pass"
    assert "apt" in r.detail


def test_updates_stale_lists_is_not_a_pass(tmp_path, monkeypatch):
    _apt_state(tmp_path, monkeypatch, age_days=30, stamp_age_days=30)
    r = misc._check_updates()
    assert r.status != "pass"
    assert "30 day" in r.detail


def test_updates_fresh_lists_pass(tmp_path, monkeypatch):
    _apt_state(tmp_path, monkeypatch, age_days=1)
    assert misc._check_updates().status == "pass"


def test_updates_fresh_stamp_with_old_list_files_passes(tmp_path, monkeypatch):
    # apt stamps list files with the server's Last-Modified, so a quiet repo
    # can look old even right after `apt update`; the success stamp is fresh.
    _apt_state(tmp_path, monkeypatch, age_days=20, stamp_age_days=0)
    assert misc._check_updates().status == "pass"


def test_updates_pending_upgrades_still_warn(tmp_path, monkeypatch):
    _apt_state(tmp_path, monkeypatch, age_days=1)
    monkeypatch.setattr(misc.subprocess, "run", lambda argv, *a, **k: _cp(
        argv, 0, "Listing...\nopenssl/stable-security 3.0.15 amd64 [upgradable from: 3.0.14]\n"))
    assert misc._check_updates().status == "warn"
