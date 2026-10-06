# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file,
# via any medium, is strictly prohibited without explicit written authorization.

"""Round-2 false-pass regression tests: GDM screen lock (1.8.4-1.8.8) and firewall.

  - 1.8.4-1.8.8 passed on a keyfile under /etc/dconf/db/local.d alone. Those
    keyfiles reach a user session only when /etc/dconf/profile/user lists
    system-db:local (stock Debian ships no such profile) and `dconf update`
    has compiled /etc/dconf/db/local. The fixers now create or extend the
    profile, journalled, so their output satisfies their own checks.
  - 1.8.4 passed on lock-enabled=true (GNOME's default) without the CIS
    session idle-delay (1..900) and lock-delay (0..5); its fixer wrote
    idle-delay under the screensaver schema, where it does nothing.
  - 1.8.5 passed on a lock on any one screen-lock key; CIS needs both
    session/idle-delay and screensaver/lock-delay locked.
  - 3.5.3.1-3.5.3.3, 3.2.1 (extras) and 3.3.9 (network) treated
    all.disable_ipv6 = 1 alone as "IPv6 is disabled"; they now use
    lss.lib.sysctl.ipv6_disabled(), and firewall._ipv6_disabled is gone.
  - 3.5.4 passed on a saved rules file with nothing loading it at boot.
  - 3.5.2.4 ignored UDP listeners and passed when `ss` failed.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import time

import pytest

from lss.controls import extras, firewall, gdm, network
from lss.lib import journal, sysctl


def _cp(argv, rc=0, out=""):
    return subprocess.CompletedProcess(argv, rc, stdout=out, stderr="")


# ============================ GDM / dconf ============================

class _Dconf:
    """A fake /etc/dconf tree under tmp_path, with gdm.Path redirected to it."""

    def __init__(self, tmp_path, monkeypatch):
        self.root = tmp_path / "dconf"
        self.profile = self.root / "profile" / "user"
        self.db = self.root / "db" / "local"
        self.local_d = self.root / "db" / "local.d"
        self.local_d.mkdir(parents=True)
        real_Path = pathlib.Path
        prefix = "/etc/dconf/"

        def fake_path(p):
            p = str(p)
            if p.startswith(prefix):
                return real_Path(self.root / p[len(prefix):])
            return real_Path(p)

        monkeypatch.setattr(gdm, "Path", fake_path)
        monkeypatch.setattr(gdm, "_gdm_installed", lambda: True)
        monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/" + name)
        monkeypatch.setattr(journal, "BACKUPS_DIR", tmp_path / "backups")
        journal.set_current_run_id("test-run")
        self.calls = []

        def fake_run(argv, *a, **kw):
            self.calls.append(argv)
            if argv[:2] == ["dconf", "update"]:
                self.compile()
                return _cp(argv)
            return _cp(argv, rc=1)  # gsettings etc.: not available
        monkeypatch.setattr(gdm.subprocess, "run", fake_run)

    def write(self, rel, text):
        f = self.local_d / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)

    def set_profile(self, text):
        self.profile.parent.mkdir(parents=True, exist_ok=True)
        self.profile.write_text(text)

    def compile(self):
        self.db.parent.mkdir(parents=True, exist_ok=True)
        self.db.write_text("compiled")
        future = time.time() + 10
        os.utime(self.db, (future, future))


@pytest.fixture
def dconf(tmp_path, monkeypatch):
    yield _Dconf(tmp_path, monkeypatch)
    journal.set_current_run_id(None)


_CIS_SCREENLOCK = (
    "[org/gnome/desktop/session]\nidle-delay=uint32 900\n\n"
    "[org/gnome/desktop/screensaver]\nlock-enabled=true\nlock-delay=uint32 5\n"
)

# (check, {local.d relative path: content}) that satisfy each keyfile test.
_CONFIGURED = {
    "1.8.4": (gdm._check_gdm_screenlock, {"00-screensaver": _CIS_SCREENLOCK}),
    "1.8.5": (gdm._check_gdm_lock_override,
              {"locks/00-screensaver": "/org/gnome/desktop/session/idle-delay\n"
                                       "/org/gnome/desktop/screensaver/lock-delay\n"}),
    "1.8.6": (gdm._check_gdm_automount,
              {"00-media-automount": "[org/gnome/desktop/media-handling]\nautomount=false\n"}),
    "1.8.7": (gdm._check_gdm_automount_lock,
              {"locks/00-media-automount": "/org/gnome/desktop/media-handling/automount\n"}),
    "1.8.8": (gdm._check_gdm_autorun,
              {"00-autorun-never": "[org/gnome/desktop/media-handling]\nautorun-never=true\n"}),
}

_FIXERS = {
    "1.8.4": (gdm._fix_gdm_screenlock, gdm._check_gdm_screenlock),
    "1.8.5": (gdm._fix_gdm_lock_override, gdm._check_gdm_lock_override),
    "1.8.6": (gdm._fix_gdm_automount, gdm._check_gdm_automount),
    "1.8.7": (gdm._fix_gdm_automount_lock, gdm._check_gdm_automount_lock),
    "1.8.8": (gdm._fix_gdm_autorun, gdm._check_gdm_autorun),
}


@pytest.mark.parametrize("cid", sorted(_CONFIGURED))
@pytest.mark.parametrize("profile", [
    None,                                   # stock Debian: no user profile
    "user-db:user\n",                       # profile without the local db
    "user-db:user\n# system-db:local\n",    # only a commented example
])
def test_local_keyfiles_need_the_user_profile(dconf, cid, profile):
    check, files = _CONFIGURED[cid]
    for rel, text in files.items():
        dconf.write(rel, text)
    dconf.compile()
    if profile is not None:
        dconf.set_profile(profile)
    assert check().status != "pass"


@pytest.mark.parametrize("cid", sorted(_CONFIGURED))
def test_local_keyfiles_need_a_compiled_current_db(dconf, cid):
    check, files = _CONFIGURED[cid]
    dconf.set_profile("user-db:user\nsystem-db:local\n")
    for rel, text in files.items():
        dconf.write(rel, text)
    assert check().status != "pass"          # never compiled
    dconf.compile()
    assert check().status == "pass"          # profile + compiled db: no false fail
    stale = time.time() - 1000
    os.utime(dconf.db, (stale, stale))
    assert check().status != "pass"          # keyfiles newer than the db


@pytest.mark.parametrize("content", [
    # The old pass: lock-enabled=true (GNOME's default) and nothing else.
    "[org/gnome/desktop/screensaver]\nlock-enabled=true\n",
    # The old fixer output: idle-delay under the wrong schema.
    "[org/gnome/desktop/screensaver]\nlock-enabled=true\nlock-delay=uint32 0\n"
    "idle-delay=uint32 900\n",
    # idle-delay 0 means the session never goes idle.
    "[org/gnome/desktop/session]\nidle-delay=uint32 0\n"
    "[org/gnome/desktop/screensaver]\nlock-enabled=true\nlock-delay=uint32 5\n",
    "[org/gnome/desktop/session]\nidle-delay=uint32 1800\n"
    "[org/gnome/desktop/screensaver]\nlock-enabled=true\nlock-delay=uint32 5\n",
    "[org/gnome/desktop/session]\nidle-delay=uint32 900\n"
    "[org/gnome/desktop/screensaver]\nlock-enabled=true\nlock-delay=uint32 60\n",
    "[org/gnome/desktop/session]\nidle-delay=uint32 900\n"
    "[org/gnome/desktop/screensaver]\nlock-delay=uint32 5\nlock-enabled=false\n",
], ids=["lock-enabled-only", "old-fix", "idle-0", "idle-1800", "lock-delay-60", "lock-disabled"])
def test_screenlock_requires_cis_idle_and_lock_delay(dconf, content):
    dconf.set_profile("user-db:user\nsystem-db:local\n")
    dconf.write("00-screensaver", content)
    dconf.compile()
    assert gdm._check_gdm_screenlock().status != "pass"


def test_screenlock_later_keyfile_overrides_earlier(dconf):
    dconf.set_profile("user-db:user\nsystem-db:local\n")
    dconf.write("00-screensaver", _CIS_SCREENLOCK)
    dconf.write("99-local", "[org/gnome/desktop/session]\nidle-delay=uint32 0\n")
    dconf.compile()
    assert gdm._check_gdm_screenlock().status != "pass"


@pytest.mark.parametrize("locks", [
    "/org/gnome/desktop/screensaver/lock-enabled\n",
    # The old fixer output: screensaver/idle-delay does not exist.
    "/org/gnome/desktop/screensaver/lock-enabled\n"
    "/org/gnome/desktop/screensaver/lock-delay\n"
    "/org/gnome/desktop/screensaver/idle-delay\n",
    "/org/gnome/desktop/session/idle-delay\n",
], ids=["lock-enabled-only", "old-fix", "idle-only"])
def test_lock_override_requires_both_cis_locks(dconf, locks):
    dconf.set_profile("user-db:user\nsystem-db:local\n")
    dconf.write("locks/00-screensaver", locks)
    dconf.compile()
    assert gdm._check_gdm_lock_override().status != "pass"


@pytest.mark.parametrize("cid", sorted(_FIXERS))
def test_fixer_creates_the_profile_and_round_trips(dconf, cid):
    fix, check = _FIXERS[cid]
    assert check().status != "pass"
    entries = fix()
    assert dconf.profile.read_text() == "user-db:user\nsystem-db:local\n"
    assert ["dconf", "update"] in dconf.calls
    assert check().status == "pass"
    prof = [e for e in entries if e.path == str(dconf.profile)]
    assert prof and prof[0].undo == [["rm", "-f", "--", str(dconf.profile)]]


def test_fixer_extends_an_existing_profile(dconf):
    dconf.set_profile("user-db:user\nsystem-db:site\n")
    entries = gdm._fix_gdm_autorun()
    assert dconf.profile.read_text() == "user-db:user\nsystem-db:site\nsystem-db:local\n"
    prof = [e for e in entries if e.path == str(dconf.profile)]
    assert prof and prof[0].backup and pathlib.Path(prof[0].backup).read_text() == \
        "user-db:user\nsystem-db:site\n"
    assert gdm._check_gdm_autorun().status == "pass"


def test_fixer_leaves_a_working_profile_alone(dconf):
    dconf.set_profile("user-db:user\nsystem-db:local\n")
    entries = gdm._fix_gdm_screenlock()
    assert all(e.path != str(dconf.profile) for e in entries)
    assert gdm._check_gdm_screenlock().status == "pass"


def test_fixer_restores_the_profile_when_dconf_update_fails(dconf, monkeypatch):
    monkeypatch.setattr(gdm.subprocess, "run", lambda argv, *a, **kw: _cp(argv, rc=1))
    with pytest.raises(RuntimeError):
        gdm._fix_gdm_autorun()
    assert not dconf.profile.exists()


# ============================ IPv6 disabled ============================

def _proc(tmp_path, monkeypatch, entries):
    net = tmp_path / "net"
    for name, value in entries.items():
        d = net / "ipv6" / "conf" / name
        d.mkdir(parents=True)
        (d / "disable_ipv6").write_text(value + "\n")
    monkeypatch.setattr(sysctl, "PROC_SYS_NET", str(net))


_PARTIAL = {"all": "1", "default": "1", "lo": "1", "eth0": "0"}
_OFF = {"all": "1", "default": "1", "lo": "1", "eth0": "1"}


def _sysctl_says_disabled(monkeypatch, module, forwarding="1"):
    """`sysctl -n` reports all.disable_ipv6 = 1 (the old, sole test)."""
    def fake_run(argv, *a, **kw):
        if argv[:2] == ["sysctl", "-n"]:
            return _cp(argv, out="1\n" if argv[2].endswith("disable_ipv6") else forwarding + "\n")
        return _cp(argv)
    monkeypatch.setattr(module.subprocess, "run", fake_run)


def test_firewall_private_ipv6_helper_removed():
    assert not hasattr(firewall, "_ipv6_disabled")


@pytest.mark.parametrize("check", [
    firewall._check_ip6tables_default_deny,
    firewall._check_ip6tables_loopback,
    firewall._check_ip6tables_established,
])
def test_ip6tables_checks_need_ipv6_off_everywhere(tmp_path, monkeypatch, check):
    _sysctl_says_disabled(monkeypatch, firewall)
    monkeypatch.setattr(firewall, "_cmd_exists", lambda name: True)
    monkeypatch.setattr(firewall, "_ip6tables_rules", lambda: "")
    _proc(tmp_path, monkeypatch, _PARTIAL)
    assert check().status != "pass"


def test_ip6tables_check_still_passes_when_ipv6_is_off(tmp_path, monkeypatch):
    monkeypatch.setattr(firewall, "_cmd_exists", lambda name: True)
    monkeypatch.setattr(firewall, "_ip6tables_rules", lambda: "")
    _proc(tmp_path, monkeypatch, _OFF)
    assert firewall._check_ip6tables_default_deny().status == "pass"


def test_ip6tables_fixer_does_not_skip_on_all_only(tmp_path, monkeypatch):
    _sysctl_says_disabled(monkeypatch, firewall)
    monkeypatch.setattr(firewall, "_persist_ip6tables_v6", lambda: None)
    monkeypatch.setattr(journal, "backup_file", lambda p: "")
    _proc(tmp_path, monkeypatch, _PARTIAL)
    assert firewall._fix_ip6tables_default_deny() != []


def test_ipv6_forwarding_needs_ipv6_off_everywhere(tmp_path, monkeypatch):
    _sysctl_says_disabled(monkeypatch, extras, forwarding="1")
    _proc(tmp_path, monkeypatch, _PARTIAL)
    assert extras._check_ipv6_forwarding().status == "fail"
    _proc(tmp_path / "off", monkeypatch, _OFF)
    assert extras._check_ipv6_forwarding().status == "pass"


def test_ipv6_ra_needs_ipv6_off_everywhere(tmp_path, monkeypatch):
    monkeypatch.setattr(network, "_get_sysctl",
                        lambda key: "1")  # disable_ipv6 = 1 and accept_ra = 1
    _proc(tmp_path, monkeypatch, _PARTIAL)
    assert network._check_ipv6_ra().status == "fail"
    _proc(tmp_path / "off", monkeypatch, _OFF)
    assert network._check_ipv6_ra().status == "pass"


# ============================ 3.5.4 boot-time loader ============================

@pytest.fixture
def fw_files(tmp_path, monkeypatch):
    paths = {}
    for const in ("IPTABLES_V4_RULES", "IPTABLES_V6_RULES", "SYSCONFIG_IPTABLES",
                  "NFTABLES_CONF", "UFW_CONF"):
        paths[const] = tmp_path / const.lower()
        monkeypatch.setattr(firewall, const, str(paths[const]))
    return paths


def _systemd(monkeypatch, enabled: set[str], calls=None):
    def fake_run(argv, *a, **kw):
        if calls is not None:
            calls.append(argv)
        if argv[:2] == ["systemctl", "is-enabled"]:
            on = argv[2] in enabled
            return _cp(argv, rc=0 if on else 1, out="enabled\n" if on else "disabled\n")
        if argv[:2] == ["systemctl", "enable"]:
            enabled.add(argv[2])
            return _cp(argv)
        return _cp(argv)
    monkeypatch.setattr(firewall.subprocess, "run", fake_run)


@pytest.mark.parametrize("const, unit", [
    ("IPTABLES_V4_RULES", "netfilter-persistent"),
    ("SYSCONFIG_IPTABLES", "iptables"),
    ("NFTABLES_CONF", "nftables"),
])
def test_saved_rules_need_a_loader(fw_files, monkeypatch, const, unit):
    fw_files[const].write_text("*filter\nCOMMIT\n")
    _systemd(monkeypatch, set())
    assert firewall._check_iptables_persistent().status != "pass"
    _systemd(monkeypatch, {unit})
    assert firewall._check_iptables_persistent().status == "pass"


def test_saved_rules_without_systemctl_do_not_pass(fw_files, monkeypatch):
    fw_files["IPTABLES_V4_RULES"].write_text("*filter\nCOMMIT\n")

    def no_systemctl(argv, *a, **kw):
        raise FileNotFoundError(argv[0])
    monkeypatch.setattr(firewall.subprocess, "run", no_systemctl)
    assert firewall._check_iptables_persistent().status != "pass"


def test_ufw_counts_only_when_enabled_in_ufw_conf(fw_files, monkeypatch):
    _systemd(monkeypatch, {"ufw"})  # Debian enables ufw.service by default
    fw_files["UFW_CONF"].write_text("ENABLED=no\n")
    assert firewall._check_iptables_persistent().status != "pass"
    fw_files["UFW_CONF"].write_text("ENABLED=yes\n")
    assert firewall._check_iptables_persistent().status == "pass"


def test_firewalld_enabled_passes(fw_files, monkeypatch):
    _systemd(monkeypatch, {"firewalld"})
    assert firewall._check_iptables_persistent().status == "pass"


def test_persistent_fixer_enables_a_loader_and_round_trips(fw_files, monkeypatch):
    enabled: set[str] = set()
    calls: list = []
    _systemd(monkeypatch, enabled, calls)
    monkeypatch.setattr(firewall, "_cmd_exists", lambda name: True)
    monkeypatch.setattr(firewall.distro, "is_debian_family", lambda: True)
    monkeypatch.setattr(firewall.pkg, "is_installed", lambda name: True)
    monkeypatch.setattr(firewall, "ipv6_disabled", lambda: True)
    monkeypatch.setattr(journal, "backup_file", lambda p: "")
    monkeypatch.setattr(firewall, "_persist_iptables_v4",
                        lambda: fw_files["IPTABLES_V4_RULES"].write_text("*filter\nCOMMIT\n"))
    assert firewall._check_iptables_persistent().status != "pass"
    entries = firewall._fix_iptables_persistent()
    assert ["systemctl", "enable", "netfilter-persistent"] in calls
    assert any(e.undo == [["systemctl", "disable", "netfilter-persistent"]] for e in entries)
    assert firewall._check_iptables_persistent().status == "pass"


# ============================ 3.5.2.4 open ports ============================

def _ss(monkeypatch, rc=0, out=""):
    def fake_run(argv, *a, **kw):
        assert argv[:2] == ["ss", "-H"] and "u" in argv[2], argv
        return _cp(argv, rc=rc, out=out)
    monkeypatch.setattr(firewall.subprocess, "run", fake_run)


@pytest.fixture
def open_ports(monkeypatch):
    monkeypatch.setattr(firewall, "_cmd_exists", lambda name: True)

    def serve(rules, ss_out, rc=0):
        monkeypatch.setattr(firewall, "_iptables_rules", lambda: rules)
        _ss(monkeypatch, rc=rc, out=ss_out)
        return firewall._check_iptables_open_ports()
    return serve


_SSH_RULE = "-P INPUT DROP\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n"
_TCP22 = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"


@pytest.mark.parametrize("ss_out, rules, expected", [
    # An uncovered UDP listener used to be invisible (ss -tlnp).
    (_TCP22 + "udp UNCONN 0 0 0.0.0.0:161 0.0.0.0:*\n", _SSH_RULE, "warn"),
    # A TCP rule on the same port does not cover the UDP listener.
    (_TCP22 + "udp UNCONN 0 0 *:22 *:*\n", _SSH_RULE, "warn"),
    (_TCP22 + "udp UNCONN 0 0 0.0.0.0:161 0.0.0.0:*\n",
     _SSH_RULE + "-A INPUT -p udp -m udp --dport 161 -j ACCEPT\n", "pass"),
    # Loopback-only listeners are skipped, as CIS does.
    (_TCP22 + "udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\n"
     "tcp LISTEN 0 4096 [::1]:631 [::]:*\n"
     "tcp LISTEN 0 4096 [::ffff:127.0.0.1]:8080 *:*\n", _SSH_RULE, "pass"),
], ids=["udp-uncovered", "udp-vs-tcp-rule", "udp-covered", "loopback-skipped"])
def test_open_ports_include_udp(open_ports, ss_out, rules, expected):
    assert open_ports(rules, ss_out).status == expected


def test_open_ports_ss_failure_is_not_a_pass(open_ports):
    assert open_ports(_SSH_RULE, "", rc=1).status != "pass"


def test_open_ports_ss_missing_is_not_a_pass(monkeypatch):
    monkeypatch.setattr(firewall, "_cmd_exists", lambda name: True)

    def no_ss(argv, *a, **kw):
        raise FileNotFoundError(argv[0])
    monkeypatch.setattr(firewall.subprocess, "run", no_ss)
    assert firewall._check_iptables_open_ports().status != "pass"
