# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file,
# via any medium, is strictly prohibited without explicit written authorization.

"""Round-3 false-pass regression tests for the network (3.1.x / 3.3.x) and
service (2.2.x) checks.

Cases:
- 3.1.x / 3.3.x read only the running kernel. A value set with `sysctl -w`
  and never persisted, or overridden by a sysctl.d file that reapplies the
  bad value at boot, passed. CIS audits both. The persisted value follows
  systemd-sysctl: *.conf only, sorted by file name, /etc shadowing
  /usr/lib, the last explicit assignment winning over globs.
- 3.3.1 and 3.3.2 ignored the IPv6 keys CIS lists, so a host with IPv6
  enabled accepting IPv6 ICMP redirects (the kernel default) passed.
- 3.1.1 and 3.3.9 passed when an IPv6 key could not be read on a host with
  IPv6 enabled.
- 2.2.x used Debian unit and package names only, so httpd, smb, dhcpd and
  rsyncd running on RHEL passed as "not installed".
- 2.2.2 / 2.2.3 ignored avahi-daemon.socket and cups.socket, so a disabled
  service that the enabled socket starts on demand passed.
- 2.2.x treated a held package (`hold ok installed`) as not installed, and
  a missing systemctl with the package installed as a pass.
- 2.2.15 read only postfix's inet_interfaces. Exim or any MTA listening on a
  non-loopback SMTP port passed, and so did postfix after `lss harden`,
  because the fixer reloaded postfix and a reload does not rebind listeners.
- Hardened hosts still pass, and the sysctl fixers satisfy their checks.
"""

from __future__ import annotations

import subprocess
import types

import pytest

from lss.controls import network, services
from lss.lib import journal, sysctl


# ---------------------------------------------------------------- sysctl ----

HARDENED = {
    "net.ipv4.conf.all.accept_source_route": "0",
    "net.ipv4.conf.default.accept_source_route": "0",
    "net.ipv6.conf.all.accept_source_route": "0",
    "net.ipv6.conf.default.accept_source_route": "0",
    "net.ipv4.conf.all.accept_redirects": "0",
    "net.ipv4.conf.default.accept_redirects": "0",
    "net.ipv6.conf.all.accept_redirects": "0",
    "net.ipv6.conf.default.accept_redirects": "0",
    "net.ipv4.conf.all.secure_redirects": "0",
    "net.ipv4.conf.default.secure_redirects": "0",
    "net.ipv4.conf.all.log_martians": "1",
    "net.ipv4.conf.default.log_martians": "1",
    "net.ipv4.ip_forward": "0",
    "net.ipv6.conf.all.forwarding": "0",
    "net.ipv4.conf.all.send_redirects": "0",
    "net.ipv4.conf.default.send_redirects": "0",
    "net.ipv4.icmp_echo_ignore_broadcasts": "1",
    "net.ipv4.icmp_ignore_bogus_error_responses": "1",
    "net.ipv4.conf.all.rp_filter": "1",
    "net.ipv4.conf.default.rp_filter": "1",
    "net.ipv4.tcp_syncookies": "1",
    "net.ipv6.conf.all.accept_ra": "0",
    "net.ipv6.conf.default.accept_ra": "0",
}

CHECKS = [
    ("3.3.1", network._check_source_route, network._fix_source_route),
    ("3.3.2", network._check_icmp_redirect, network._fix_icmp_redirect),
    ("3.3.3", network._check_secure_redirect, network._fix_secure_redirect),
    ("3.3.4", network._check_log_martians, network._fix_log_martians),
    ("3.1.1", network._check_ip_forward, network._fix_ip_forward),
    ("3.1.2", network._check_send_redirects, network._fix_send_redirects),
    ("3.3.5", network._check_icmp_echo_broadcast, network._fix_icmp_echo_broadcast),
    ("3.3.6", network._check_bogus_icmp, network._fix_bogus_icmp),
    ("3.3.7", network._check_rp_filter, network._fix_rp_filter),
    ("3.3.8", network._check_syn_cookies, network._fix_syn_cookies),
    ("3.3.9", network._check_ipv6_ra, network._fix_ipv6_ra),
]


def _conf(values: dict[str, str]) -> str:
    return "".join(f"{k} = {v}\n" for k, v in values.items())


@pytest.fixture
def host(tmp_path, monkeypatch):
    """A fake kernel (runtime dict) plus fake sysctl.d trees under tmp_path."""
    etc = tmp_path / "etc" / "sysctl.d"
    usr = tmp_path / "usr" / "lib" / "sysctl.d"
    etc.mkdir(parents=True)
    usr.mkdir(parents=True)
    monkeypatch.setattr(network, "_SYSCTL_D_DIRS", [str(etc), str(usr)])
    monkeypatch.setattr(sysctl, "SYSCTL_CONF", str(etc / "99-zzz-lss.conf"))
    monkeypatch.setattr(journal, "backup_file", lambda p: None)
    runtime = dict(HARDENED)
    state = types.SimpleNamespace(runtime=runtime, etc=etc, usr=usr, ipv6_off=False)
    monkeypatch.setattr(network, "_ipv6_disabled", lambda: state.ipv6_off)

    def fake_run(cmd, *a, **kw):
        if cmd[:2] == ["sysctl", "-n"]:
            val = runtime.get(cmd[2])
            if val is None:
                return subprocess.CompletedProcess(cmd, 255, "", "unknown key")
            return subprocess.CompletedProcess(cmd, 0, val + "\n", "")
        if cmd[:2] == ["sysctl", "-w"]:
            k, v = cmd[2].split("=", 1)
            runtime[k] = v
            return subprocess.CompletedProcess(cmd, 0, "", "")
        raise AssertionError(f"unexpected command {cmd}")

    monkeypatch.setattr(sysctl.subprocess, "run", fake_run)
    return state


@pytest.mark.parametrize("cid,check,fix", CHECKS, ids=[c[0] for c in CHECKS])
def test_hardened_host_passes(host, cid, check, fix):
    (host.etc / "60-cis.conf").write_text(_conf(HARDENED))
    assert check().status == "pass"


@pytest.mark.parametrize("cid,check,fix", CHECKS, ids=[c[0] for c in CHECKS])
def test_runtime_only_value_fails(host, cid, check, fix):
    # Set with `sysctl -w`, nothing persisted: reverts at the next boot.
    assert check().status == "fail"


@pytest.mark.parametrize("cid,check,fix", CHECKS, ids=[c[0] for c in CHECKS])
def test_fixer_satisfies_check(host, cid, check, fix):
    # Runtime wrong everywhere, nothing persisted: harden must turn it green.
    for k, v in HARDENED.items():
        host.runtime[k] = "1" if v == "0" else "0"
    assert check().status == "fail"
    fix()
    assert check().status == "pass"


def test_later_file_reapplies_bad_value(host):
    (host.etc / "60-cis.conf").write_text(_conf(HARDENED))
    (host.etc / "90-router.conf").write_text("net.ipv4.ip_forward = 1\n")
    r = network._check_ip_forward()
    assert r.status == "fail" and "ip_forward" in r.detail


def test_earlier_file_overridden_by_later_good_value_passes(host):
    (host.usr / "50-default.conf").write_text("net.ipv4.ip_forward = 1\n")
    (host.etc / "60-cis.conf").write_text(_conf(HARDENED))
    assert network._check_ip_forward().status == "pass"


def test_etc_file_shadows_usr_lib_file_of_same_name(host):
    (host.etc / "60-cis.conf").write_text(_conf(HARDENED))
    (host.usr / "70-vendor.conf").write_text("net.ipv4.tcp_syncookies = 0\n")
    assert network._check_syn_cookies().status == "fail"
    # The admin's /etc copy of the same file name replaces the vendor one.
    (host.etc / "70-vendor.conf").write_text("# disabled\n")
    assert network._check_syn_cookies().status == "pass"


def test_commented_and_non_conf_files_do_not_count(host):
    (host.etc / "60-cis.conf").write_text(
        "# net.ipv4.conf.all.rp_filter = 1\n;net.ipv4.conf.default.rp_filter = 1\n"
    )
    (host.etc / "61-cis.conf.bak").write_text(_conf(HARDENED))
    assert network._check_rp_filter().status == "fail"


def test_inline_comment_value_is_not_the_value(host):
    # systemd-sysctl writes the whole remainder; the kernel rejects it.
    (host.etc / "60-cis.conf").write_text(
        "net.ipv4.tcp_syncookies = 1 # CIS 3.3.8\n"
    )
    assert network._check_syn_cookies().status == "fail"


def test_glob_sets_bad_value_unless_explicit_key(host):
    (host.etc / "60-cis.conf").write_text(
        _conf({k: v for k, v in HARDENED.items() if "rp_filter" not in k}))
    (host.etc / "80-glob.conf").write_text("net.ipv4.conf.*.rp_filter = 2\n")
    assert network._check_rp_filter().status == "fail"
    # An explicit assignment always beats a glob, wherever it appears.
    (host.etc / "10-explicit.conf").write_text(
        "net.ipv4.conf.all.rp_filter = 1\nnet.ipv4.conf.default.rp_filter = 1\n"
    )
    assert network._check_rp_filter().status == "pass"


def test_slash_separated_keys_are_read(host):
    (host.etc / "60-cis.conf").write_text("net/ipv4/tcp_syncookies = 1\n")
    assert network._check_syn_cookies().status == "pass"


def test_unreadable_sysctl_d_is_not_a_pass(host, monkeypatch):
    (host.etc / "60-cis.conf").write_text(_conf(HARDENED))
    monkeypatch.setattr(network, "_read_text", lambda p: (_ for _ in ()).throw(PermissionError()))
    assert network._check_syn_cookies().status == "warn"


@pytest.mark.parametrize("key,check", [
    ("net.ipv6.conf.all.accept_redirects", network._check_icmp_redirect),
    ("net.ipv6.conf.default.accept_redirects", network._check_icmp_redirect),
    ("net.ipv6.conf.all.accept_source_route", network._check_source_route),
])
def test_ipv6_keys_checked_when_ipv6_enabled(host, key, check):
    (host.etc / "60-cis.conf").write_text(_conf(HARDENED))
    host.runtime[key] = "1"
    r = check()
    assert r.status == "fail" and key in r.detail


def test_ipv6_keys_ignored_when_ipv6_disabled(host):
    v4 = {k: v for k, v in HARDENED.items() if not k.startswith("net.ipv6")}
    (host.etc / "60-cis.conf").write_text(_conf(v4))
    host.ipv6_off = True
    host.runtime["net.ipv6.conf.all.accept_redirects"] = "1"
    host.runtime["net.ipv6.conf.all.forwarding"] = "1"
    assert network._check_icmp_redirect().status == "pass"
    assert network._check_ip_forward().status == "pass"
    assert network._check_ipv6_ra().status == "pass"


@pytest.mark.parametrize("key,check", [
    ("net.ipv6.conf.all.forwarding", network._check_ip_forward),
    ("net.ipv6.conf.all.accept_ra", network._check_ipv6_ra),
])
def test_unreadable_ipv6_key_with_ipv6_enabled_is_not_a_pass(host, key, check):
    (host.etc / "60-cis.conf").write_text(_conf(HARDENED))
    del host.runtime[key]
    assert check().status != "pass"


# -------------------------------------------------------------- services ----

def _svc_env(monkeypatch, units: dict[str, tuple[str, str]], pkgs: dict[str, str],
             systemctl: bool = True, old_systemd: bool = False):
    """units: name -> (is-enabled output, is-active output); pkgs: name -> dpkg Status."""

    def unit(name):
        return name if "." in name else name + ".service"

    def fake_run(cmd, *a, **kw):
        if cmd[0] == "systemctl":
            if not systemctl:
                raise FileNotFoundError("systemctl")
            u = units.get(unit(cmd[2]))
            if cmd[1] == "is-enabled":
                if u is None:
                    if old_systemd:
                        return subprocess.CompletedProcess(
                            cmd, 1, "",
                            f"Failed to get unit file state for {unit(cmd[2])}: "
                            "No such file or directory\n")
                    return subprocess.CompletedProcess(cmd, 4, "not-found\n", "")
                return subprocess.CompletedProcess(cmd, 0 if u[0] == "enabled" else 1, u[0] + "\n", "")
            if cmd[1] == "is-active":
                state = u[1] if u else "inactive"
                return subprocess.CompletedProcess(cmd, 0 if state == "active" else 3, state + "\n", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd[0] == "dpkg-query":
            st = pkgs.get(cmd[-1])
            if st is None:
                return subprocess.CompletedProcess(cmd, 1, "", "no packages found")
            return subprocess.CompletedProcess(cmd, 0, st, "")
        if cmd[0] == "rpm":
            raise FileNotFoundError("rpm")
        raise AssertionError(f"unexpected command {cmd}")

    monkeypatch.setattr(services.subprocess, "run", fake_run)


def _control(cid):
    import lss.list_controls  # noqa: F401
    from lss.lib.registry import get_controls
    return next(c for c in get_controls() if c.id == cid)


@pytest.mark.parametrize("cid,unit", [
    ("2.2.9", "httpd.service"),
    ("2.2.11", "smb.service"),
    ("2.2.4", "dhcpd.service"),
    ("2.2.16", "rsyncd.service"),
    ("2.2.9", "nginx.service"),
])
def test_rhel_unit_names_are_checked(monkeypatch, cid, unit):
    _svc_env(monkeypatch, {unit: ("enabled", "active")}, {})
    assert _control(cid).check().status == "fail"


@pytest.mark.parametrize("cid,unit", [
    ("2.2.2", "avahi-daemon.socket"),
    ("2.2.3", "cups.socket"),
])
def test_enabled_socket_activation_fails(monkeypatch, cid, unit):
    svc = unit.replace(".socket", ".service")
    _svc_env(monkeypatch, {svc: ("disabled", "inactive"), unit: ("enabled", "active")},
             {"avahi-daemon": "install ok installed", "cups": "install ok installed"})
    r = _control(cid).check()
    assert r.status == "fail" and unit.split(".")[0] in r.detail


def test_masked_service_and_socket_pass(monkeypatch):
    _svc_env(monkeypatch, {"cups.service": ("masked", "inactive"),
                           "cups.socket": ("masked", "inactive")},
             {"cups": "install ok installed"})
    assert _control("2.2.3").check().status == "pass"
    # CIS masks the service and socket only; cups.path is left behind.
    _svc_env(monkeypatch, {"cups.service": ("masked", "inactive"),
                           "cups.socket": ("masked", "inactive"),
                           "cups.path": ("enabled", "active")},
             {"cups": "install ok installed"})
    assert _control("2.2.3").check().status == "pass"


def test_path_unit_starting_disabled_service_fails(monkeypatch):
    _svc_env(monkeypatch, {"cups.service": ("disabled", "inactive"),
                           "cups.socket": ("disabled", "inactive"),
                           "cups.path": ("enabled", "active")},
             {"cups": "install ok installed"})
    assert _control("2.2.3").check().status == "fail"


def test_not_installed_passes(monkeypatch):
    _svc_env(monkeypatch, {}, {})
    assert _control("2.2.9").check().status == "pass"
    _svc_env(monkeypatch, {}, {}, old_systemd=True)
    assert _control("2.2.9").check().status == "pass"


def test_held_package_counts_as_installed(monkeypatch):
    _svc_env(monkeypatch, {}, {"snmpd": "hold ok installed"})
    assert services._pkg_is_installed("snmpd") is True
    _svc_env(monkeypatch, {}, {"snmpd": "deinstall ok config-files"})
    assert services._pkg_is_installed("snmpd") is False


def test_missing_systemctl_with_package_installed_is_not_a_pass(monkeypatch):
    _svc_env(monkeypatch, {}, {"apache2": "install ok installed"}, systemctl=False)
    assert _control("2.2.9").check().status == "warn"
    _svc_env(monkeypatch, {}, {}, systemctl=False)
    assert _control("2.2.9").check().status == "pass"


def test_fixer_masks_socket_too(monkeypatch):
    calls = []
    _svc_env(monkeypatch, {"cups.service": ("enabled", "active"),
                           "cups.socket": ("enabled", "active")}, {})
    real = services.subprocess.run

    def spy(cmd, *a, **kw):
        calls.append(cmd)
        return real(cmd, *a, **kw)

    monkeypatch.setattr(services.subprocess, "run", spy)
    _control("2.2.3").fix()
    assert ["systemctl", "mask", "cups.socket"] in calls
    assert ["systemctl", "stop", "cups.socket"] in calls


# ------------------------------------------------------------------ 2.2.15 ----

def _mta_env(monkeypatch, ss_out: str | None, inet: str | None, pkgs=(), calls=None):
    def fake_run(cmd, *a, **kw):
        if calls is not None:
            calls.append(cmd)
        if cmd[0] == "ss":
            if ss_out is None:
                return subprocess.CompletedProcess(cmd, 1, "", "ss failed")
            return subprocess.CompletedProcess(cmd, 0, ss_out, "")
        if cmd[0] == "postconf":
            if cmd[1] == "-e":
                return subprocess.CompletedProcess(cmd, 0, "", "")
            if inet is None:
                raise FileNotFoundError("postconf")
            return subprocess.CompletedProcess(cmd, 0, inet + "\n", "")
        if cmd[0] == "dpkg-query":
            if cmd[-1] in pkgs:
                return subprocess.CompletedProcess(cmd, 0, "install ok installed", "")
            return subprocess.CompletedProcess(cmd, 1, "", "")
        if cmd[0] == "rpm":
            raise FileNotFoundError("rpm")
        if cmd[0] == "systemctl":
            return subprocess.CompletedProcess(cmd, 0, "", "")
        raise AssertionError(f"unexpected command {cmd}")

    monkeypatch.setattr(services.subprocess, "run", fake_run)


LOCAL_SS = (
    "tcp   LISTEN 0 100   127.0.0.1:25   0.0.0.0:*\n"
    "tcp   LISTEN 0 100       [::1]:25      [::]:*\n"
    "tcp   LISTEN 0 128     0.0.0.0:22   0.0.0.0:*\n"
)


def test_exim_listening_on_all_interfaces_fails(monkeypatch):
    ss = LOCAL_SS + "tcp   LISTEN 0 20      0.0.0.0:25   0.0.0.0:*\n"
    _mta_env(monkeypatch, ss, None, pkgs=("exim4-daemon-light",))
    r = services._check_mta_local_only()
    assert r.status == "fail" and "0.0.0.0:25" in r.detail


@pytest.mark.parametrize("addr", ["*:587", "[::]:465", "192.0.2.10:25", "10.0.0.5%eth0:25"])
def test_any_non_loopback_smtp_listener_fails(monkeypatch, addr):
    ss = LOCAL_SS + f"tcp   LISTEN 0 100   {addr}   0.0.0.0:*\n"
    _mta_env(monkeypatch, ss, "loopback-only", pkgs=("postfix",))
    assert services._check_mta_local_only().status == "fail"


def test_loopback_only_postfix_passes(monkeypatch):
    _mta_env(monkeypatch, LOCAL_SS, "loopback-only", pkgs=("postfix",))
    assert services._check_mta_local_only().status == "pass"


def test_no_mta_passes(monkeypatch):
    _mta_env(monkeypatch, "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n", None)
    assert services._check_mta_local_only().status == "pass"


def test_ss_failure_with_mta_installed_is_not_a_pass(monkeypatch):
    _mta_env(monkeypatch, None, "loopback-only", pkgs=("postfix",))
    assert services._check_mta_local_only().status == "warn"


def test_postfix_fixer_restarts_so_listener_rebinds(monkeypatch, tmp_path):
    calls = []
    maincf = tmp_path / "main.cf"
    maincf.write_text("inet_interfaces = all\n")
    monkeypatch.setattr(services, "_POSTFIX_MAIN_CF", str(maincf))
    monkeypatch.setattr(journal, "backup_file", lambda p: None)
    _mta_env(monkeypatch, LOCAL_SS, "all", pkgs=("postfix",), calls=calls)
    entries = services._fix_mta_local_only()
    assert ["systemctl", "restart", "postfix"] in calls
    assert ["systemctl", "reload", "postfix"] not in calls
    assert entries[0].undo == [["systemctl", "restart", "postfix"]]
