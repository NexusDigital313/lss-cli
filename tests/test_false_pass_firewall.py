# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file,
# via any medium, is strictly prohibited without explicit written authorization.

"""False-pass regression tests for lss/controls/firewall.py.

  - 3.6 recognised a wireless interface only by "wlan" or "wlp" in its
    `ip link show` line, so an up USB Wi-Fi adapter (systemd names it
    wlx<MAC>) or an onboard one (wlo*, wls*) passed. A failed `ip link show`
    printed nothing and passed too, as did 3.5.5.
  - 3.5.2.3 / 3.5.3.3 (ESTABLISHED) matched "ACCEPT" as a substring, so a
    jump to a custom chain like `-j ACCEPT_LOG` passed, and
    `startswith("-A INPUT")` accepted any chain named INPUT-something.
  - 3.5.3.2 (ip6tables loopback) was a whole-ruleset substring test; it now
    mirrors the IPv4 check (whole line, chain reachable from INPUT).
  - 3.5.2.4 counted OUTPUT rules, so `-A OUTPUT ... --dport 22` covered a
    listening sshd with no inbound rule.
"""

from __future__ import annotations

import subprocess

import pytest

from lss.controls import firewall

_WIRED = (
    "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n"
    "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
    "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\n"
    "    link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff\n"
)


def _iface(name: str, flags: str = "BROADCAST,MULTICAST,UP,LOWER_UP") -> str:
    return (
        f"3: {name}: <{flags}> mtu 1500 qdisc noqueue state UP mode DORMANT group default qlen 1000\n"
        "    link/ether 00:c0:ca:12:34:56 brd ff:ff:ff:ff:ff:ff\n"
    )


def _fake_ip(monkeypatch, stdout: str, returncode: int = 0) -> None:
    def fake_run(argv, *args, **kwargs):
        assert argv == ["ip", "link", "show"], argv
        return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr="")
    monkeypatch.setattr(firewall.subprocess, "run", fake_run)


@pytest.fixture
def no_sysfs(tmp_path, monkeypatch):
    """An empty sysfs root: no interface entries, so the name test decides."""
    monkeypatch.setattr(firewall, "_SYS_CLASS_NET", str(tmp_path / "sys-class-net"))


@pytest.mark.parametrize("name", ["wlx00c0ca123456", "wlo1", "wls1", "wlp2s0", "wlan0"])
def test_up_wireless_interface_is_reported(monkeypatch, no_sysfs, name):
    # wlx/wlo/wls are the cases the old "wlan"/"wlp" substring test missed.
    _fake_ip(monkeypatch, _WIRED + _iface(name))
    result = firewall._check_wireless_disabled()
    assert result.status == "warn"
    assert name in result.detail


def test_down_wireless_interface_passes(monkeypatch, no_sysfs):
    _fake_ip(monkeypatch, _WIRED + _iface("wlx00c0ca123456", flags="BROADCAST,MULTICAST"))
    assert firewall._check_wireless_disabled().status == "pass"


def test_wired_only_host_passes(monkeypatch, no_sysfs):
    _fake_ip(monkeypatch, _WIRED)
    assert firewall._check_wireless_disabled().status == "pass"


def test_altname_continuation_line_is_not_an_interface(monkeypatch, no_sysfs):
    _fake_ip(monkeypatch, _WIRED + "    altname wlp0s20u1\n")
    assert firewall._check_wireless_disabled().status == "pass"


def test_sysfs_identifies_a_renamed_wireless_interface(tmp_path, monkeypatch):
    sysfs = tmp_path / "sys-class-net"
    (sysfs / "office-wifi" / "phy80211").mkdir(parents=True)
    (sysfs / "lo").mkdir()
    (sysfs / "eth0").mkdir()
    monkeypatch.setattr(firewall, "_SYS_CLASS_NET", str(sysfs))
    _fake_ip(monkeypatch, _WIRED + _iface("office-wifi"))
    result = firewall._check_wireless_disabled()
    assert result.status == "warn"
    assert "office-wifi" in result.detail


def test_sysfs_overrides_the_name_fallback(tmp_path, monkeypatch):
    # A wired NIC that happens to be named wl*: sysfs shows no 802.11 phy.
    sysfs = tmp_path / "sys-class-net"
    (sysfs / "wlbackbone").mkdir(parents=True)
    monkeypatch.setattr(firewall, "_SYS_CLASS_NET", str(sysfs))
    _fake_ip(monkeypatch, _iface("wlbackbone"))
    assert firewall._check_wireless_disabled().status == "pass"


def test_failed_ip_link_is_not_a_pass(monkeypatch, no_sysfs):
    _fake_ip(monkeypatch, "", returncode=1)
    assert firewall._check_wireless_disabled().status != "pass"


def test_unused_interfaces_failed_ip_is_not_a_pass(monkeypatch):
    def fake_run(argv, *args, **kwargs):
        assert argv[0] == "ip", argv
        return subprocess.CompletedProcess(argv, 1, stdout="", stderr="err")
    monkeypatch.setattr(firewall.subprocess, "run", fake_run)
    assert firewall._check_unused_interfaces().status != "pass"


# --- Rule-based checks: iptables -S output, chains reachable from INPUT ---

@pytest.fixture
def firewall_rules(monkeypatch):
    """Serve `iptables -S` / `ip6tables -S` text to the checks under test."""
    monkeypatch.setattr(firewall, "_cmd_exists", lambda name: True)
    monkeypatch.setattr(firewall, "_ipv6_disabled", lambda: False)

    def serve(text: str) -> None:
        monkeypatch.setattr(firewall, "_iptables_rules", lambda: text)
        monkeypatch.setattr(firewall, "_ip6tables_rules", lambda: text)
    return serve


_POLICIES = "-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n"
_UFW_JUMP = "-N ufw-before-input\n-A INPUT -j ufw-before-input\n"

_ESTABLISHED_CHECKS = pytest.mark.parametrize(
    "check", ["_check_iptables_established", "_check_ip6tables_established"],
)


@_ESTABLISHED_CHECKS
@pytest.mark.parametrize("rules", [
    "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n",
    "-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT\n",
    # ufw keeps it in a chain INPUT jumps to; the old literal `-A INPUT`
    # test failed every ufw host.
    _UFW_JUMP + "-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n",
], ids=["conntrack", "state", "ufw"])
def test_established_accept_passes(firewall_rules, check, rules):
    firewall_rules(_POLICIES + rules)
    assert getattr(firewall, check)().status == "pass"


@_ESTABLISHED_CHECKS
@pytest.mark.parametrize("rules", [
    # A jump to a custom chain whose name starts with ACCEPT.
    "-N ACCEPT_LOG\n-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT_LOG\n"
    "-A ACCEPT_LOG -j LOG\n-A ACCEPT_LOG -j DROP\n",
    # A chain named INPUT-something that INPUT never jumps to.
    "-N INPUT_EXTRA\n-A INPUT_EXTRA -m conntrack --ctstate ESTABLISHED -j ACCEPT\n",
    # Negated state match.
    "-A INPUT -m conntrack ! --ctstate ESTABLISHED -j ACCEPT\n",
    # ESTABLISHED accepted, but only on OUTPUT.
    "-A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT\n",
], ids=["accept-log-chain", "unreachable-chain", "negated", "output-only"])
def test_established_old_false_pass_inputs_fail(firewall_rules, check, rules):
    firewall_rules(_POLICIES + rules)
    assert getattr(firewall, check)().status == "fail"


@pytest.mark.parametrize("rules, expected", [
    ("-A INPUT -i lo -j ACCEPT\n", "pass"),
    ("-N ufw6-before-input\n-A INPUT -j ufw6-before-input\n"
     "-A ufw6-before-input -i lo -j ACCEPT\n", "pass"),
    # The old substring test passed on this prefix of a custom-chain jump.
    ("-N ACCEPT_LOG\n-A INPUT -i lo -j ACCEPT_LOG\n", "fail"),
    ("-A OUTPUT -o lo -j ACCEPT\n", "fail"),
], ids=["input", "ufw", "accept-log-chain", "output-only"])
def test_ip6tables_loopback_matches_ipv4_semantics(firewall_rules, rules, expected):
    firewall_rules(_POLICIES + rules)
    assert firewall._check_ip6tables_loopback().status == expected


def _fake_ss(monkeypatch, ports):
    out = "".join(
        f'LISTEN 0 128 0.0.0.0:{p} 0.0.0.0:* users:(("svc",pid=1,fd=3))\n' for p in ports
    )

    def fake_run(argv, *args, **kwargs):
        assert argv[0] == "ss", argv
        return subprocess.CompletedProcess(argv, 0, stdout=out, stderr="")
    monkeypatch.setattr(firewall.subprocess, "run", fake_run)


@pytest.mark.parametrize("rules, expected", [
    ("-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n", "pass"),
    ("-A INPUT -p tcp -m multiport --dports 22,443 -j ACCEPT\n", "pass"),
    (_UFW_JUMP + "-A ufw-before-input -p tcp -m tcp --dport 22 -j ACCEPT\n", "pass"),
    # An outbound rule (ssh-ing out) used to count as covering the listener.
    ("-A OUTPUT -p tcp -m tcp --dport 22 -j ACCEPT\n", "warn"),
], ids=["input", "multiport", "ufw", "output-only"])
def test_open_ports_counts_only_inbound_rules(firewall_rules, monkeypatch, rules, expected):
    firewall_rules(_POLICIES + rules)
    _fake_ss(monkeypatch, [22])
    assert firewall._check_iptables_open_ports().status == expected
