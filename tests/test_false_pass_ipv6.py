# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file,
# via any medium, is strictly prohibited without explicit written authorization.

"""False-pass regression tests for lss.lib.sysctl.ipv6_disabled.

Several IPv6 controls pass as "IPv6 is disabled" without reading their
rules. They used to trust net.ipv6.conf.all.disable_ipv6 = 1 alone, which
stays 1 after one interface is re-enabled (NetworkManager does this for
ipv6.method=auto), so the IPv6 firewall and forwarding checks passed on a
host with live IPv6.
"""

from __future__ import annotations

import pytest

from lss.lib import sysctl


def _proc(tmp_path, monkeypatch, entries: dict[str, str] | None):
    """Build a fake /proc/sys/net; entries=None means no ipv6 subtree."""
    net = tmp_path / "net"
    net.mkdir()
    if entries is not None:
        for name, value in entries.items():
            d = net / "ipv6" / "conf" / name
            d.mkdir(parents=True)
            (d / "disable_ipv6").write_text(value + "\n")
    monkeypatch.setattr(sysctl, "PROC_SYS_NET", str(net))


def test_all_entries_disabled(tmp_path, monkeypatch):
    _proc(tmp_path, monkeypatch, {"all": "1", "default": "1", "lo": "1", "eth0": "1"})
    assert sysctl.ipv6_disabled() is True


@pytest.mark.parametrize("enabled", ["eth0", "default", "lo"])
def test_one_enabled_entry_means_not_disabled(tmp_path, monkeypatch, enabled):
    # all = 1 stays set while a single interface (or the default for new ones)
    # has IPv6 back on: the old all-only test called this "disabled".
    entries = {"all": "1", "default": "1", "lo": "1", "eth0": "1"}
    entries[enabled] = "0"
    _proc(tmp_path, monkeypatch, entries)
    assert sysctl.ipv6_disabled() is False


def test_kernel_ipv6_disable_parameter(tmp_path, monkeypatch):
    # ipv6.disable=1: the kernel never creates /proc/sys/net/ipv6.
    _proc(tmp_path, monkeypatch, None)
    assert sysctl.ipv6_disabled() is True


def test_no_proc_is_never_assumed_disabled(tmp_path, monkeypatch):
    monkeypatch.setattr(sysctl, "PROC_SYS_NET", str(tmp_path / "missing"))
    assert sysctl.ipv6_disabled() is False


def test_unreadable_entry_is_never_assumed_disabled(tmp_path, monkeypatch):
    _proc(tmp_path, monkeypatch, {"all": "1"})
    # An interface directory with no disable_ipv6 file: read fails.
    (tmp_path / "net" / "ipv6" / "conf" / "eth0").mkdir()
    assert sysctl.ipv6_disabled() is False
