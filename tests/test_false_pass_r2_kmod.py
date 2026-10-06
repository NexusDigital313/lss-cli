# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file,
# via any medium, is strictly prohibited without explicit written authorization.

"""False-pass regression tests, round 2: kernel modules, core dumps, find scans.

Kernel-module controls (1.1.1.x, 3.4.x, 1.1.15), now one helper (lss.lib.kmod):
  - `blacklist dccp` alone passed; blacklist only stops alias autoload, and a
    dependency or explicit modprobe still loads it. CIS needs install-null
    AND blacklist AND not loaded (or the module absent from the tree).
  - modprobe.d was read with glob("*"), so `.bak` / `.dpkg-old` files counted;
    kmod reads only *.conf, across five directories with earlier-dir masking.
  - names were not normalised: lsmod prints `usb_storage`, so a loaded
    usb-storage was never seen; `install usb_storage ...` was not matched.
  - `/usr/bin/false` / `/usr/bin/true` were rejected as install-null commands.
  - `modprobe --showconfig` (merged config) is authoritative when it works;
    unreadable config or loaded-module state is never a pass.
  - the fixers write both directives, and their output passes the check.
1.4.1 core dumps:
  - `ftp hard core 0` (a single-user domain) counted as the system limit.
  - a later `* hard core unlimited` in limits.d did not override an earlier 0.
6.1.9-6.1.13 scans:
  - `find / -xdev` never crossed into a separate /home, /var or /tmp; every
    local mount is now scanned, network and pseudo filesystems skipped.
  - an incomplete scan (timeout, unreadable mount table) is never a pass.
"""

from __future__ import annotations

import os
import subprocess

import pytest

from lss.controls import file_perms, filesystem, filesystem_perms, kernel, misc  # noqa: F401
from lss.lib import fsscan, journal, kmod
from lss.lib.registry import get_control

REL = "6.1.0-test"
DEP = (
    "kernel/net/dccp/dccp.ko.zst:\n"
    "kernel/net/dccp/dccp_ipv4.ko.zst: kernel/net/dccp/dccp.ko.zst\n"
    "kernel/net/sctp/sctp.ko:\n"
    "kernel/fs/cramfs/cramfs.ko:\n"
    "kernel/drivers/usb/storage/usb-storage.ko:\n"
)
LSMOD_HDR = "Module                  Size  Used by\n"


# ---------------------------------------------------------------- kmod setup

@pytest.fixture
def host(tmp_path, monkeypatch):
    """Fake modprobe dirs, module tree and subprocess for lss.lib.kmod.

    Returns a dict the test mutates: lsmod (stdout or None = fails),
    showconfig (stdout or None = fails)."""
    dirs = [tmp_path / d.strip("/").replace("/", "_") for d in kmod.MODPROBE_DIRS]
    for d in dirs:
        d.mkdir()
    monkeypatch.setattr(kmod, "MODPROBE_DIRS", [str(d) for d in dirs])
    tree = tmp_path / "modules" / REL
    tree.mkdir(parents=True)
    (tree / "modules.dep").write_text(DEP)
    (tree / "modules.builtin").write_text("kernel/drivers/tty/vt.ko\n")
    monkeypatch.setattr(kmod, "MODULES_ROOT", str(tmp_path / "modules"))
    monkeypatch.setattr(kmod, "_kernel_release", lambda: REL)
    monkeypatch.setattr(kmod, "PROC_MODULES", str(tmp_path / "no-proc-modules"))
    monkeypatch.setattr(journal, "backup_file", lambda path, run_id=None: "")

    state = {"lsmod": LSMOD_HDR, "showconfig": None, "etc": dirs[0], "lib": dirs[-1],
             "tree": tree, "calls": []}

    def fake_run(argv, *a, **kw):
        state["calls"].append(argv)
        if argv == ["lsmod"]:
            out = state["lsmod"]
        elif argv == ["modprobe", "--showconfig"]:
            out = state["showconfig"]
        elif argv[0] == "rmmod":
            out = ""
        else:
            raise AssertionError(argv)
        if out is None:
            return subprocess.CompletedProcess(argv, 1, stdout="", stderr="err")
        return subprocess.CompletedProcess(argv, 0, stdout=out, stderr="")

    monkeypatch.setattr(kmod.subprocess, "run", fake_run)
    return state


def _check(cid):
    return get_control(cid).check()


@pytest.mark.parametrize("cid,mod", [("3.4.1", "dccp"), ("1.1.1.1", "cramfs")])
def test_blacklist_only_is_not_disabled(host, cid, mod):
    (host["etc"] / f"{mod}.conf").write_text(f"blacklist {mod}\n")
    r = _check(cid)
    assert r.status == "fail"
    assert "install" in r.detail


@pytest.mark.parametrize("cid,mod", [("3.4.1", "dccp"), ("1.1.1.1", "cramfs")])
def test_install_null_only_is_not_disabled(host, cid, mod):
    (host["etc"] / f"{mod}.conf").write_text(f"install {mod} /bin/true\n")
    assert _check(cid).status == "fail"


@pytest.mark.parametrize("cmd", ["/bin/false", "/bin/true", "/usr/bin/false", "/usr/bin/true"])
def test_install_null_and_blacklist_passes(host, cmd):
    (host["etc"] / "dccp.conf").write_text(f"install dccp {cmd}\nblacklist dccp\n")
    assert _check("3.4.1").status == "pass"


@pytest.mark.parametrize("name", ["dccp.conf.bak", "dccp.conf.dpkg-old", "dccp"])
def test_non_conf_files_are_ignored(host, name):
    (host["etc"] / name).write_text("install dccp /bin/false\nblacklist dccp\n")
    assert _check("3.4.1").status == "fail"


def test_conf_in_lib_dir_counts_and_etc_masks_same_name(host):
    (host["lib"] / "dccp.conf").write_text("install dccp /bin/false\nblacklist dccp\n")
    assert _check("3.4.1").status == "pass"
    (host["etc"] / "dccp.conf").write_text("# masked\n")
    assert _check("3.4.1").status == "fail"


def test_loaded_module_fails(host):
    (host["etc"] / "dccp.conf").write_text("install dccp /bin/false\nblacklist dccp\n")
    host["lsmod"] = LSMOD_HDR + "dccp   20480  0\n"
    assert _check("3.4.1").status == "fail"


def test_showconfig_is_authoritative(host):
    # Files on disk look hardened, but the merged config says blacklist only.
    (host["etc"] / "dccp.conf").write_text("install dccp /bin/false\nblacklist dccp\n")
    host["showconfig"] = "blacklist dccp\nalias net-pf-33 dccp_ipv4\n"
    assert _check("3.4.1").status == "fail"
    host["showconfig"] = "install dccp /bin/false\nblacklist dccp\n"
    assert _check("3.4.1").status == "pass"


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads mode-000 files")
def test_unreadable_config_is_not_a_pass(host):
    f = host["etc"] / "dccp.conf"
    f.write_text("install dccp /bin/false\nblacklist dccp\n")
    f.chmod(0)
    try:
        assert _check("3.4.1").status == "warn"
    finally:
        f.chmod(0o644)


def test_unreadable_loaded_state_is_not_a_pass(host):
    (host["etc"] / "dccp.conf").write_text("install dccp /bin/false\nblacklist dccp\n")
    host["lsmod"] = None
    assert _check("3.4.1").status == "warn"


def test_module_absent_from_tree_passes(host):
    (host["tree"] / "modules.dep").write_text("kernel/fs/ext4/ext4.ko:\n")
    assert _check("3.4.1").status == "pass"


def test_builtin_module_fails(host):
    (host["tree"] / "modules.builtin").write_text("kernel/net/dccp/dccp.ko\n")
    (host["etc"] / "dccp.conf").write_text("install dccp /bin/false\nblacklist dccp\n")
    assert _check("3.4.1").status == "fail"


@pytest.mark.parametrize("cid,mod", [("3.4.1", "dccp"), ("1.1.1.1", "cramfs")])
def test_fixer_round_trip(host, cid, mod):
    (host["etc"] / f"{mod}.conf").write_text(f"blacklist {mod}\n")
    assert _check(cid).status == "fail"
    get_control(cid).fix()
    text = (host["etc"] / f"lss-{mod}.conf").read_text()
    assert f"blacklist {mod}" in text and f"install {mod} /bin/" in text
    assert _check(cid).status == "pass"


# ---------------------------------------------------------------- 1.1.15

def test_usb_storage_loaded_underscore_name_is_seen(host):
    (host["etc"] / "usb-storage.conf").write_text(
        "install usb-storage /bin/false\nblacklist usb-storage\n")
    host["lsmod"] = LSMOD_HDR + "usb_storage   81920  1 uas\n"
    assert _check("1.1.15").status == "manual"


def test_usb_storage_usr_bin_false_accepted(host):
    (host["etc"] / "usb-storage.conf").write_text(
        "install usb-storage /usr/bin/false\nblacklist usb-storage\n")
    assert _check("1.1.15").status == "pass"


def test_usb_storage_underscore_directives_match(host):
    (host["etc"] / "usb.conf").write_text("install usb_storage /bin/false\nblacklist usb-storage\n")
    assert _check("1.1.15").status == "pass"


def test_usb_storage_blacklist_only_not_disabled(host):
    (host["etc"] / "usb-storage.conf").write_text("blacklist usb-storage\n")
    assert _check("1.1.15").status == "manual"


def test_usb_storage_bak_file_ignored(host):
    (host["etc"] / "usb-storage.conf.dpkg-old").write_text(
        "install usb-storage /bin/false\nblacklist usb-storage\n")
    assert _check("1.1.15").status == "manual"


def test_usb_storage_fixer_round_trip(host):
    misc._fix_usb_storage()
    assert _check("1.1.15").status == "pass"


# ---------------------------------------------------------------- 1.4.1

@pytest.fixture
def limits(tmp_path, monkeypatch):
    conf = tmp_path / "limits.conf"
    d = tmp_path / "limits.d"
    d.mkdir()
    monkeypatch.setattr(filesystem_perms, "LIMITS_CONF", str(conf))
    monkeypatch.setattr(filesystem_perms, "LIMITS_D", str(d))

    def fake_run(argv, *a, **kw):
        assert argv == ["sysctl", "-n", "fs.suid_dumpable"], argv
        return subprocess.CompletedProcess(argv, 0, stdout="0\n", stderr="")
    monkeypatch.setattr(filesystem_perms.subprocess, "run", fake_run)
    monkeypatch.setattr(journal, "backup_file", lambda path, run_id=None: "")
    monkeypatch.setattr(filesystem_perms, "set_sysctl", lambda k, v: None)
    return conf, d


def test_user_domain_core_limit_does_not_count(limits):
    conf, _ = limits
    conf.write_text("ftp hard core 0\n")
    assert _check("1.4.1").status == "fail"


def test_later_limits_d_entry_overrides(limits):
    conf, d = limits
    conf.write_text("* hard core 0\n")
    (d / "90-dev.conf").write_text("* hard core unlimited\n")
    assert _check("1.4.1").status == "fail"


def test_limits_d_c_locale_order(limits):
    _, d = limits
    (d / "10-a.conf").write_text("* hard core unlimited\n")
    (d / "20-b.conf").write_text("*    -    core    0\n")
    assert _check("1.4.1").status == "pass"
    # C locale: 'B' (0x42) sorts before 'a' (0x61), so a.conf is applied last.
    (d / "a.conf").write_text("* hard core 0\n")
    (d / "B.conf").write_text("* hard core unlimited\n")
    assert _check("1.4.1").status == "pass"


def test_core_dump_fixer_round_trip(limits):
    _, d = limits
    (d / "80-lss.conf").write_text("ftp hard core 0\n")
    assert _check("1.4.1").status == "fail"
    get_control("1.4.1").fix()
    assert _check("1.4.1").status == "pass"


# ---------------------------------------------------------------- 6.1.9-6.1.13

MOUNTS = (
    "/dev/sda1 / ext4 rw 0 0\n"
    "proc /proc proc rw 0 0\n"
    "sysfs /sys sysfs rw 0 0\n"
    "/dev/sda2 /home ext4 rw 0 0\n"
    "/dev/sda3 /var xfs rw 0 0\n"
    "tmpfs /tmp tmpfs rw 0 0\n"
    "server:/x /mnt/nfs nfs4 rw 0 0\n"
    "/dev/sdb1 /mnt/my\\040disk ext4 rw 0 0\n"
)


@pytest.fixture
def scan(tmp_path, monkeypatch):
    m = tmp_path / "mounts"
    m.write_text(MOUNTS)
    monkeypatch.setattr(fsscan, "PROC_MOUNTS", str(m))
    state = {"hits": {}, "timeout": set(), "roots": []}

    def fake_run(argv, *a, **kw):
        if argv[0] == "chmod":
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        assert argv[0] == "find" and argv[2] == "-xdev", argv
        root = argv[1]
        state["roots"].append(root)
        if root in state["timeout"]:
            raise subprocess.TimeoutExpired(argv, kw.get("timeout"))
        out = "".join(p + "\n" for p in state["hits"].get(root, []))
        return subprocess.CompletedProcess(argv, 0, stdout=out, stderr="")

    monkeypatch.setattr(fsscan.subprocess, "run", fake_run)
    return state


def test_scan_covers_every_local_mount(scan):
    assert _check("6.1.9").status == "pass"
    assert scan["roots"] == ["/", "/home", "/var", "/tmp", "/mnt/my disk"]


@pytest.mark.parametrize("cid,mount", [
    ("6.1.9", "/home"), ("6.1.10", "/var"), ("6.1.11", "/tmp"), ("6.1.12", "/var"),
])
def test_finding_on_separate_mount_is_reported(scan, cid, mount):
    scan["hits"][mount] = [f"{mount}/thing"]
    r = _check(cid)
    assert r.status != "pass"
    assert f"{mount}/thing" in r.detail


def test_suid_on_separate_mount_counted(scan):
    scan["hits"]["/var"] = [f"/var/x{i}" for i in range(31)]
    assert _check("6.1.13").status == "warn"


@pytest.mark.parametrize("cid", ["6.1.9", "6.1.10", "6.1.11", "6.1.12", "6.1.13"])
def test_timeout_on_one_mount_is_not_a_pass(scan, cid):
    scan["timeout"].add("/home")
    r = _check(cid)
    assert r.status == "warn"
    assert "timed out" in r.detail


def test_unreadable_mount_table_is_not_a_pass(scan, tmp_path, monkeypatch):
    monkeypatch.setattr(fsscan, "PROC_MOUNTS", str(tmp_path / "missing"))
    assert _check("6.1.9").status == "warn"
    assert scan["roots"] == ["/"]


def test_sticky_fixer_covers_separate_mounts(scan, monkeypatch):
    scan["hits"]["/tmp"] = ["/tmp/open"]
    entries = filesystem_perms._fix_sticky_bit()
    assert [e.undo for e in entries] == [[["chmod", "o-t", "/tmp/open"]]]
