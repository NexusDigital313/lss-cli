# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file,
# via any medium, is strictly prohibited without explicit written authorization.

"""False-pass regression tests, round 2: account, cron and sshd checks.

Cases:
- 6.2.4 / 6.2.5 compared UIDs/GIDs as strings, so "0" and "00" (both root)
  were not duplicates, and a non-numeric ID passed; 6.2.3 skipped a
  non-numeric GID.
- 5.4.2 read only /etc/shadow, so an empty password field in /etc/passwd
  (no password needed) passed.
- 6.2.8 audited this process's PATH (sudo's secure_path) instead of root's
  login PATH, and never checked ownership, empty entries or non-directories.
- 5.1.9 passed on any /etc/at.allow, whatever its owner or mode.
- sshd: `sshd -T` without `-C` applies no Match blocks, so a Match block
  re-enabling root login passed; Match blocks in Include'd files are scanned
  too; a failing `sshd -T` is never a pass.
- 5.2.16 / 5.2.12 passed ClientAliveCountMax 0 (disables termination).
- 5.2.14 weak-MAC list lacked hmac-sha1 / umac-128; the fix's MACs round-trip.
- 5.2.18 passed when the Banner file was missing, empty or not a file.
"""

from __future__ import annotations

import os
import stat
import subprocess
from types import SimpleNamespace

import pytest

from lss.controls import cron, misc, ssh, users
from lss.lib import sshd


# ---------------------------------------------------------------- 6.2.3-5

def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return str(p)


PASSWD_OK = "root:x:0:0:root:/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\n"


@pytest.mark.parametrize("passwd", [
    PASSWD_OK + "toor:x:00:0::/root:/bin/bash\n",   # "00" is root
    PASSWD_OK + "evil:x:01000:1000::/home/e:/bin/sh\n",
])
def test_duplicate_uid_compared_numerically(tmp_path, monkeypatch, passwd):
    monkeypatch.setattr(users, "PASSWD_FILE", _write(tmp_path, "passwd", passwd))
    assert users._check_duplicate_uids().status == "fail"


def test_non_numeric_uid_is_not_a_pass(tmp_path, monkeypatch):
    monkeypatch.setattr(users, "PASSWD_FILE",
                        _write(tmp_path, "passwd", PASSWD_OK + "odd:x:abc:0::/:/bin/sh\n"))
    assert users._check_duplicate_uids().status == "fail"


def test_duplicate_gid_compared_numerically(tmp_path, monkeypatch):
    monkeypatch.setattr(users, "GROUP_FILE",
                        _write(tmp_path, "group", "root:x:0:\nwheel2:x:000:\n"))
    assert users._check_duplicate_gids().status == "fail"


def test_unique_ids_pass(tmp_path, monkeypatch):
    monkeypatch.setattr(users, "PASSWD_FILE", _write(tmp_path, "passwd", PASSWD_OK))
    monkeypatch.setattr(users, "GROUP_FILE", _write(tmp_path, "group", "root:x:0:\nbob:x:1000:\n"))
    assert users._check_duplicate_uids().status == "pass"
    assert users._check_duplicate_gids().status == "pass"


def test_non_numeric_passwd_gid_flagged(tmp_path, monkeypatch):
    import grp
    monkeypatch.setattr(users, "PASSWD_FILE",
                        _write(tmp_path, "passwd", PASSWD_OK + "odd:x:1001:xyz::/:/bin/sh\n"))
    monkeypatch.setattr(grp, "getgrall",
                        lambda: [SimpleNamespace(gr_gid=0), SimpleNamespace(gr_gid=1000)])
    assert users._check_groups_exist().status == "fail"


# ---------------------------------------------------------------- 5.4.2

SHADOW_OK = "root:$6$abc:19000:0:99999:7:::\nbob:!:19000:0:99999:7:::\n"


def _accounts(tmp_path, monkeypatch, passwd, shadow):
    monkeypatch.setattr(users, "PASSWD_FILE", _write(tmp_path, "passwd", passwd))
    sh = _write(tmp_path, "shadow", shadow) if shadow is not None else str(tmp_path / "nope")
    monkeypatch.setattr(users, "SHADOW_FILE", sh)


def test_empty_passwd_field_fails(tmp_path, monkeypatch):
    _accounts(tmp_path, monkeypatch, PASSWD_OK + "guest::1001:1001::/home/g:/bin/bash\n",
              SHADOW_OK)
    r = users._check_empty_passwords()
    assert r.status == "fail" and "guest" in r.detail


def test_empty_passwd_field_fails_even_without_shadow(tmp_path, monkeypatch):
    _accounts(tmp_path, monkeypatch, PASSWD_OK + "guest::1001:1001::/:/bin/sh\n", None)
    assert users._check_empty_passwords().status == "fail"


def test_empty_passwords_hardened(tmp_path, monkeypatch):
    _accounts(tmp_path, monkeypatch, PASSWD_OK, SHADOW_OK)
    assert users._check_empty_passwords().status == "pass"
    _accounts(tmp_path, monkeypatch, PASSWD_OK, None)
    assert users._check_empty_passwords().status == "warn"


# ---------------------------------------------------------------- 6.2.8

def _root_path(monkeypatch, path, rc=0, owners=None):
    """Fake `sudo -Hiu root env` output and directory ownership."""
    monkeypatch.setenv("PATH", "/usr/bin:/bin")   # the process PATH looks clean

    def run(cmd, *a, **k):
        return subprocess.CompletedProcess(cmd, rc, f"HOME=/root\nPATH={path}\n" if rc == 0 else "", "")
    monkeypatch.setattr(users.subprocess, "run", run)
    owners = owners or {}

    def fake_stat(p):
        st = os.stat(p)
        return SimpleNamespace(st_mode=st.st_mode, st_uid=owners.get(p, 0))
    monkeypatch.setattr(users, "_stat_entry", fake_stat)


def _dirs(tmp_path, *names, mode=0o755):
    out = []
    for n in names:
        d = tmp_path / n
        d.mkdir()
        d.chmod(mode)
        out.append(str(d))
    return out


def test_root_path_clean_passes(tmp_path, monkeypatch):
    a, b = _dirs(tmp_path, "sbin", "bin")
    _root_path(monkeypatch, f"{a}:{b}")
    assert users._check_root_path().status == "pass"


def test_root_login_path_is_audited_not_process_path(tmp_path, monkeypatch):
    a, = _dirs(tmp_path, "bin")
    _root_path(monkeypatch, f"{a}:.")
    assert users._check_root_path().status == "fail"


@pytest.mark.parametrize("tmpl", ["{a}::{b}", ":{a}:{b}", "{a}:{b}:"])
def test_root_path_empty_entry_fails(tmp_path, monkeypatch, tmpl):
    a, b = _dirs(tmp_path, "x", "y")
    _root_path(monkeypatch, tmpl.format(a=a, b=b))
    assert users._check_root_path().status == "fail"


def test_root_path_dir_not_owned_by_root_fails(tmp_path, monkeypatch):
    a, b = _dirs(tmp_path, "x", "y")
    _root_path(monkeypatch, f"{a}:{b}", owners={b: 1000})
    r = users._check_root_path()
    assert r.status == "fail" and "owned" in r.detail


def test_root_path_non_directory_fails(tmp_path, monkeypatch):
    a, = _dirs(tmp_path, "x")
    f = tmp_path / "file"
    f.write_text("")
    _root_path(monkeypatch, f"{a}:{f}:{tmp_path / 'missing'}")
    assert users._check_root_path().status == "fail"


def test_root_path_writable_dir_fails(tmp_path, monkeypatch):
    a, = _dirs(tmp_path, "x", mode=0o775)
    _root_path(monkeypatch, a)
    assert users._check_root_path().status == "fail"


def test_root_path_unreadable_is_not_a_pass(tmp_path, monkeypatch):
    _root_path(monkeypatch, "/usr/bin", rc=1)
    monkeypatch.setattr(users.os, "geteuid", lambda: 1000, raising=False)
    assert users._check_root_path().status == "warn"


# ---------------------------------------------------------------- 5.1.9 at.allow

@pytest.fixture
def at_env(tmp_path, monkeypatch):
    allow = tmp_path / "at.allow"
    monkeypatch.setattr(cron, "AT_ALLOW", str(allow))
    monkeypatch.setattr(cron, "AT_DENY", str(tmp_path / "at.deny"))
    monkeypatch.setattr(cron.subprocess, "run",
                        lambda cmd, *a, **k: subprocess.CompletedProcess(cmd, 0, "/usr/bin/at\n", ""))
    monkeypatch.setattr(cron, "_at_allowed_gids", lambda: {0, 1})
    owner = {"uid": 0, "gid": 0}

    def fake_stat(p):
        st = os.stat(p)
        return SimpleNamespace(st_mode=st.st_mode, st_uid=owner["uid"], st_gid=owner["gid"])

    def fake_chown(p, uid, gid):
        owner["uid"], owner["gid"] = uid, gid
    monkeypatch.setattr(cron, "_stat_file", fake_stat)
    monkeypatch.setattr(cron.os, "chown", fake_chown)
    return allow, owner


@pytest.mark.parametrize("mode,uid,gid", [(0o666, 0, 0), (0o644, 0, 0), (0o640, 1000, 0), (0o640, 0, 1000)])
def test_at_allow_owner_and_mode_checked(at_env, mode, uid, gid):
    allow, owner = at_env
    allow.write_text("root\n")
    allow.chmod(mode)
    owner.update(uid=uid, gid=gid)
    assert cron._check_at_allow().status == "fail"


@pytest.mark.parametrize("mode,gid", [(0o640, 0), (0o640, 1), (0o600, 0)])
def test_at_allow_hardened_passes(at_env, mode, gid):
    allow, owner = at_env
    allow.write_text("root\n")
    allow.chmod(mode)
    owner.update(gid=gid)
    assert cron._check_at_allow().status == "pass"


def test_at_allow_fix_round_trip(at_env):
    allow, owner = at_env
    allow.write_text("root\n")
    allow.chmod(0o666)
    owner.update(uid=1000, gid=1000)
    entries = cron._fix_at_allow()
    assert len(entries) == 2 and all(e.undo for e in entries)
    assert cron._check_at_allow().status == "pass"
    assert stat.S_IMODE(allow.stat().st_mode) == 0o640


# ---------------------------------------------------------------- sshd

@pytest.fixture
def sshd_env(tmp_path, monkeypatch):
    """Fake `sshd -T` and an empty tmp sshd_config. Returns a setter."""
    cfg = tmp_path / "sshd_config"
    cfg.write_text("")
    monkeypatch.setattr(sshd, "SSHD_CONFIG", str(cfg))
    monkeypatch.setattr(sshd, "SSHD_CONFIG_D", str(tmp_path / "sshd_config.d"))
    state = {"plain": {}, "with_c": None, "rc": 0, "calls": []}

    def run(cmd, *a, **k):
        state["calls"].append(cmd)
        vals = state["with_c"] if "-C" in cmd and state["with_c"] is not None else state["plain"]
        out = "".join(f"{key.lower()} {v}\n" for key, v in vals.items())
        return subprocess.CompletedProcess(cmd, state["rc"], out if state["rc"] == 0 else "", "")
    monkeypatch.setattr(sshd.subprocess, "run", run)
    return cfg, state


def test_sshd_T_resolves_match_for_root_login(sshd_env):
    cfg, state = sshd_env
    cfg.write_text("PermitRootLogin no\n")
    state["plain"] = {"permitrootlogin": "no"}
    state["with_c"] = {"permitrootlogin": "yes"}   # Match User root re-enables it
    assert ssh._check_permit_root().status == "fail"
    c = next(c for c in state["calls"] if "-C" in c)
    spec = c[c.index("-C") + 1]
    assert "user=root" in spec and "host=" in spec and "addr=" in spec


def test_match_block_in_included_file_fails(sshd_env, tmp_path):
    cfg, state = sshd_env
    d = tmp_path / "sshd_config.d"
    d.mkdir()
    (d / "50-cloud.conf").write_text("Match Address 10.0.0.0/8\n    PermitRootLogin yes\n")
    cfg.write_text(f"Include {d}/*.conf\nPermitRootLogin no\n")
    state["plain"] = {"permitrootlogin": "no"}
    r = ssh._check_permit_root()
    assert r.status == "fail" and "10.0.0.0/8" in r.detail


def test_include_inside_match_inherits_match(sshd_env, tmp_path):
    cfg, state = sshd_env
    inc = tmp_path / "x11.conf"
    inc.write_text("X11Forwarding yes\n")
    cfg.write_text(f"X11Forwarding no\nMatch Group devs\n  Include {inc}\n")
    state["plain"] = {"x11forwarding": "no"}
    assert ssh._check_x11().status == "fail"


def test_compliant_match_blocks_still_pass(sshd_env):
    cfg, state = sshd_env
    cfg.write_text("PermitRootLogin no\nX11Forwarding no\nMatch User alice\n  X11Forwarding no\n"
                   "Match all\nPermitRootLogin no\n")
    state["plain"] = {"permitrootlogin": "no", "x11forwarding": "no"}
    assert ssh._check_permit_root().status == "pass"
    assert ssh._check_x11().status == "pass"


def test_sshd_T_failure_is_not_a_pass(sshd_env):
    cfg, state = sshd_env
    state["rc"] = 255
    state["plain"] = {"permitrootlogin": "no"}
    assert ssh._check_permit_root().status == "warn"
    assert ssh._check_banner().status == "warn"


@pytest.mark.parametrize("check", [ssh._check_client_alive, misc._check_ssh_alive_not_zero])
def test_client_alive_count_zero_fails(sshd_env, check):
    _, state = sshd_env
    state["plain"] = {"clientaliveinterval": "300", "clientalivecountmax": "0"}
    assert check().status == "fail"


@pytest.mark.parametrize("check", [ssh._check_client_alive, misc._check_ssh_alive_not_zero])
def test_client_alive_match_override_fails(sshd_env, check):
    cfg, state = sshd_env
    cfg.write_text("ClientAliveInterval 300\nMatch User bob\n  ClientAliveInterval 0\n")
    state["plain"] = {"clientaliveinterval": "300", "clientalivecountmax": "3"}
    assert check().status == "fail"


@pytest.mark.parametrize("check", [ssh._check_client_alive, misc._check_ssh_alive_not_zero])
def test_client_alive_hardened_passes(sshd_env, check):
    cfg, state = sshd_env
    cfg.write_text("Match User bob\n  ClientAliveInterval 5m\n")
    state["plain"] = {"clientaliveinterval": "300", "clientalivecountmax": "3"}
    assert check().status == "pass"


def _record_sets(monkeypatch, module, state):
    def fake_set(key, value):
        state["plain"][key.lower()] = value
        return SimpleNamespace(action=f"set {key}", undo=[])
    monkeypatch.setattr(module, "_set_sshd_setting", fake_set)


def test_alive_not_zero_fix_round_trip(sshd_env, monkeypatch):
    _, state = sshd_env
    state["plain"] = {"clientaliveinterval": "300", "clientalivecountmax": "0"}
    _record_sets(monkeypatch, misc, state)
    assert misc._fix_ssh_alive_not_zero()
    assert misc._check_ssh_alive_not_zero().status == "pass"


@pytest.mark.parametrize("mac", ["hmac-sha1", "umac-128@openssh.com",
                                 "hmac-sha1-etm@openssh.com", "umac-128-etm@openssh.com"])
def test_weak_macs_include_sha1_and_umac128(sshd_env, mac):
    _, state = sshd_env
    state["plain"] = {"macs": f"hmac-sha2-256,{mac}"}
    assert ssh._check_macs().status == "fail"


def test_macs_fix_round_trip(sshd_env, monkeypatch):
    _, state = sshd_env
    state["plain"] = {"macs": "hmac-sha1,umac-128@openssh.com"}
    _record_sets(monkeypatch, ssh, state)
    ssh._fix_macs()
    assert not set(ssh.STRONG_MACS.split(",")) & ssh.WEAK_MACS
    assert ssh._check_macs().status == "pass"


def test_banner_missing_empty_or_dir_fails(sshd_env, tmp_path):
    _, state = sshd_env
    empty = tmp_path / "empty"
    empty.write_text("  \n")
    for val in [str(tmp_path / "missing"), str(empty), str(tmp_path), "none"]:
        state["plain"] = {"banner": val}
        assert ssh._check_banner().status == "fail", val


def test_banner_fix_round_trip(sshd_env, tmp_path, monkeypatch):
    _, state = sshd_env
    state["plain"] = {"banner": "none"}
    monkeypatch.setattr(ssh, "BANNER_FILE", str(tmp_path / "issue.net"))
    _record_sets(monkeypatch, ssh, state)
    ssh._fix_banner()
    assert ssh._check_banner().status == "pass"
