# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file,
# via any medium, is strictly prohibited without explicit written authorization.

"""Round-3 false-pass regression tests for lss.controls.boot.

1.4.2  RHEL's /etc/grub.d/01_users writes `set superusers="root"` and
       `password_pbkdf2 root ${GRUB2_PASSWORD}` into every grub.cfg; the
       password only exists if user.cfg sets GRUB2_PASSWORD. The check
       passed on the template alone (no user.cfg, or an empty variable).
1.4.3  On RHEL user.cfg holds the password hash and must be 0600 root:root;
       only grub.cfg was checked, so a world-readable user.cfg passed.
1.4.4  A deny-list of "*", "!", "!!" passed other locked or hashless root
       entries ("!*", the `passwd -l` form "!$6$..."). CIS wants a hash.
2.1.1  `systemctl is-active` alone passed a time daemon started by hand but
       disabled at boot; CIS requires enabled and running. The fixer now
       enables that daemon instead of starting a conflicting timesyncd.
"""

from __future__ import annotations

import os
import subprocess

import pytest

from lss.controls import boot

_HASH = "grub.pbkdf2.sha512.10000." + "A" * 128 + "." + "B" * 128

# What grub2-mkconfig emits on RHEL from /etc/grub.d/01_users.
_RHEL_GRUB_CFG = """\
### BEGIN /etc/grub.d/01_users ###
if [ -f ${prefix}/user.cfg ]; then
  source ${prefix}/user.cfg
  if [ -n "${GRUB2_PASSWORD}" ]; then
    set superusers="root"
    export superusers
    password_pbkdf2 root ${GRUB2_PASSWORD}
  fi
fi
### END /etc/grub.d/01_users ###
"""


@pytest.fixture
def grub(tmp_path, monkeypatch):
    d = tmp_path / "grub2"
    d.mkdir()
    cfg = d / "grub.cfg"
    monkeypatch.setattr(boot, "_GRUB_CFGS", (str(tmp_path / "nope" / "grub.cfg"), str(cfg)))
    return cfg


# ---- 1.4.2 ----

def test_1_4_2_rhel_template_without_user_cfg_fails(grub):
    grub.write_text(_RHEL_GRUB_CFG)
    assert boot._check_bootloader_password().status == "fail"


def test_1_4_2_rhel_user_cfg_with_empty_password_fails(grub):
    grub.write_text(_RHEL_GRUB_CFG)
    (grub.parent / "user.cfg").write_text("GRUB2_PASSWORD=\n")
    assert boot._check_bootloader_password().status == "fail"


def test_1_4_2_rhel_hardened_host_still_passes(grub):
    grub.write_text(_RHEL_GRUB_CFG)
    (grub.parent / "user.cfg").write_text(f"GRUB2_PASSWORD={_HASH}\n")
    assert boot._check_bootloader_password().status == "pass"


def test_1_4_2_rhel_unreadable_user_cfg_is_not_pass(grub, monkeypatch):
    grub.write_text(_RHEL_GRUB_CFG)
    (grub.parent / "user.cfg").write_text(f"GRUB2_PASSWORD={_HASH}\n")

    def boom(*a, **kw):
        raise PermissionError("denied")

    monkeypatch.setattr(boot, "_grub_var_value", boom)
    assert boot._check_bootloader_password().status == "warn"


def test_1_4_2_debian_literal_hash_still_passes(grub):
    grub.write_text(f'set superusers="root"\npassword_pbkdf2 root {_HASH}\n')
    assert boot._check_bootloader_password().status == "pass"


# ---- 1.4.3 ----

def _own_ids(monkeypatch, path):
    st = os.stat(path)
    monkeypatch.setattr(boot, "_ROOT_UID", st.st_uid)
    monkeypatch.setattr(boot, "_ROOT_GID", st.st_gid)


def test_1_4_3_world_readable_user_cfg_fails(grub, monkeypatch):
    grub.write_text(_RHEL_GRUB_CFG)
    grub.chmod(0o600)
    user_cfg = grub.parent / "user.cfg"
    user_cfg.write_text(f"GRUB2_PASSWORD={_HASH}\n")
    user_cfg.chmod(0o644)
    _own_ids(monkeypatch, grub)
    r = boot._check_grub_perms()
    assert r.status == "fail" and "user.cfg" in r.detail


def test_1_4_3_fix_round_trip_and_hardened_host_passes(grub, monkeypatch):
    grub.write_text(_RHEL_GRUB_CFG)
    grub.chmod(0o644)
    user_cfg = grub.parent / "user.cfg"
    user_cfg.write_text(f"GRUB2_PASSWORD={_HASH}\n")
    user_cfg.chmod(0o644)
    _own_ids(monkeypatch, grub)
    entries = boot._fix_grub_perms()
    assert {e.path for e in entries} == {str(grub), str(user_cfg)}
    assert boot._check_grub_perms().status == "pass"


# ---- 1.4.4 ----

@pytest.mark.parametrize("pw", ["!*", "!$6$salt$hash", "*LK*", "x"])
def test_1_4_4_locked_or_hashless_root_fails(tmp_path, monkeypatch, pw):
    shadow = tmp_path / "shadow"
    shadow.write_text(f"root:{pw}:19000:0:99999:7:::\n")
    monkeypatch.setattr(boot, "_SHADOW", str(shadow))
    assert boot._check_single_user_auth().status == "fail"


@pytest.mark.parametrize("pw", ["$6$salt$hash", "$y$j9T$salt$hash"])
def test_1_4_4_root_with_hash_still_passes(tmp_path, monkeypatch, pw):
    shadow = tmp_path / "shadow"
    shadow.write_text(f"root:{pw}:19000:0:99999:7:::\n")
    monkeypatch.setattr(boot, "_SHADOW", str(shadow))
    assert boot._check_single_user_auth().status == "pass"


# ---- 2.1.1 ----

def _fake_systemctl(monkeypatch, states: dict[tuple[str, str], str]):
    """states maps (verb, unit) -> stdout; anything else prints nothing, rc 1.
    `enable` calls are recorded and succeed."""
    calls = []

    def run(argv, *a, **kw):
        calls.append(argv)
        if argv[1] == "enable":
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        out = states.get((argv[1], argv[-1]))
        if out is None:
            return subprocess.CompletedProcess(argv, 1, stdout="", stderr="")
        return subprocess.CompletedProcess(argv, 0, stdout=out + "\n", stderr="")

    monkeypatch.setattr(boot.subprocess, "run", run)
    return calls


def test_2_1_1_active_but_disabled_daemon_fails(monkeypatch):
    _fake_systemctl(monkeypatch, {
        ("is-active", "chrony"): "active",
        ("is-enabled", "chrony"): "disabled",
    })
    assert boot._check_time_sync().status == "fail"


def test_2_1_1_fix_enables_the_running_daemon(monkeypatch):
    calls = _fake_systemctl(monkeypatch, {
        ("is-active", "chrony"): "active",
        ("is-enabled", "chrony"): "disabled",
    })
    entries = boot._fix_time_sync()
    assert ["systemctl", "enable", "chrony"] in calls
    assert not any("systemd-timesyncd" in c and c[1] == "enable" for c in calls)
    assert entries and entries[0].undo == [["systemctl", "disable", "chrony"]]


def test_2_1_1_debian_chrony_alias_still_passes(monkeypatch):
    # chronyd is an alias of chrony.service on Debian: is-enabled says "alias".
    _fake_systemctl(monkeypatch, {
        ("is-active", "chronyd"): "active",
        ("is-enabled", "chronyd"): "alias",
        ("is-active", "chrony"): "active",
        ("is-enabled", "chrony"): "enabled",
    })
    assert boot._check_time_sync().status == "pass"


def test_2_1_1_enabled_timesyncd_still_passes(monkeypatch):
    _fake_systemctl(monkeypatch, {
        ("is-active", "systemd-timesyncd"): "active",
        ("is-enabled", "systemd-timesyncd"): "enabled",
    })
    assert boot._check_time_sync().status == "pass"
