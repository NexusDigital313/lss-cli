# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file,
# via any medium, is strictly prohibited without explicit written authorization.

"""Round-3 false-pass regressions — logging and auditd (lss/controls/logging.py).

- 4.1.1.3 / 4.1.1.4 read the FIRST max_log_file / max_log_file_action line;
  auditd applies the last, so a later `max_log_file = 1` or
  `max_log_file_action = ROTATE` passed. The fixers rewrote only the first
  line, so they could not clear a later duplicate (round trip), and the
  4.1.1.4 fixer appended onto a file with no trailing newline, gluing its
  line onto the previous one.
- 4.2.1.1 / 4.2.1.2 read only /etc/systemd/journald.conf, first match, and
  only `Key=` with no spaces. A drop-in in journald.conf.d setting
  Storage=volatile or Compress=no, a later duplicate, or `Storage = volatile`
  (which journald accepts) all passed. They now apply journald's own order:
  main file, then *.conf drop-ins by name, last [Journal] assignment wins.
  Compress accepts journald's other true spellings (`true`, a size threshold).
- The 4.2.1.x fixers also rewrite /etc drop-ins that set the key, and refuse
  when a /run or /usr/lib drop-in would still override it.
- 4.1.1.1's fixer installed `auditd` on RHEL, where the package is `audit`.
"""

from __future__ import annotations

import pytest

from lss.controls import logging as lg


@pytest.fixture
def auditd_conf(tmp_path, monkeypatch):
    p = tmp_path / "auditd.conf"
    monkeypatch.setattr(lg, "AUDITD_CONF", p)
    monkeypatch.setattr(lg.journal, "backup_file", lambda path: "")
    monkeypatch.setattr(lg.subprocess, "run", lambda *a, **k: None)
    return p


@pytest.fixture
def jd(tmp_path, monkeypatch):
    """Fake journald layout: returns (main conf, /etc drop-in dir, /usr/lib drop-in dir)."""
    etc = tmp_path / "etc"
    etc.mkdir()
    main = etc / "journald.conf"
    etc_d = etc / "journald.conf.d"
    run_d = tmp_path / "run" / "journald.conf.d"
    usr_d = tmp_path / "usr" / "journald.conf.d"
    monkeypatch.setattr(lg, "JOURNALD_CONF", main)
    monkeypatch.setattr(lg, "JOURNALD_MAIN_FALLBACKS", (tmp_path / "usr" / "journald.conf",))
    monkeypatch.setattr(lg, "JOURNALD_DROPIN_DIRS", (etc_d, run_d, usr_d))
    monkeypatch.setattr(lg, "JOURNAL_DIR", tmp_path / "var-log-journal")
    monkeypatch.setattr(lg.journal, "backup_file", lambda path: "")
    monkeypatch.setattr(lg.subprocess, "run", lambda *a, **k: None)
    return main, etc_d, usr_d


def _dropin(d, name, body):
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(body)


# ---- 4.1.1.3 / 4.1.1.4: auditd applies the last assignment ----

def test_4_1_1_3_later_small_max_log_file_not_pass(auditd_conf):
    auditd_conf.write_text("max_log_file = 32\nmax_log_file_action = keep_logs\nmax_log_file = 1\n")
    assert lg._check_audit_log_size().status != "pass"


def test_4_1_1_4_later_rotate_fails(auditd_conf):
    auditd_conf.write_text("max_log_file_action = keep_logs\nmax_log_file_action = ROTATE\n")
    assert lg._check_audit_log_retention().status == "fail"


def test_4_1_1_3_and_4_hardened_still_pass(auditd_conf):
    auditd_conf.write_text("# max_log_file = 1\nmax_log_file = 8\nmax_log_file_action = KEEP_LOGS\n")
    assert lg._check_audit_log_size().status == "pass"
    assert lg._check_audit_log_retention().status == "pass"


def test_4_1_1_3_fix_round_trip_with_duplicates(auditd_conf):
    auditd_conf.write_text("max_log_file = 32\nmax_log_file = 1\n")
    lg._fix_audit_log_size()
    assert lg._check_audit_log_size().status == "pass"


def test_4_1_1_4_fix_round_trip_with_duplicates_and_no_newline(auditd_conf):
    auditd_conf.write_text("max_log_file_action = keep_logs\nmax_log_file_action = rotate")
    lg._fix_audit_log_retention()
    assert lg._check_audit_log_retention().status == "pass"
    auditd_conf.write_text("num_logs = 5")
    lg._fix_audit_log_retention()
    assert "num_logs = 5\n" in auditd_conf.read_text()
    assert lg._check_audit_log_retention().status == "pass"


# ---- 4.2.1.1: Storage ----

def test_4_2_1_1_dropin_volatile_fails(jd):
    main, etc_d, _ = jd
    main.write_text("[Journal]\nStorage=persistent\n")
    _dropin(etc_d, "50-volatile.conf", "[Journal]\nStorage=volatile\n")
    assert lg._check_journald_persistent().status == "fail"


def test_4_2_1_1_spaced_volatile_with_journal_dir_fails(jd):
    main, _, _ = jd
    lg.JOURNAL_DIR.mkdir()
    main.write_text("[Journal]\nStorage = volatile\n")
    assert lg._check_journald_persistent().status == "fail"


def test_4_2_1_1_later_duplicate_fails(jd):
    main, _, _ = jd
    main.write_text("[Journal]\nStorage=persistent\nStorage=none\n")
    assert lg._check_journald_persistent().status == "fail"


def test_4_2_1_1_hardened_via_dropin_passes(jd):
    main, etc_d, usr_d = jd
    main.write_text("[Journal]\n#Storage=auto\n")
    _dropin(usr_d, "10-vendor.conf", "[Journal]\nStorage=volatile\n")
    _dropin(etc_d, "60-journald.conf", "[Journal]\nStorage=persistent\n")
    _dropin(etc_d, "70-notes.conf.bak", "[Journal]\nStorage=volatile\n")
    assert lg._check_journald_persistent().status == "pass"


def test_4_2_1_1_unreadable_dropin_not_pass(jd, monkeypatch):
    main, etc_d, _ = jd
    main.write_text("[Journal]\nStorage=persistent\n")
    _dropin(etc_d, "50-x.conf", "[Journal]\n")
    real = lg.Path.read_text

    def boom(self, *a, **k):
        if self.name == "50-x.conf":
            raise PermissionError("denied")
        return real(self, *a, **k)

    monkeypatch.setattr(lg.Path, "read_text", boom)
    assert lg._check_journald_persistent().status == "warn"


def test_4_2_1_1_fix_round_trip_over_etc_dropin(jd):
    main, etc_d, _ = jd
    main.write_text("[Journal]\n#Storage=auto\n")
    _dropin(etc_d, "50-volatile.conf", "[Journal]\nStorage = volatile\n")
    entries = lg._fix_journald_persistent()
    assert lg._check_journald_persistent().status == "pass"
    assert len(entries) == 2 and entries[0].undo[-1][-1] == "systemd-journald"


def test_4_2_1_1_fix_refuses_unfixable_usr_override(jd):
    main, _, usr_d = jd
    main.write_text("[Journal]\n")
    _dropin(usr_d, "90-vendor.conf", "[Journal]\nStorage=volatile\n")
    with pytest.raises(RuntimeError, match="90-vendor.conf"):
        lg._fix_journald_persistent()
    assert main.read_text() == "[Journal]\n"


def test_4_2_1_1_fix_creates_missing_main(jd):
    lg._fix_journald_persistent()
    assert lg._check_journald_persistent().status == "pass"


# ---- 4.2.1.2: Compress ----

def test_4_2_1_2_dropin_compress_no_fails(jd):
    main, etc_d, _ = jd
    main.write_text("[Journal]\n#Compress=yes\n")
    _dropin(etc_d, "50-nocompress.conf", "[Journal]\nCompress=no\n")
    assert lg._check_journald_compress().status == "fail"


def test_4_2_1_2_spaced_compress_no_fails(jd):
    main, _, _ = jd
    main.write_text("[Journal]\nCompress = off\n")
    assert lg._check_journald_compress().status == "fail"


@pytest.mark.parametrize("val", ["yes", "true", "1", "on", "4M"])
def test_4_2_1_2_true_spellings_pass(jd, val):
    main, _, _ = jd
    main.write_text(f"[Journal]\nCompress={val}\n")
    assert lg._check_journald_compress().status == "pass"


def test_4_2_1_2_fix_round_trip_over_dropin(jd):
    main, etc_d, _ = jd
    main.write_text("[Journal]\nCompress=no\n")
    _dropin(etc_d, "50-nocompress.conf", "[Journal]\nCompress=false\n")
    lg._fix_journald_compress()
    assert lg._check_journald_compress().status == "pass"


# ---- 4.1.1.1: fixer package name on RHEL ----

def test_4_1_1_1_fix_installs_audit_on_rhel(monkeypatch):
    from lss.lib.registry import get_control
    seen = []
    monkeypatch.setattr(lg.distro, "is_rhel_family", lambda: True)
    monkeypatch.setattr(lg.pkg, "install", lambda name: seen.append(name) or [])
    get_control("4.1.1.1").fix()
    assert seen == ["audit"]
