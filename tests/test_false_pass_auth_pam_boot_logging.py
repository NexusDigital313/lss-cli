# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file,
# via any medium, is strictly prohibited without explicit written authorization.

"""False-pass regressions — auth (5.3.4), pam (5.3.7), boot (2.1.2), logging
(4.1.1.1, 4.2.2.1).

Each test feeds a check the evidence that used to fool it — a commented-out
PAM line, a commented `# pool` example, a removed-but-not-purged package —
and asserts the check no longer reports compliance on it. Hardcoded /etc
paths are redirected to tmp files by swapping the module's `Path`, and
package-manager calls are faked, so nothing here reads the host's config.
"""

from __future__ import annotations

import pathlib
import subprocess

import pytest

from lss.controls import auth, boot, pam
from lss.controls import logging as lss_logging


def _redirect_paths(monkeypatch, module, mapping: dict[str, pathlib.Path]) -> None:
    """Make `module.Path("/etc/...")` resolve to the tmp path in `mapping`."""
    real_Path = pathlib.Path
    monkeypatch.setattr(module, "Path", lambda p: real_Path(mapping.get(str(p), p)))


def _pam_files(tmp_path, common_password: str) -> dict[str, pathlib.Path]:
    """pwquality.conf absent; common-password holds `common_password`."""
    cp = tmp_path / "common-password"
    cp.write_text(common_password)
    return {
        "/etc/security/pwquality.conf": tmp_path / "absent-pwquality.conf",
        "/etc/pam.d/common-password": cp,
        "/etc/pam.d/system-auth": tmp_path / "absent-system-auth",
        "/etc/pam.d/password-auth": tmp_path / "absent-password-auth",
    }


_PAM_UNIX = "password [success=1 default=ignore] pam_unix.so obscure yescrypt\n"


# ---- 5.3.4: password minimum length ----

def test_5_3_4_commented_pwquality_minlen_does_not_pass(tmp_path, monkeypatch):
    _redirect_paths(monkeypatch, auth, _pam_files(
        tmp_path,
        "# password requisite pam_pwquality.so retry=3 minlen=14\n" + _PAM_UNIX,
    ))
    assert auth._check_password_minlen().status != "pass"


def test_5_3_4_active_pwquality_minlen_passes(tmp_path, monkeypatch):
    _redirect_paths(monkeypatch, auth, _pam_files(
        tmp_path,
        "password requisite pam_pwquality.so retry=3 minlen=14\n" + _PAM_UNIX,
    ))
    assert auth._check_password_minlen().status == "pass"


# ---- 5.3.7: password retry limit ----

def test_5_3_7_commented_pwquality_retry_does_not_pass(tmp_path, monkeypatch):
    _redirect_paths(monkeypatch, pam, _pam_files(
        tmp_path,
        "# password requisite pam_pwquality.so retry=3\n" + _PAM_UNIX,
    ))
    assert pam._check_pw_retry().status != "pass"


def test_5_3_7_active_pwquality_retry_passes(tmp_path, monkeypatch):
    _redirect_paths(monkeypatch, pam, _pam_files(
        tmp_path,
        "password requisite pam_pwquality.so retry=3\n" + _PAM_UNIX,
    ))
    assert pam._check_pw_retry().status == "pass"


# ---- 2.1.2: chrony time sources ----

@pytest.mark.parametrize("text", [
    "# pool 2.debian.pool.ntp.org iburst\n",
    "# server 10.0.0.1\n",
    "# Use public servers from the pool.ntp.org project.\n",
    "pool\n",
    "serverfoo x\n",
    "pool # placeholder\n",
    "! pool 2.debian.pool.ntp.org iburst\n",  # `!` is a chrony comment leader
])
def test_has_ntp_source_rejects_inert_lines(text):
    assert boot._has_ntp_source(text) is False


@pytest.mark.parametrize("text", [
    "pool 2.debian.pool.ntp.org iburst\n",
    "  server 10.0.0.1 iburst\n",
])
def test_has_ntp_source_accepts_real_sources(text):
    assert boot._has_ntp_source(text) is True


_COMMENTED_ONLY_CHRONY = (
    "# Use Debian vendor zone.\n"
    "# pool 2.debian.pool.ntp.org iburst\n"
    "sourcedir /run/chrony-dhcp\n"
)


def test_2_1_2_check_fails_on_commented_only_sources(tmp_path, monkeypatch):
    conf = tmp_path / "chrony.conf"
    conf.write_text(_COMMENTED_ONLY_CHRONY)
    monkeypatch.setattr(boot, "_chrony_conf_path", lambda: conf)
    # chronyd is the active time sync, so the config check applies.
    monkeypatch.setattr(
        boot.subprocess, "run",
        lambda argv, *a, **kw: subprocess.CompletedProcess(argv, 0, stdout="active\n", stderr=""),
    )
    assert boot._check_chrony_config().status == "fail"


@pytest.fixture
def isolated_journal(tmp_path, monkeypatch):
    from lss.lib import journal
    monkeypatch.setattr(journal, "BACKUPS_DIR", tmp_path / "backups")
    journal.set_current_run_id("test-run")
    yield journal
    journal.set_current_run_id(None)


def test_2_1_2_fix_appends_sources_when_only_commented_examples(tmp_path, monkeypatch, isolated_journal):
    conf = tmp_path / "chrony.conf"
    conf.write_text(_COMMENTED_ONLY_CHRONY)
    monkeypatch.setattr(boot, "_chrony_conf_path", lambda: conf)

    entries = boot._fix_chrony_config()

    assert entries, "fix skipped appending sources because a comment mentioned `pool`"
    assert boot._has_ntp_source(conf.read_text())


# ---- 4.1.1.1 / 4.2.2.1: package installed via dpkg Status ----

def _fake_pkg_tools(dpkg_status: str):
    """`which` misses, dpkg-query reports `dpkg_status`, rpm is absent."""
    def fake_run(argv, *a, **kw):
        tool = argv[0]
        if tool == "which":
            return subprocess.CompletedProcess(argv, 1, stdout="", stderr="")
        if tool == "dpkg-query":
            assert "-f=${Status}" in argv, f"dpkg-query must query Status, got {argv}"
            return subprocess.CompletedProcess(argv, 0, stdout=dpkg_status, stderr="")
        if tool == "rpm":
            raise FileNotFoundError(tool)
        raise AssertionError(f"unexpected command: {argv}")
    return fake_run


def test_4_1_1_1_removed_but_not_purged_auditd_fails(monkeypatch):
    monkeypatch.setattr(lss_logging.subprocess, "run", _fake_pkg_tools("deinstall ok config-files"))
    assert lss_logging._check_auditd_installed().status == "fail"


def test_4_1_1_1_installed_auditd_passes(monkeypatch):
    monkeypatch.setattr(lss_logging.subprocess, "run", _fake_pkg_tools("install ok installed"))
    assert lss_logging._check_auditd_installed().status == "pass"


def test_4_2_2_1_installed_rsyslog_detected_via_dpkg(monkeypatch):
    monkeypatch.setattr(lss_logging.subprocess, "run", _fake_pkg_tools("install ok installed"))
    assert lss_logging._check_rsyslog().status == "pass"
