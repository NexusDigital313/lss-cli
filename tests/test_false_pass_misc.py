# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file,
# via any medium, is strictly prohibited without explicit written authorization.

"""False-pass regression tests for lss/controls/misc.py.

Each test pins a case where a check used to report "pass" (or could never
reach a correct "pass") on evidence that does not hold:
  - 1.3.1 / 1.6.1: `dpkg-query -W` without `-f=${Status}` never prints the
    status, so the "install ok installed" guard was dead.
  - 1.3.2: `grep -r aide` matched commented lines and substrings of other
    words (maidenhead, unaided).
  - 1.2.2: `grep -r signed-by` matched commented examples and missed deb822
    `Signed-By:`.
  - 1.2.1: a comment-only sources.list counted as a configured repository.
"""

from __future__ import annotations

import subprocess

import pytest

from lss.controls import misc


# --- 1.3.1 / 1.6.1: dpkg install guard must request ${Status} ---

def _fake_pkg_run(pkg: str, status: str, seen: list[list[str]]):
    def fake_run(argv, *args, **kwargs):
        seen.append(list(argv))
        if argv[0] == "which":
            return subprocess.CompletedProcess(argv, 1, stdout="", stderr="")
        if argv[0] == "dpkg-query":
            assert "-f=${Status}" in argv, f"dpkg-query without -f=${{Status}}: {argv}"
            assert argv[-1] == pkg
            return subprocess.CompletedProcess(argv, 0, stdout=status, stderr="")
        if argv[0] == "rpm":
            raise FileNotFoundError(argv[0])
        raise AssertionError(f"unexpected command: {argv}")
    return fake_run


@pytest.mark.parametrize("check, pkg", [
    (misc._check_aide_installed, "aide"),
    (misc._check_apparmor_installed, "apparmor"),
])
def test_installed_check_passes_on_dpkg_installed_status(monkeypatch, check, pkg):
    seen: list[list[str]] = []
    monkeypatch.setattr(misc.subprocess, "run", _fake_pkg_run(pkg, "install ok installed", seen))
    assert check().status == "pass"
    assert any(a[0] == "dpkg-query" for a in seen)


@pytest.mark.parametrize("check, pkg", [
    (misc._check_aide_installed, "aide"),
    (misc._check_apparmor_installed, "apparmor"),
])
def test_installed_check_rejects_removed_package(monkeypatch, check, pkg):
    """A removed-but-not-purged package ("rc" state) is not installed."""
    seen: list[list[str]] = []
    monkeypatch.setattr(misc.subprocess, "run", _fake_pkg_run(pkg, "deinstall ok config-files", seen))
    assert check().status != "pass"


# --- 1.3.2: AIDE must actually be invoked from cron ---

@pytest.mark.parametrize("text", [
    "# aide --check\n",
    "# run aide nightly\n",
    "maidenhead\n",
    "unaided\n",
    "#!/bin/sh\n",
    "",
])
def test_text_runs_aide_rejects_comments_and_substrings(text):
    assert misc._text_runs_aide(text) is False


@pytest.mark.parametrize("text", [
    "/usr/bin/aide --check --config=/etc/aide/aide.conf | /usr/bin/logger -t aide\n",
    "  aide.wrapper --check\n",
])
def test_text_runs_aide_accepts_real_invocations(text):
    assert misc._text_runs_aide(text) is True


def test_text_runs_aide_accepts_lss_cron_script():
    """The 1.3.2 fix's own cron script must satisfy the 1.3.2 check."""
    assert misc._text_runs_aide(misc._AIDE_CRON_DAILY) is True


def _timer_disabled(argv, *args, **kwargs):
    assert argv[:2] == ["systemctl", "is-enabled"], f"unexpected command: {argv}"
    return subprocess.CompletedProcess(argv, 1, stdout="disabled\n", stderr="")


def _cron_layout(tmp_path, daily_content: str | bytes) -> tuple[str, str, str]:
    crontab = tmp_path / "crontab"
    crontab.write_text(
        "SHELL=/bin/sh\n"
        "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n"
    )
    daily = tmp_path / "cron.daily"
    daily.mkdir()
    target = daily / "aide"
    if isinstance(daily_content, bytes):
        target.write_bytes(daily_content)
    else:
        target.write_text(daily_content)
    weekly = tmp_path / "cron.weekly"
    weekly.mkdir()
    return (str(crontab), str(daily), str(weekly))


def test_aide_cron_commented_mention_is_not_a_pass(tmp_path, monkeypatch):
    monkeypatch.setattr(misc, "_AIDE_CRON_PATHS",
                        _cron_layout(tmp_path, "#!/bin/sh\n# run aide nightly\n"))
    monkeypatch.setattr(misc.subprocess, "run", _timer_disabled)
    assert misc._check_aide_cron().status != "pass"


def test_aide_cron_real_invocation_passes(tmp_path, monkeypatch):
    monkeypatch.setattr(misc, "_AIDE_CRON_PATHS",
                        _cron_layout(tmp_path, misc._AIDE_CRON_DAILY))
    monkeypatch.setattr(misc.subprocess, "run", _timer_disabled)
    assert misc._check_aide_cron().status == "pass"


def test_aide_cron_binary_file_does_not_crash(tmp_path, monkeypatch):
    monkeypatch.setattr(misc, "_AIDE_CRON_PATHS",
                        _cron_layout(tmp_path, b"\x7fELF\x02\x01\x00\xff\xfe\x00"))
    monkeypatch.setattr(misc.subprocess, "run", _timer_disabled)
    assert misc._check_aide_cron().status != "pass"


# --- 1.2.2: signed-by must be on an uncommented line apt actually reads ---

def test_signed_by_commented_line_does_not_count(tmp_path):
    (tmp_path / "vendor.list").write_text(
        "# deb [signed-by=/usr/share/keyrings/x.gpg] https://example.invalid/apt stable main\n"
    )
    assert misc._sources_have_signed_by(tmp_path) is False


def test_signed_by_one_line_form_counts(tmp_path):
    (tmp_path / "vendor.list").write_text(
        "deb [signed-by=/usr/share/keyrings/x.gpg] https://example.invalid/apt stable main\n"
    )
    assert misc._sources_have_signed_by(tmp_path) is True


def test_signed_by_deb822_form_counts(tmp_path):
    (tmp_path / "debian.sources").write_text(
        "Types: deb\n"
        "URIs: http://deb.debian.org/debian\n"
        "Suites: bookworm\n"
        "Components: main\n"
        "Signed-By: /usr/share/keyrings/x.gpg\n"
    )
    assert misc._sources_have_signed_by(tmp_path) is True


def test_signed_by_ignores_files_apt_does_not_read(tmp_path):
    (tmp_path / "vendor.list.save").write_text(
        "deb [signed-by=/usr/share/keyrings/x.gpg] https://example.invalid/apt stable main\n"
    )
    assert misc._sources_have_signed_by(tmp_path) is False


def test_signed_by_missing_dir_is_false(tmp_path):
    assert misc._sources_have_signed_by(tmp_path / "absent") is False


# --- 1.2.1: a comment-only sources.list configures no repository ---

def test_comment_only_sources_list_has_no_entry():
    assert misc._has_uncommented_line(
        "# Ubuntu sources have moved to /etc/apt/sources.list.d/ubuntu.sources\n\n"
    ) is False


def test_real_sources_list_entry_counts():
    assert misc._has_uncommented_line(
        "deb http://deb.debian.org/debian bookworm main\n"
    ) is True
