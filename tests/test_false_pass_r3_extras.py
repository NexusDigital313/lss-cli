# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file,
# via any medium, is strictly prohibited without explicit written authorization.

"""Round-3 false-pass regression tests for lss.controls.extras.

  - LSS-001: a LEGACY crypto policy with a subpolicy (LEGACY:AD-SUPPORT) or
    after a comment line passed, as did a DEFAULT config whose applied state
    is still LEGACY. An inline `#` in openssl.cnf no longer breaks the chain.
  - LSS-002: /etc/securetty passed while nothing enforced it: no file at all,
    or a file that pam_securetty never reads because it is not in the login
    PAM stack. A locked root password still passes.
  - 4.2.3: only the top level of /var/log was scanned (CIS uses
    `find /var/log -type f`), and an unreadable /var/log passed.
  - 2.4: a failed `ss` passed as "no services listening", and UDP listeners
    were never enumerated.
  - 5.4.5: the first TMOUT found decided the result, so a later TMOUT=0
    passed; TMOUT without readonly + export passed. The fixer now comments
    out out-of-range TMOUT lines so it satisfies its own check.
  - 4.1.2: the first audit_backlog_limit on the cmdline was read, but the
    kernel applies the last one.
  - LSS-004: a failed `systemctl show` passed as "condition is satisfied".
  - LSS-005: substring matches let `auid>=10000`, `-S execveat`, a `never`
    rule or a rule narrowed to euid=0 pass.
"""

from __future__ import annotations

import os
import subprocess

import pytest

from lss.controls import extras
from lss.lib import journal


def _run(stdout: str = "", rc: int = 0):
    def fake(cmd, *a, **kw):
        fake.calls.append(cmd)
        return subprocess.CompletedProcess(cmd, rc, stdout=stdout, stderr="")
    fake.calls = []
    return fake


@pytest.fixture(autouse=True)
def _no_backups(monkeypatch):
    monkeypatch.setattr(journal, "backup_file", lambda path, run_id=None: "")


# ---- LSS-001 ----

@pytest.fixture
def crypto(tmp_path, monkeypatch):
    conf = tmp_path / "config"
    state = tmp_path / "current"
    monkeypatch.setattr(extras, "_CRYPTO_POLICY_CONF", conf)
    monkeypatch.setattr(extras, "_CRYPTO_POLICY_STATE", state)
    monkeypatch.setattr(extras, "_OPENSSL_CNF", tmp_path / "openssl.cnf")
    return conf, state


def test_crypto_legacy_with_subpolicy_fails(crypto):
    crypto[0].write_text("LEGACY:AD-SUPPORT\n")
    assert extras._check_crypto_policy().status == "fail"


def test_crypto_legacy_after_comment_fails(crypto):
    crypto[0].write_text("# set by admin\nLEGACY  # temporary\n")
    assert extras._check_crypto_policy().status == "fail"


def test_crypto_config_default_but_applied_legacy_fails(crypto):
    crypto[0].write_text("DEFAULT\n")
    crypto[1].write_text("LEGACY\n")
    assert extras._check_crypto_policy().status == "fail"


def test_crypto_default_hardened_passes(crypto):
    crypto[0].write_text("DEFAULT:NO-SHA1\n")
    crypto[1].write_text("DEFAULT:NO-SHA1\n")
    assert extras._check_crypto_policy().status == "pass"


def test_openssl_inline_comment_still_traced(tmp_path, crypto):
    (tmp_path / "openssl.cnf").write_text(
        "openssl_conf = init # wire it\n[init]\nssl_conf = ssl\n"
        "[ssl]\nsystem_default = sd\n[sd]\nMinProtocol = TLSv1.2 # CIS\n"
    )
    assert extras._check_crypto_policy().status == "pass"


# ---- LSS-002 ----

@pytest.fixture
def tty(tmp_path, monkeypatch):
    pam = tmp_path / "pam.d"
    pam.mkdir()
    monkeypatch.setattr(extras, "_PAM_D", pam)
    monkeypatch.setattr(extras, "_SECURETTY", tmp_path / "securetty")
    monkeypatch.setattr(extras, "_SHADOW", tmp_path / "shadow")
    (tmp_path / "shadow").write_text("root:$6$abc$def:19000:0:99999:7:::\n")
    return tmp_path


def test_securetty_missing_root_unlocked_warns(tty):
    (tty / "pam.d" / "login").write_text("auth requisite pam_nologin.so\n@include common-auth\n")
    assert extras._check_securetty().status == "warn"


def test_securetty_file_not_read_by_pam_warns(tty):
    (tty / "securetty").write_text("console\ntty1\n")
    (tty / "pam.d" / "login").write_text(
        "# auth required pam_securetty.so\nauth requisite pam_nologin.so\n"
    )
    assert extras._check_securetty().status == "warn"


def test_securetty_enforced_passes(tty):
    (tty / "securetty").write_text("console\ntty1\n")
    (tty / "pam.d" / "login").write_text("@include common-auth\n")
    (tty / "pam.d" / "common-auth").write_text(
        "auth [success=ok new_authtok_reqd=ok ignore=ignore user_unknown=bad default=die] pam_securetty.so\n"
    )
    assert extras._check_securetty().status == "pass"


def test_securetty_root_locked_passes(tty):
    (tty / "pam.d" / "login").write_text("auth requisite pam_nologin.so\n")
    (tty / "shadow").write_text("root:!:19000:0:99999:7:::\n")
    assert extras._check_securetty().status == "pass"


def test_securetty_unreadable_shadow_not_pass(tty):
    (tty / "pam.d" / "login").write_text("auth requisite pam_nologin.so\n")
    (tty / "shadow").unlink()
    assert extras._check_securetty().status == "warn"


# ---- 4.2.3 ----

@pytest.fixture
def logdir(tmp_path, monkeypatch):
    d = tmp_path / "log"
    d.mkdir()
    monkeypatch.setattr(extras, "_LOG_DIR", str(d))
    return d


def test_log_world_readable_in_subdir_warns_and_fix_round_trips(logdir):
    (logdir / "apt").mkdir()
    f = logdir / "apt" / "history.log"
    f.write_text("x")
    f.chmod(0o644)
    assert extras._check_log_permissions().status == "warn"
    extras._fix_log_permissions()
    assert oct(f.stat().st_mode & 0o777) == oct(0o640)
    assert extras._check_log_permissions().status == "pass"


def test_log_symlink_target_not_touched(logdir, tmp_path):
    outside = tmp_path / "outside"
    outside.write_text("x")
    outside.chmod(0o644)
    os.symlink(outside, logdir / "link.log")
    assert extras._check_log_permissions().status == "pass"
    extras._fix_log_permissions()
    assert outside.stat().st_mode & 0o777 == 0o644


def test_log_dir_unreadable_not_pass(logdir, monkeypatch):
    monkeypatch.setattr(extras, "_LOG_DIR", str(logdir / "missing"))
    assert extras._check_log_permissions().status == "warn"


# ---- 2.4 ----

def test_ss_failure_not_pass(monkeypatch):
    monkeypatch.setattr(extras.subprocess, "run", _run("", rc=1))
    assert extras._check_listening_services().status == "warn"


def test_ss_udp_listener_counted(monkeypatch):
    fake = _run("udp UNCONN 0 0 0.0.0.0:161 0.0.0.0:* users:((\"snmpd\",pid=9,fd=6))\n")
    monkeypatch.setattr(extras.subprocess, "run", fake)
    r = extras._check_listening_services()
    assert "-tulnp" in fake.calls[0]
    assert r.status == "warn" and "161/udp" in r.detail


def test_ss_nothing_listening_passes(monkeypatch):
    monkeypatch.setattr(extras.subprocess, "run", _run(""))
    assert extras._check_listening_services().status == "pass"


# ---- 5.4.5 ----

@pytest.fixture
def shell(tmp_path, monkeypatch):
    prof = tmp_path / "profile"
    pd = tmp_path / "profile.d"
    pd.mkdir()
    monkeypatch.setattr(extras, "_SHELL_RC_FILES", [prof, tmp_path / "bash.bashrc"])
    monkeypatch.setattr(extras, "_PROFILE_D", pd)
    return prof, pd


def test_tmout_later_zero_override_not_pass(shell):
    prof, pd = shell
    prof.write_text("readonly TMOUT=600\nexport TMOUT\n")
    (pd / "zz-local.sh").write_text("TMOUT=0\n")
    assert extras._check_shell_timeout().status != "pass"


def test_tmout_not_readonly_fails(shell):
    shell[0].write_text("TMOUT=600\nexport TMOUT\n")
    assert extras._check_shell_timeout().status == "fail"


def test_tmout_commented_still_ignored(shell):
    shell[0].write_text("# readonly TMOUT=600; export TMOUT\n")
    assert extras._check_shell_timeout().status == "fail"


@pytest.mark.parametrize("text", [
    "readonly TMOUT=900 ; export TMOUT\n",
    'TMOUT="600"\nreadonly TMOUT\nexport TMOUT\n',
    "if [ -n \"$PS1\" ]; then declare -rx TMOUT=300; fi\n",
])
def test_tmout_hardened_passes(shell, text):
    shell[0].write_text(text)
    assert extras._check_shell_timeout().status == "pass"


def test_tmout_fix_round_trips_over_bad_override(shell):
    prof, pd = shell
    prof.write_text("export TMOUT=3600  # long sessions\n")
    (pd / "zz-local.sh").write_text("TMOUT=0\n")
    assert extras._check_shell_timeout().status != "pass"
    extras._fix_shell_timeout()
    assert extras._check_shell_timeout().status == "pass"
    assert prof.read_text().startswith("# [LSS-DISABLED] export TMOUT=3600")


def test_tmout_fix_from_scratch_passes(shell):
    extras._fix_shell_timeout()
    assert extras._check_shell_timeout().status == "pass"


# ---- 4.1.2 ----

@pytest.fixture
def cmdline(tmp_path, monkeypatch):
    p = tmp_path / "cmdline"
    monkeypatch.setattr(extras, "_PROC_CMDLINE", p)
    return p


def test_backlog_last_occurrence_wins(cmdline):
    cmdline.write_text("ro audit=1 audit_backlog_limit=8192 quiet audit_backlog_limit=64\n")
    assert extras._check_audit_backlog().status == "warn"


def test_backlog_hardened_passes(cmdline):
    cmdline.write_text("BOOT_IMAGE=/vmlinuz ro audit=1 audit_backlog_limit=8192\n")
    assert extras._check_audit_backlog().status == "pass"


# ---- LSS-004 ----

def test_apparmor_live_systemctl_failure_not_pass(monkeypatch):
    monkeypatch.setattr(extras, "_is_live_persistence", lambda: True)
    monkeypatch.setattr(extras.subprocess, "run", _run("", rc=1))
    assert extras._check_apparmor_live_condition().status == "warn"


def test_apparmor_live_condition_ok_passes(monkeypatch):
    monkeypatch.setattr(extras, "_is_live_persistence", lambda: True)
    monkeypatch.setattr(extras.subprocess, "run", _run("LoadState=loaded\nConditionResult=yes\n"))
    assert extras._check_apparmor_live_condition().status == "pass"


def test_apparmor_live_condition_skipped_fails(monkeypatch):
    monkeypatch.setattr(extras, "_is_live_persistence", lambda: True)
    monkeypatch.setattr(extras.subprocess, "run", _run("LoadState=loaded\nConditionResult=no\n"))
    assert extras._check_apparmor_live_condition().status == "fail"


# ---- LSS-005 ----

@pytest.mark.parametrize("rule", [
    "-a always,exit -F arch=b64 -S execve -F auid>=10000 -F auid!=-1 -F key=user-exec",
    "-a always,exit -F arch=b64 -S execveat -F auid>=1000 -F auid!=-1 -F key=user-exec",
    "-a never,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=-1",
    "-a always,exit -F arch=b64 -S execve -F auid>=1000 -F euid=0 -F key=priv",
    "-a always,exit -F arch=b64 -S execve -C uid!=euid -F auid>=1000 -F key=priv",
])
def test_execve_rule_lookalikes_not_pass(monkeypatch, rule):
    monkeypatch.setattr(extras.subprocess, "run", _run(rule + "\n"))
    assert extras._check_forensic_execve().status == "manual"


@pytest.mark.parametrize("rule", [
    "-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=-1 -F key=user-exec",
    "-a always,exit -F arch=b32 -S execve,execveat -F auid>=500 -F auid!=unset -k user-exec",
])
def test_execve_rule_hardened_passes(monkeypatch, rule):
    monkeypatch.setattr(extras.subprocess, "run", _run(rule + "\n"))
    assert extras._check_forensic_execve().status == "pass"
