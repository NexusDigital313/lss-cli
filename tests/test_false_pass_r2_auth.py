# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file,
# via any medium, is strictly prohibited without explicit written authorization.

"""False-pass regression tests, round 2: PAM, password policy and accounts.

  - 5.3.2 passed on any pam_faillock line. Without `preauth` before pam_unix
    nothing is ever locked out; authfail after pam_unix and pam_faillock in
    the account stack are required too. LSS's own pam-config profile lacked
    preauth; it now ships the CIS faillock + faillock_notify pair.
  - 5.3.1 / 5.3.4 / 5.3.7 read pwquality.conf only (first value). Module
    arguments override the conf, pwquality.conf overrides pwquality.conf.d,
    and 5.3.4 / 5.3.7 passed with the module not loaded at all.
  - login.defs checks read the first occurrence; shadow-utils applies the
    last. pam._set_login_defs rewrote Debian's `#\tPASS_MIN_DAYS` comment and
    left the real line in force; the pwquality fixers rewrote comments too.
  - 5.6 passed `pam_wheel.so deny group=nosu`. 5.3.5 read RHEL's auth
    pam_unix line, never the password line. Inline `#` comments counted.
  - 6.2.1 compared UIDs as strings (`00` is root). 5.4.4 compared the umask
    numerically (`070` passed) and ignored profile/bashrc/pam_umask
    overrides. 5.4.1.1-5.4.1.4 never looked at existing accounts in
    /etc/shadow.
"""

from __future__ import annotations

import pytest

from lss.controls import auth, pam

# common-auth / common-account exactly as pam-auth-update 1.5.2 (debian:12)
# writes them with LSS's faillock + faillock_notify profiles enabled.
_CIS_COMMON_AUTH = (
    "auth\trequisite\tpam_faillock.so preauth\n"
    "auth\t[success=2 default=ignore]\tpam_unix.so nullok try_first_pass\n"
    "auth\t[default=die]\tpam_faillock.so authfail\n"
    "auth\trequisite\t\t\tpam_deny.so\n"
    "auth\trequired\t\t\tpam_permit.so\n"
)
_CIS_COMMON_ACCOUNT = (
    "account\trequired\tpam_faillock.so \n"
    "account\t[success=1 new_authtok_reqd=done default=ignore]\tpam_unix.so \n"
    "account\trequisite\t\t\tpam_deny.so\n"
    "account\trequired\t\t\tpam_permit.so\n"
)
# Old LSS profile layout: authfail only, no preauth.
_AUTHFAIL_ONLY = (
    "auth\t[success=2 default=ignore]\tpam_unix.so nullok\n"
    "auth\t[default=ignore]\tpam_faillock.so authfail\n"
    "auth\trequisite\tpam_deny.so\n"
    "auth\trequired\tpam_permit.so\n"
)
_PAM_UNIX_PW = "password [success=1 default=ignore] pam_unix.so obscure yescrypt\n"
_SHADOW_OK = (
    "root:$y$j9T$abc:19000:1:365:7:30::\n"
    "daemon:*:19000:0:99999:7:::\n"
    "locked:!$6$xyz:19000:0:99999:7:::\n"
)


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Point every path constant in auth.py / pam.py at (absent) tmp files."""
    def p(name):
        return str(tmp_path / name)

    for mod in (auth, pam):
        monkeypatch.setattr(mod, "PWQUALITY_CONF", p("pwquality.conf"))
        monkeypatch.setattr(mod, "PWQUALITY_CONF_D", p("pwquality.conf.d"))
        monkeypatch.setattr(mod, "PASSWORD_STACKS", (p("common-password"), p("system-auth"), p("password-auth")))
        monkeypatch.setattr(mod, "LOGIN_DEFS", p("login.defs"))
    monkeypatch.setattr(pam, "FAILLOCK_CONF", p("faillock.conf"))
    monkeypatch.setattr(pam, "COMMON_AUTH", p("common-auth"))
    monkeypatch.setattr(pam, "COMMON_ACCOUNT", p("common-account"))
    monkeypatch.setattr(pam, "RHEL_AUTH_STACKS", (p("system-auth"), p("password-auth")))
    monkeypatch.setattr(pam, "_FAILLOCK_PROFILE_PATH", tmp_path / "pam-configs" / "faillock")
    monkeypatch.setattr(pam, "_FAILLOCK_NOTIFY_PROFILE_PATH", tmp_path / "pam-configs" / "faillock_notify")
    monkeypatch.setattr(auth, "SHADOW", p("shadow"))
    monkeypatch.setattr(auth, "PASSWD", p("passwd"))
    monkeypatch.setattr(auth, "PAM_SU", p("su"))
    monkeypatch.setattr(auth, "PROFILE_D", p("profile.d"))
    monkeypatch.setattr(auth, "UMASK_SHELL_FILES", (p("profile"), p("bashrc"), p("bash.bashrc")))
    monkeypatch.setattr(auth, "UMASK_PAM_FILES", (p("common-session"),))

    def write(name, text):
        f = tmp_path / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
        return f

    return write


@pytest.fixture
def isolated_journal(tmp_path, monkeypatch):
    from lss.lib import journal
    monkeypatch.setattr(journal, "BACKUPS_DIR", tmp_path / "backups")
    journal.set_current_run_id("test-run")
    yield journal
    journal.set_current_run_id(None)


# ---- 5.3.2: faillock ----

def test_5_3_2_authfail_without_preauth_does_not_pass(env):
    env("common-auth", _AUTHFAIL_ONLY)
    env("common-account", _CIS_COMMON_ACCOUNT)
    r = pam._check_faillock()
    assert r.status != "pass" and "preauth" in r.detail


def test_5_3_2_cis_layout_passes(env):
    env("common-auth", _CIS_COMMON_AUTH)
    env("common-account", _CIS_COMMON_ACCOUNT)
    assert pam._check_faillock().status == "pass"


@pytest.mark.parametrize("auth_text,account_text", [
    # preauth after pam_unix: the password is checked before the lock is.
    (_CIS_COMMON_AUTH.replace("auth\trequisite\tpam_faillock.so preauth\n", "")
     + "auth required pam_faillock.so preauth\n", _CIS_COMMON_ACCOUNT),
    # preauth with a non-enforcing control: the PAM_AUTH_ERR is ignored.
    (_CIS_COMMON_AUTH.replace("requisite\tpam_faillock.so preauth", "optional\tpam_faillock.so preauth"),
     _CIS_COMMON_ACCOUNT),
    # preauth only inside an inline comment.
    (_CIS_COMMON_AUTH.replace("auth\trequisite\tpam_faillock.so preauth\n",
                              "auth requisite pam_deny.so # pam_faillock.so preauth\n"),
     _CIS_COMMON_ACCOUNT),
    # no pam_faillock in common-account.
    (_CIS_COMMON_AUTH, "account [success=1 default=ignore] pam_unix.so\n"),
])
def test_5_3_2_incomplete_layouts_do_not_pass(env, auth_text, account_text):
    env("common-auth", auth_text)
    env("common-account", account_text)
    assert pam._check_faillock().status != "pass"


_RHEL_WITH_FAILLOCK = (
    "auth        required      pam_env.so\n"
    "auth        required      pam_faillock.so preauth silent\n"
    "auth        sufficient    pam_unix.so nullok\n"
    "auth        required      pam_faillock.so authfail\n"
    "auth        required      pam_deny.so\n"
    "account     required      pam_faillock.so\n"
    "account     required      pam_unix.so\n"
)


def test_5_3_2_rhel_with_faillock_passes_and_needs_both_stacks(env):
    env("system-auth", _RHEL_WITH_FAILLOCK)
    env("password-auth", _RHEL_WITH_FAILLOCK)
    assert pam._check_faillock().status == "pass"
    env("password-auth", _RHEL_WITH_FAILLOCK.replace("auth        required      pam_faillock.so preauth silent\n", ""))
    assert pam._check_faillock().status != "pass"


def test_5_3_2_fix_installs_preauth_profile_and_replaces_old_lss_one(env, isolated_journal, tmp_path):
    old = env("pam-configs/faillock", "Name: pam_faillock (provided by LSS)\nAuth:\n\t[default=ignore]\tpam_faillock.so authfail\n")
    env("faillock.conf", "# deny = 3\n")
    pam._fix_faillock()
    notify = (tmp_path / "pam-configs" / "faillock_notify").read_text()
    assert "Priority: 1024" in notify and "requisite\tpam_faillock.so preauth" in notify
    assert "Account-Type: Primary" in notify and "required\tpam_faillock.so" in notify
    fl = old.read_text()
    assert "Priority: 0" in fl and "[default=die]\tpam_faillock.so authfail" in fl


def test_5_3_2_fix_leaves_foreign_profile_alone(env, isolated_journal):
    foreign = env("pam-configs/faillock", "Name: distro faillock\n")
    pam._fix_faillock()
    assert foreign.read_text() == "Name: distro faillock\n"


# ---- 5.3.1 / 5.3.4 / 5.3.7: pwquality ----

_PWQ_LINE = "password requisite pam_pwquality.so retry=3\n"


def test_5_3_4_module_argument_overrides_conf(env):
    env("pwquality.conf", "minlen = 14\n")
    env("common-password", "password requisite pam_pwquality.so retry=3 minlen=8\n" + _PAM_UNIX_PW)
    assert auth._check_password_minlen().status == "fail"


def test_5_3_4_pwquality_conf_wins_over_conf_d(env):
    env("common-password", _PWQ_LINE + _PAM_UNIX_PW)
    env("pwquality.conf.d/50-site.conf", "minlen = 14\n")
    env("pwquality.conf", "minlen = 8\n")
    assert auth._check_password_minlen().status == "fail"
    env("pwquality.conf", "minlen = 14\n")
    env("pwquality.conf.d/50-site.conf", "minlen = 8\n")
    assert auth._check_password_minlen().status == "pass"


def test_5_3_4_last_value_in_conf_wins(env):
    env("common-password", _PWQ_LINE + _PAM_UNIX_PW)
    env("pwquality.conf", "minlen = 14\nminlen = 8\n")
    assert auth._check_password_minlen().status == "fail"


def test_5_3_4_requires_module_loaded(env):
    env("pwquality.conf", "minlen = 14\n")
    env("common-password", "# " + _PWQ_LINE + _PAM_UNIX_PW)
    assert auth._check_password_minlen().status != "pass"


def test_5_3_4_inline_comment_does_not_count(env):
    env("common-password", "password requisite pam_pwquality.so retry=3 # minlen=14\n" + _PAM_UNIX_PW)
    assert auth._check_password_minlen().status != "pass"


def test_5_3_7_requires_module_loaded(env):
    env("pwquality.conf", "retry = 3\n")
    env("common-password", _PAM_UNIX_PW)
    assert pam._check_pw_retry().status != "pass"


def test_5_3_7_module_argument_overrides_conf(env):
    env("pwquality.conf", "retry = 3\n")
    env("common-password", "password requisite pam_pwquality.so retry=5\n" + _PAM_UNIX_PW)
    assert pam._check_pw_retry().status == "fail"


def test_5_3_1_module_argument_overrides_conf(env):
    env("pwquality.conf", "dcredit = -1\nucredit = -1\nlcredit = -1\nocredit = -1\n")
    env("common-password", "password requisite pam_pwquality.so dcredit=0\n" + _PAM_UNIX_PW)
    assert pam._check_pw_complexity().status == "fail"
    env("common-password", _PWQ_LINE + _PAM_UNIX_PW)
    assert pam._check_pw_complexity().status == "pass"


def test_5_3_1_conf_d_value_overridden_by_weaker_conf(env):
    env("common-password", _PWQ_LINE + _PAM_UNIX_PW)
    env("pwquality.conf.d/10-cis.conf", "dcredit = -1\nucredit = -1\nlcredit = -1\nocredit = -1\n")
    env("pwquality.conf", "dcredit = 0\n")
    assert pam._check_pw_complexity().status == "fail"


def test_pwquality_fixers_keep_comments_and_win_round_trip(env, isolated_journal, tmp_path):
    env("common-password", _PWQ_LINE + _PAM_UNIX_PW)
    env("pwquality.conf.d/50-weak.conf", "minlen = 6\ndcredit = 1\nretry = 9\n")
    conf = env("pwquality.conf", "# minlen = 8\n# dcredit = 0\nminlen = 6\nretry = 5\nminlen = 7\n")
    auth._fix_password_minlen()
    pam._fix_pw_complexity()
    pam._fix_pw_retry()
    text = conf.read_text()
    assert text.startswith("# minlen = 8\n# dcredit = 0\n")
    assert "minlen = 7" not in text and text.count("minlen = 14") == 1
    assert auth._check_password_minlen().status == "pass"
    assert pam._check_pw_complexity().status == "pass"
    assert pam._check_pw_retry().status == "pass"


# ---- login.defs ----

def test_5_4_1_1_last_login_defs_occurrence_wins(env):
    env("shadow", _SHADOW_OK)
    env("login.defs", "PASS_MAX_DAYS\t90\nPASS_MAX_DAYS\t99999\n")
    assert auth._check_pass_max_days().status == "fail"


def test_5_3_6_fix_leaves_debian_comment_and_sets_real_line(env, isolated_journal):
    defs = env("login.defs", "#\tPASS_MIN_DAYS\tMinimum number of days allowed between password changes.\n"
                             "PASS_MAX_DAYS\t99999\nPASS_MIN_DAYS\t0\n")
    env("shadow", _SHADOW_OK)
    pam._fix_pam_mindays()
    text = defs.read_text()
    assert text.startswith("#\tPASS_MIN_DAYS\tMinimum number")
    assert "PASS_MIN_DAYS\t0" not in text
    assert pam._check_pam_mindays().status == "pass"
    assert auth._check_pass_min_days().status == "pass"


def test_auth_set_login_def_leaves_no_conflicting_copy(env, isolated_journal):
    env("shadow", _SHADOW_OK)
    defs = env("login.defs", "PASS_WARN_AGE\t3\nUMASK 022\nPASS_WARN_AGE\t1\n")
    auth._fix_pass_warn_age()
    assert defs.read_text().count("PASS_WARN_AGE") == 1
    assert auth._check_pass_warn_age().status == "pass"


def test_5_3_5_hash_last_login_defs_occurrence(env):
    env("login.defs", "ENCRYPT_METHOD SHA512\nENCRYPT_METHOD MD5\n")
    assert pam._check_pw_hash().status == "fail"


# ---- 5.6 / 5.3.5 PAM line parsing ----

@pytest.mark.parametrize("su_text", [
    "auth required pam_wheel.so deny group=nosu\n",
    "auth required pam_wheel.so # use_uid group=sudo\n",
    "auth optional pam_wheel.so use_uid group=sudo\n",
    "# auth required pam_wheel.so use_uid group=sudo\n",
])
def test_5_6_non_restricting_pam_wheel_does_not_pass(env, su_text):
    env("su", "auth sufficient pam_rootok.so\n" + su_text)
    assert auth._check_su_restricted().status != "pass"


def test_5_6_cis_pam_wheel_passes(env):
    env("su", "auth sufficient pam_rootok.so\nauth required pam_wheel.so use_uid group=sugroup\n")
    assert auth._check_su_restricted().status == "pass"


def test_5_3_5_rhel_password_line_md5_fails(env):
    env("login.defs", "ENCRYPT_METHOD SHA512\n")
    env("system-auth", "auth sufficient pam_unix.so nullok\n"
                       "password sufficient pam_unix.so md5 shadow use_authtok\n")
    assert pam._check_pw_hash().status == "fail"


def test_5_3_5_inline_comment_algorithm_does_not_count(env):
    env("login.defs", "ENCRYPT_METHOD MD5\n")
    env("common-password", "password [success=1 default=ignore] pam_unix.so obscure # sha512\n")
    assert pam._check_pw_hash().status == "fail"


def test_5_3_5_strong_password_line_passes(env):
    env("login.defs", "ENCRYPT_METHOD MD5\n")
    env("common-password", _PAM_UNIX_PW)
    assert pam._check_pw_hash().status == "pass"


# ---- 6.2.1 / 6.2.2 ----

def test_6_2_1_uid_00_is_root(env):
    env("passwd", "root:x:0:0:root:/root:/bin/bash\ntoor:x:00:0::/root:/bin/sh\n")
    r = auth._check_uid_zero()
    assert r.status == "fail" and "toor" in r.detail


def test_6_2_2_root_gid_00_is_zero(env):
    env("passwd", "root:x:0:00:root:/root:/bin/bash\n")
    assert auth._check_root_gid().status == "pass"


# ---- 5.4.4 umask ----

@pytest.mark.parametrize("value,status", [("070", "fail"), ("007", "fail"), ("027", "pass"),
                                          ("077", "pass"), ("0027", "pass"), ("022", "fail")])
def test_5_4_4_umask_is_a_bitmask(env, value, status):
    env("login.defs", f"UMASK\t{value}\n")
    assert auth._check_umask().status == status


@pytest.mark.parametrize("name,text", [
    ("profile", 'if [ "$UID" -gt 199 ]; then\n    umask 002\nfi\n'),
    ("profile.d/local.sh", "umask 022\n"),
    ("bash.bashrc", "[ -n \"$PS1\" ] && umask u=rwx,g=rwx,o=rx\n"),
    ("common-session", "session optional pam_umask.so umask=0022\n"),
])
def test_5_4_4_weaker_override_fails(env, name, text):
    env("login.defs", "UMASK\t027\n")
    env(name, text)
    r = auth._check_umask()
    assert r.status == "fail" and name.split("/")[-1] in r.detail


def test_5_4_4_strict_profile_override_passes(env):
    env("login.defs", "UMASK\t027\n")
    env("profile.d/cis.sh", "umask 027  # CIS\n")
    env("bash.bashrc", "umask u=rwx,g=rx,o=\n")
    assert auth._check_umask().status == "pass"


def test_5_4_4_fix_round_trip(env, isolated_journal):
    env("login.defs", "# UMASK is the default umask value\nUMASK\t022\n")
    auth._fix_umask()
    assert auth._check_umask().status == "pass"


# ---- 5.4.1.x: existing accounts in /etc/shadow ----

_DEFS_OK = "PASS_MAX_DAYS\t365\nPASS_MIN_DAYS\t1\nPASS_WARN_AGE\t7\n"


@pytest.mark.parametrize("check,shadow_line,user", [
    ("_check_pass_max_days", "alice:$6$h:19000:1:99999:7:30::\n", "alice"),
    ("_check_pass_max_days", "bob:$6$h:19000:1::7:30::\n", "bob"),
    ("_check_pass_min_days", "carol:$y$h:19000:0:365:7:30::\n", "carol"),
    ("_check_pass_warn_age", "dave:$y$h:19000:1:365:3:30::\n", "dave"),
])
def test_5_4_1_existing_accounts_checked(env, check, shadow_line, user):
    env("login.defs", _DEFS_OK)
    env("shadow", _SHADOW_OK + shadow_line)
    r = getattr(auth, check)()
    assert r.status == "fail" and user in r.detail and "chage" in r.detail


def test_5_4_1_compliant_accounts_and_locked_ones_pass(env):
    env("login.defs", _DEFS_OK)
    env("shadow", _SHADOW_OK)
    for check in ("_check_pass_max_days", "_check_pass_min_days", "_check_pass_warn_age"):
        assert getattr(auth, check)().status == "pass"


def test_5_4_1_unreadable_shadow_is_not_pass(env):
    env("login.defs", _DEFS_OK)
    assert auth._check_pass_max_days().status == "warn"


def _useradd_d(inactive):
    class R:
        returncode = 0
        stdout = f"GROUP=100\nINACTIVE={inactive}\nSHELL=/bin/sh\n"
        stderr = ""
    return lambda *a, **k: R()


def test_5_4_1_4_existing_account_without_inactive_fails(env, monkeypatch):
    monkeypatch.setattr(auth.subprocess, "run", _useradd_d(30))
    env("shadow", _SHADOW_OK + "erin:$6$h:19000:1:365:7:::\n")
    r = auth._check_inactive_lock()
    assert r.status == "fail" and "erin" in r.detail
    env("shadow", _SHADOW_OK)
    assert auth._check_inactive_lock().status == "pass"
