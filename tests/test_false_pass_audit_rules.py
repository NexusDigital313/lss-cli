# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file,
# via any medium, is strictly prohibited without explicit written authorization.

"""Regression tests for the audit-rule false-pass class (CIS 4.1.3-4.1.16).

`_rule_is_active` / `_rule_is_persisted` decided pass with `pattern in line`,
where the pattern is the rule's audit key. Generic keys matched unrelated
rules — a watched path (`/etc/security/access.conf` satisfied 4.1.10), a
syscall name (`-S delete_module` satisfied 4.1.11), or a longer key — and a
commented-out rule counted as persisted. Matching is now on the key itself;
the no-regression guard proves every shipped rule set still passes in both
the `auditctl -l` (`-F key=`) and rules-file (`-k`) key forms.
"""

from __future__ import annotations

import subprocess

import pytest

from lss.controls import audit_rules
from lss.lib.registry import get_control


def _fake_auditctl(monkeypatch, stdout: str = "", returncode: int = 0,
                   status: str = "enabled 0\n") -> None:
    """Make `auditctl -l` return `stdout` and `auditctl -s` return `status`
    (default: not immutable); any other command fails the test."""
    def fake_run(argv, *args, **kwargs):
        if argv == ["auditctl", "-s"]:
            return subprocess.CompletedProcess(argv, 0, stdout=status, stderr="")
        assert argv == ["auditctl", "-l"], argv
        return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr="")
    monkeypatch.setattr(audit_rules.subprocess, "run", fake_run)


def _as_listed(rule: str) -> str:
    """Render a rule as `auditctl -l` prints it back: a syscall rule carries
    its key as `-F key=<k>`, a watch rule keeps `-k <k>`."""
    if rule.startswith("-a "):
        head, sep, key = rule.rpartition(" -k ")
        assert sep, rule
        return f"{head} -F key={key}"
    return rule


_RULES_BY_ID = {cid: rules for cid, _title, _key, rules in audit_rules._AUDIT_CONTROLS}
_CONTROL_IDS = list(_RULES_BY_ID)


# ---- _line_has_rule ----

@pytest.mark.parametrize("line, pattern", [
    ("-a always,exit -F arch=b64 -S adjtimex,settimeofday -F key=time-change", "time-change"),
    ("-w /etc/localtime -p wa -k time-change", "time-change"),
    ("-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F key=access", "access"),
    ('-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F key="access"', "access"),
    ("-w /etc/security/access.conf -p wa -k identity", "identity"),
    ("-e 2", "-e 2"),
])
def test_line_has_rule_matches_the_key(line, pattern):
    assert audit_rules._line_has_rule(line, pattern)


@pytest.mark.parametrize("line, pattern", [
    # Generic key only inside a watched path.
    ("-w /etc/security/access.conf -p wa -k identity", "access"),
    # Generic key only as part of a longer key.
    ("-a always,exit -F arch=b64 -S open -F key=unauthorized-access", "access"),
    ("-a always,exit -F arch=b64 -S open -F key=access-extra", "access"),
    ("-a always,exit -F arch=b64 -S execve -F key=privileged-actions", "actions"),
    # Generic key only as a syscall name (shipped 4.1.14 rule vs 4.1.11's key).
    ("-a always,exit -F arch=b64 -S init_module,delete_module -F key=modules", "delete"),
    ("-a always,exit -F arch=b64 -S adjtimex -F key=time-change", "-e 2"),
])
def test_line_has_rule_rejects_non_key_occurrences(line, pattern):
    assert not audit_rules._line_has_rule(line, pattern)


# ---- _rule_is_active ----

def test_rule_is_active_uses_key_matching(monkeypatch):
    _fake_auditctl(monkeypatch, "-w /etc/security/access.conf -p wa -k identity\n")
    assert audit_rules._rule_is_active("identity")
    assert not audit_rules._rule_is_active("access")


def test_rule_is_active_false_when_auditctl_fails(monkeypatch):
    _fake_auditctl(monkeypatch, "-w /etc/passwd -p wa -k identity\n", returncode=1)
    assert not audit_rules._rule_is_active("identity")


def test_rule_is_active_false_when_auditctl_missing(monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError("auditctl")
    monkeypatch.setattr(audit_rules.subprocess, "run", missing)
    assert not audit_rules._rule_is_active("identity")


# ---- _rule_is_persisted ----

@pytest.mark.parametrize("text, expected", [
    ("# -w /etc/passwd -p wa -k identity\n", False),
    ("   # -w /etc/passwd -p wa -k identity\n", False),
    ("-w /etc/passwd -p wa -k identity\n", True),
    ("# LSS audit rules\n-w /etc/passwd -p wa -k identity\n", True),
])
def test_rule_is_persisted_ignores_comments(tmp_path, monkeypatch, text, expected):
    (tmp_path / "50-test.rules").write_text(text)
    monkeypatch.setattr(audit_rules, "AUDIT_RULES_DIR", str(tmp_path))
    assert audit_rules._rule_is_persisted("identity") is expected


def test_rule_is_persisted_uses_key_matching(tmp_path, monkeypatch):
    (tmp_path / "50-test.rules").write_text("-w /etc/security/access.conf -p wa -k identity\n")
    monkeypatch.setattr(audit_rules, "AUDIT_RULES_DIR", str(tmp_path))
    assert audit_rules._rule_is_persisted("identity")
    assert not audit_rules._rule_is_persisted("access")


# ---- No-regression guard over every shipped audit control ----

@pytest.mark.parametrize("render", [_as_listed, lambda rule: rule], ids=["auditctl-l", "rules-file"])
@pytest.mark.parametrize("cid", _CONTROL_IDS)
def test_shipped_rules_satisfy_their_control(tmp_path, monkeypatch, cid, render):
    """Each control's own rules, loaded, must still pass in either key form —
    the stricter match must not false-FAIL a compliant host. CIS also needs
    them persisted (round 3), so the rules file carries them too."""
    _fake_auditctl(monkeypatch, "\n".join(render(r) for r in _RULES_BY_ID[cid]) + "\n")
    monkeypatch.setattr(audit_rules, "AUDIT_RULES_DIR", str(tmp_path))
    (tmp_path / "80-lss-test.rules").write_text("\n".join(_RULES_BY_ID[cid]) + "\n")
    assert get_control(cid).check().status == "pass"


@pytest.mark.parametrize("cid", _CONTROL_IDS)
def test_control_fails_with_no_rules(tmp_path, monkeypatch, cid):
    _fake_auditctl(monkeypatch, "")
    monkeypatch.setattr(audit_rules, "AUDIT_RULES_DIR", str(tmp_path))
    assert get_control(cid).check().status == "fail"


@pytest.mark.parametrize("cid", _CONTROL_IDS)
def test_other_controls_rules_do_not_satisfy_control(tmp_path, monkeypatch, cid):
    """Loading every OTHER shipped rule set must not pass this control. The
    old substring match let 4.1.14's `-S delete_module` satisfy 4.1.11."""
    others = [_as_listed(r) for oid, rules in _RULES_BY_ID.items() if oid != cid for r in rules]
    _fake_auditctl(monkeypatch, "\n".join(others) + "\n")
    monkeypatch.setattr(audit_rules, "AUDIT_RULES_DIR", str(tmp_path))
    assert get_control(cid).check().status == "fail"


@pytest.mark.parametrize("cid", _CONTROL_IDS)
def test_persisted_but_not_loaded_warns(tmp_path, monkeypatch, cid):
    (tmp_path / "80-lss-test.rules").write_text(
        "# LSS audit rules\n" + "\n".join(_RULES_BY_ID[cid]) + "\n"
    )
    _fake_auditctl(monkeypatch, "")
    monkeypatch.setattr(audit_rules, "AUDIT_RULES_DIR", str(tmp_path))
    assert get_control(cid).check().status == "warn"


def test_immutable_flag_keeps_substring_match(tmp_path, monkeypatch):
    """4.1.16's `-e 2` flag is not a key, so it keeps substring matching; only
    an uncommented flag counts as persisted."""
    _fake_auditctl(monkeypatch, "")
    monkeypatch.setattr(audit_rules, "AUDIT_RULES_DIR", str(tmp_path))
    rules = tmp_path / "99-finalize.rules"
    rules.write_text("# -e 2\n")
    assert get_control("4.1.16").check().status == "manual"
    rules.write_text("-e 2\n")
    assert get_control("4.1.16").check().status == "warn"


def test_immutable_active_passes_via_auditctl_s(tmp_path, monkeypatch):
    """The immutable flag is reported by `auditctl -s` (`enabled 2`), never by
    `auditctl -l`. Reading it from `-l` meant 4.1.16 could never pass at
    runtime; it must pass when the kernel reports enabled 2."""
    monkeypatch.setattr(audit_rules, "AUDIT_RULES_DIR", str(tmp_path))
    # Loaded rules (-l) never carry -e 2; status (-s) is the only source.
    _fake_auditctl(monkeypatch, "", status="enabled 2\nfailure 1\n")
    assert get_control("4.1.16").check().status == "pass"
    # enabled 1 (on, mutable) is not immutable, even with -e 2 persisted.
    (tmp_path / "99-finalize.rules").write_text("-e 2\n")
    _fake_auditctl(monkeypatch, "", status="enabled 1\n")
    assert get_control("4.1.16").check().status == "warn"
