# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file,
# via any medium, is strictly prohibited without explicit written authorization.

"""Round-3 false-pass regression tests for the 4.1.3-4.1.15 audit-rule checks.

Each check passed as soon as ONE loaded rule carried the control's key, and
never looked at the persisted rules once a loaded one matched:

- A partial rule set passed: `-w /etc/group -p wa -k identity` alone passed
  4.1.4 with passwd/shadow/gshadow unwatched; b64-only syscall rules passed
  on an x86_64 host, where 32-bit callers go unaudited; 4.1.10 passed with
  the EACCES rules but no EPERM rules.
- A watch with the wrong permissions (`-p r`) or an `-a never,exit` rule
  counted as collecting the events.
- Rules loaded with `auditctl` but missing from /etc/audit/rules.d passed,
  although augenrules deletes them the next time auditd starts. CIS checks
  both the on-disk and the running configuration.
- The fixer skipped a rule whose text appeared in its own file inside a
  comment, so `lss harden` left the control unpersisted.

Hardened hosts still pass: rules as `auditctl -l` prints them back (syscalls
merged with commas, `-F key=`, `auid!=-1`, directory watches without the
trailing slash, /run for /var/run), the fixer's own output, aarch64 hosts
that lack legacy syscalls, and 32-bit hosts without b64 rules.
"""

from __future__ import annotations

import subprocess

import pytest

from lss.controls import audit_rules
from lss.lib.registry import get_control

_RULES_BY_ID = {cid: rules for cid, _t, _k, rules in audit_rules._AUDIT_CONTROLS}
_CONTROL_IDS = list(_RULES_BY_ID)


class _Host:
    """Fake auditctl/ausyscall. `loaded` is what `auditctl -l` prints;
    `unknown` holds syscall names ausyscall does not know on this machine."""

    def __init__(self, monkeypatch, tmp_path, loaded="", machine="x86_64",
                 unknown=(), auditctl_rc=0):
        self.loaded = loaded
        self.unknown = set(unknown)
        self.added: list[list[str]] = []
        self.rc = auditctl_rc
        monkeypatch.setattr(audit_rules.subprocess, "run", self.run)
        monkeypatch.setattr(audit_rules, "AUDIT_RULES_DIR", str(tmp_path / "rules.d"))
        monkeypatch.setattr(audit_rules, "_machine", lambda: machine)
        (tmp_path / "rules.d").mkdir(exist_ok=True)
        self.rules_d = tmp_path / "rules.d"

    def run(self, argv, *a, **kw):
        if argv == ["auditctl", "-l"]:
            return subprocess.CompletedProcess(argv, self.rc, stdout=self.loaded, stderr="")
        if argv[0] == "ausyscall":
            name = argv[2]
            if name in self.unknown:
                return subprocess.CompletedProcess(
                    argv, 1, stdout="", stderr=f"Unknown syscall {name} using {argv[1]} lookup table\n")
            return subprocess.CompletedProcess(argv, 0, stdout="42\n", stderr="")
        if argv[0] == "auditctl":
            self.added.append(argv[1:])
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        raise AssertionError(argv)

    def persist(self, rules):
        (self.rules_d / "50-site.rules").write_text("\n".join(rules) + "\n")


def _listed(rule: str) -> str:
    """Render a shipped rule the way `auditctl -l` prints it back."""
    if rule.startswith("-a "):
        toks = rule.split()
        syscalls = [toks[i + 1] for i, t in enumerate(toks) if t == "-S"]
        rest, i = [], 0
        while i < len(toks):
            if toks[i] == "-S":
                i += 2
                continue
            rest.append(toks[i])
            i += 1
        head = " ".join(rest[:4])  # -a always,exit -F arch=bNN
        tail = " ".join(rest[4:]).replace("4294967295", "-1")
        tail, _, key = tail.rpartition("-k ")
        return f"{head} -S {','.join(syscalls)} {tail}-F key={key}"
    return rule.replace("/var/run/", "/run/").replace("/ -p", " -p")


def _status(cid):
    return get_control(cid).check().status


# ---- Partial rule sets ----

def test_one_watch_does_not_pass_identity(monkeypatch, tmp_path):
    rule = ["-w /etc/group -p wa -k identity"]
    h = _Host(monkeypatch, tmp_path, loaded=rule[0] + "\n")
    h.persist(rule)
    r = get_control("4.1.4").check()
    assert r.status == "fail"
    assert "/etc/shadow" in r.detail


def test_b64_only_rules_fail_on_x86_64(monkeypatch, tmp_path):
    rules = [r for r in _RULES_BY_ID["4.1.11"] if "arch=b32" not in r]
    h = _Host(monkeypatch, tmp_path, loaded="\n".join(map(_listed, rules)) + "\n")
    h.persist(rules)
    assert _status("4.1.11") == "fail"


def test_eacces_without_eperm_fails_access(monkeypatch, tmp_path):
    rules = [r for r in _RULES_BY_ID["4.1.10"] if "EPERM" not in r]
    h = _Host(monkeypatch, tmp_path, loaded="\n".join(map(_listed, rules)) + "\n")
    h.persist(rules)
    assert _status("4.1.10") == "fail"


def test_missing_syscall_fails(monkeypatch, tmp_path):
    rules = [r.replace(" -S rename -S renameat", "") for r in _RULES_BY_ID["4.1.11"]]
    h = _Host(monkeypatch, tmp_path, loaded="\n".join(map(_listed, rules)) + "\n")
    h.persist(rules)
    assert _status("4.1.11") == "fail"


def test_read_only_watch_fails(monkeypatch, tmp_path):
    rules = [r.replace("-p wa", "-p r") for r in _RULES_BY_ID["4.1.12"]]
    h = _Host(monkeypatch, tmp_path, loaded="\n".join(rules) + "\n")
    h.persist(rules)
    assert _status("4.1.12") == "fail"


def test_never_rule_does_not_collect(monkeypatch, tmp_path):
    rules = [r.replace("-a always,exit", "-a never,exit") for r in _RULES_BY_ID["4.1.15"]]
    h = _Host(monkeypatch, tmp_path, loaded="\n".join(map(_listed, rules)) + "\n")
    h.persist(rules)
    assert _status("4.1.15") == "fail"


# ---- Loaded but not persisted ----

@pytest.mark.parametrize("cid", _CONTROL_IDS)
def test_loaded_but_not_persisted_fails(monkeypatch, tmp_path, cid):
    _Host(monkeypatch, tmp_path, loaded="\n".join(map(_listed, _RULES_BY_ID[cid])) + "\n")
    r = get_control(cid).check()
    assert r.status == "fail"
    assert "not persisted" in r.detail


def test_persisted_and_auditctl_failing_is_not_pass(monkeypatch, tmp_path):
    h = _Host(monkeypatch, tmp_path, loaded="", auditctl_rc=1)
    h.persist(_RULES_BY_ID["4.1.4"])
    assert _status("4.1.4") == "warn"


# ---- Hardened hosts still pass ----

@pytest.mark.parametrize("cid", _CONTROL_IDS)
def test_hardened_host_passes(monkeypatch, tmp_path, cid):
    h = _Host(monkeypatch, tmp_path, loaded="\n".join(map(_listed, _RULES_BY_ID[cid])) + "\n")
    h.persist(_RULES_BY_ID[cid])
    assert _status(cid) == "pass"


def test_merged_syscalls_across_rules_pass(monkeypatch, tmp_path):
    rules = [
        "-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change",
        "-a always,exit -F arch=b32 -S adjtimex,settimeofday,stime -k time-change",
        "-w /etc/localtime -p rwa -k time-change",
    ]
    h = _Host(monkeypatch, tmp_path, loaded="\n".join(rules) + "\n")
    h.persist(rules)
    assert _status("4.1.3") == "pass"


def test_aarch64_without_legacy_syscalls_passes(monkeypatch, tmp_path):
    rules = [
        "-a always,exit -F arch=b64 -S unlinkat -S renameat -F auid>=1000 -F auid!=4294967295 -k delete",
        "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete",
    ]
    h = _Host(monkeypatch, tmp_path, loaded="\n".join(map(_listed, rules)) + "\n",
              machine="aarch64", unknown={"unlink", "rename"})
    h.persist(rules)
    assert _status("4.1.11") == "pass"
    h.unknown = set()  # the same rules on a kernel that has unlink/rename
    assert _status("4.1.11") == "fail"


def test_32bit_host_without_b64_rules_passes(monkeypatch, tmp_path):
    rules = [r for r in _RULES_BY_ID["4.1.11"] if "arch=b64" not in r]
    h = _Host(monkeypatch, tmp_path, loaded="\n".join(map(_listed, rules)) + "\n", machine="i686")
    h.persist(rules)
    assert _status("4.1.11") == "pass"


# ---- Fixer round trip ----

@pytest.mark.parametrize("cid", _CONTROL_IDS)
def test_fix_satisfies_check(monkeypatch, tmp_path, cid):
    h = _Host(monkeypatch, tmp_path)
    monkeypatch.setattr(audit_rules, "_rules_path_for", lambda c: str(h.rules_d / f"80-lss-{c}.rules"))
    monkeypatch.setattr(audit_rules.journal, "backup_file", lambda p: None)
    get_control(cid).fix()
    h.loaded = "\n".join(" ".join(a) for a in h.added) + "\n"
    assert _status(cid) == "pass"


def test_fix_writes_rule_present_only_as_comment(monkeypatch, tmp_path):
    h = _Host(monkeypatch, tmp_path)
    own = h.rules_d / "80-lss-4.1.12.rules"
    monkeypatch.setattr(audit_rules, "_rules_path_for", lambda c: str(own))
    monkeypatch.setattr(audit_rules.journal, "backup_file", lambda p: None)
    own.write_text("# LSS audit rules\n" + "".join(f"# {r}\n" for r in _RULES_BY_ID["4.1.12"]))
    get_control("4.1.12").fix()
    lines = own.read_text().splitlines()
    assert all(r in lines for r in _RULES_BY_ID["4.1.12"])
    h.loaded = "\n".join(_RULES_BY_ID["4.1.12"]) + "\n"
    assert _status("4.1.12") == "pass"
