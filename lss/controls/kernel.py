# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file, 
# via any medium, is strictly prohibited without explicit written authorization.

"""CIS Section 1.5 — Kernel hardening."""

import subprocess
from pathlib import Path

from lss.lib import journal, kmod
from lss.lib.registry import Control, CheckResult, RollbackEntry, register
from lss.lib.sysctl import get_sysctl as _get_sysctl, set_sysctl as _set_sysctl


# ---- CIS 1.5.1: Ensure ASLR is enabled (randomize_va_space = 2) ----

def _check_aslr() -> CheckResult:
    val = _get_sysctl("kernel.randomize_va_space")
    if val == "2":
        return CheckResult("pass")
    if val == "1":
        return CheckResult("warn", f"randomize_va_space={val}, recommended: 2")
    return CheckResult("fail", f"randomize_va_space={val}")


def _fix_aslr() -> list[RollbackEntry]:
    return [_set_sysctl("kernel.randomize_va_space", "2")]


register(Control(
    id="1.5.1",
    title="Ensure address space layout randomization (ASLR) is enabled",
    section="kernel",
    check=_check_aslr,
    fix=_fix_aslr,
))


# ---- CIS 1.5.2: Ensure ptrace_scope is restricted ----

def _check_ptrace() -> CheckResult:
    val = _get_sysctl("kernel.yama.ptrace_scope")
    if val is None:
        return CheckResult("warn", "yama module not loaded")
    try:
        n = int(val)
    except ValueError:
        return CheckResult("fail", f"ptrace_scope={val}")
    if n >= 1:
        return CheckResult("pass")
    return CheckResult("fail", f"ptrace_scope={n}, recommended: ≥ 1")


def _fix_ptrace() -> list[RollbackEntry]:
    return [_set_sysctl("kernel.yama.ptrace_scope", "1")]


register(Control(
    id="1.5.2",
    title="Ensure ptrace_scope is restricted",
    section="kernel",
    check=_check_ptrace,
    fix=_fix_ptrace,
))


# ---- CIS 1.5.3: Ensure unprivileged users cannot read dmesg ----

def _check_dmesg_restrict() -> CheckResult:
    val = _get_sysctl("kernel.dmesg_restrict")
    if val == "1":
        return CheckResult("pass")
    return CheckResult("fail", f"dmesg_restrict={val}, recommended: 1")


def _fix_dmesg_restrict() -> list[RollbackEntry]:
    return [_set_sysctl("kernel.dmesg_restrict", "1")]


register(Control(
    id="1.5.3",
    title="Ensure access to dmesg is restricted",
    section="kernel",
    check=_check_dmesg_restrict,
    fix=_fix_dmesg_restrict,
))


# ---- CIS 1.5.4: Ensure kernel pointer addresses are restricted ----

def _check_kptr_restrict() -> CheckResult:
    val = _get_sysctl("kernel.kptr_restrict")
    if val in ("1", "2"):
        return CheckResult("pass")
    return CheckResult("fail", f"kptr_restrict={val}, recommended: 1 or 2")


def _fix_kptr_restrict() -> list[RollbackEntry]:
    return [_set_sysctl("kernel.kptr_restrict", "2")]


register(Control(
    id="1.5.4",
    title="Ensure kernel pointer addresses are restricted",
    section="kernel",
    check=_check_kptr_restrict,
    fix=_fix_kptr_restrict,
))


# ---- CIS 1.5.5: Ensure unprivileged eBPF is disabled ----

def _check_unprivileged_bpf() -> CheckResult:
    val = _get_sysctl("kernel.unprivileged_bpf_disabled")
    if val == "1":
        return CheckResult("pass")
    if val is None:
        return CheckResult("warn", "sysctl key not available on this kernel")
    return CheckResult("fail", f"unprivileged_bpf_disabled={val}, recommended: 1")


def _fix_unprivileged_bpf() -> list[RollbackEntry]:
    return [_set_sysctl("kernel.unprivileged_bpf_disabled", "1")]


register(Control(
    id="1.5.5",
    title="Ensure unprivileged eBPF is disabled",
    section="kernel",
    check=_check_unprivileged_bpf,
    fix=_fix_unprivileged_bpf,
))


# ---- CIS 1.5.6: Ensure perf_event_paranoid is set to 3 or higher ----

def _check_perf_paranoid() -> CheckResult:
    val = _get_sysctl("kernel.perf_event_paranoid")
    if val is None:
        return CheckResult("warn", "sysctl key not available")
    try:
        n = int(val)
    except ValueError:
        return CheckResult("fail", f"perf_event_paranoid={val}")
    if n >= 3:
        return CheckResult("pass")
    return CheckResult("fail", f"perf_event_paranoid={n}, recommended: ≥ 3")


def _fix_perf_paranoid() -> list[RollbackEntry]:
    return [_set_sysctl("kernel.perf_event_paranoid", "3")]


register(Control(
    id="1.5.6",
    title="Ensure perf_event_paranoid is restrictive",
    section="kernel",
    check=_check_perf_paranoid,
    fix=_fix_perf_paranoid,
))


# ---- CIS 1.5.7: Ensure unprivileged user namespaces are restricted ----

def _check_user_namespaces() -> CheckResult:
    val = _get_sysctl("kernel.unprivileged_userns_clone")
    if val is None:
        # Some kernels use a different path
        val = _get_sysctl("user.max_user_namespaces")
        if val is not None and val == "0":
            return CheckResult("pass")
        return CheckResult("warn", "sysctl key not available — kernel may not support restriction")
    if val == "0":
        return CheckResult("pass")
    return CheckResult("fail", f"unprivileged_userns_clone={val}, recommended: 0")


def _fix_user_namespaces() -> list[RollbackEntry]:
    val = _get_sysctl("kernel.unprivileged_userns_clone")
    if val is not None:
        return [_set_sysctl("kernel.unprivileged_userns_clone", "0")]
    return [_set_sysctl("user.max_user_namespaces", "0")]


register(Control(
    id="1.5.7",
    title="Ensure unprivileged user namespaces are restricted",
    section="kernel",
    check=_check_user_namespaces,
    fix=_fix_user_namespaces,
))


# ---- CIS 3.4.1: Ensure DCCP is disabled ----
# ---- CIS 3.4.2: Ensure SCTP is disabled ----
# ---- CIS 3.4.3: Ensure RDS is disabled ----
# ---- CIS 3.4.4: Ensure TIPC is disabled ----

_DISABLED_NET_MODULES = [
    ("3.4.1", "dccp",  "Ensure DCCP is disabled"),
    ("3.4.2", "sctp",  "Ensure SCTP is disabled"),
    ("3.4.3", "rds",   "Ensure RDS is disabled"),
    ("3.4.4", "tipc",  "Ensure TIPC is disabled"),
]


for _id, _mod, _title in _DISABLED_NET_MODULES:
    mod = _mod

    def _make_check(m):
        def check():
            # Shared CIS "not available" test: install-nulled AND
            # blacklisted AND not loaded, or absent from the kernel tree.
            return kmod.check_disabled(m)
        return check

    def _make_fix(m):
        def fix():
            return kmod.disable_module(m)
        return fix

    register(Control(
        id=_id,
        title=_title,
        section="network",
        check=_make_check(mod),
        fix=_make_fix(mod),
    ))
