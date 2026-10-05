# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file, 
# via any medium, is strictly prohibited without explicit written authorization.

"""CIS Section 3.5 — Firewall configuration (iptables / nftables)."""

from __future__ import annotations

import ipaddress
import re
import subprocess
from pathlib import Path

from lss.lib import distro, journal, pkg
from lss.lib.registry import Control, CheckResult, RollbackEntry, register
from lss.lib.sysctl import ipv6_disabled

IPTABLES_V4_RULES = "/etc/iptables/rules.v4"
IPTABLES_V6_RULES = "/etc/iptables/rules.v6"
SYSCONFIG_IPTABLES = "/etc/sysconfig/iptables"
NFTABLES_CONF = "/etc/nftables.conf"
UFW_CONF = "/etc/ufw/ufw.conf"


def _persist_ip6tables_v6() -> None:
    out_dir = Path(IPTABLES_V6_RULES).parent
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return
    try:
        r = subprocess.run(["ip6tables-save"], capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return
    if r.returncode != 0:
        return
    Path(IPTABLES_V6_RULES).write_text(r.stdout)


def _cmd_exists(name: str) -> bool:
    try:
        r = subprocess.run(["which", name], capture_output=True, text=True)
    except FileNotFoundError:
        return False
    return r.returncode == 0


def _iptables_rules() -> str:
    try:
        r = subprocess.run(["iptables", "-S"], capture_output=True, text=True)
    except FileNotFoundError:
        return ""
    return r.stdout if r.returncode == 0 else ""


def _persist_iptables_v4() -> None:
    """Save current in-memory iptables rules to /etc/iptables/rules.v4 so they
    survive reboot. Creates the directory if needed. Silent no-op if the
    iptables-save tool isn't available (the runtime change still applies)."""
    out_dir = Path(IPTABLES_V4_RULES).parent
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return
    try:
        r = subprocess.run(["iptables-save"], capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return
    if r.returncode != 0:
        return
    Path(IPTABLES_V4_RULES).write_text(r.stdout)


def _ip6tables_rules() -> str:
    try:
        r = subprocess.run(["ip6tables", "-S"], capture_output=True, text=True)
    except FileNotFoundError:
        return ""
    return r.stdout if r.returncode == 0 else ""


def _nft_ruleset() -> str:
    try:
        r = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True)
    except FileNotFoundError:
        return ""
    return r.stdout if r.returncode == 0 else ""


# ---- CIS 3.5.1.1: Ensure iptables is installed ----

def _check_iptables_installed() -> CheckResult:
    if _cmd_exists("iptables"):
        return CheckResult("pass")
    return CheckResult("fail", "iptables not installed")


register(Control(
    id="3.5.1.1",
    title="Ensure iptables is installed",
    section="network",
    check=_check_iptables_installed,
    fix=lambda: pkg.install("iptables"),
))


# ---- CIS 3.5.1.2: Ensure nftables is installed ----

def _check_nftables_installed() -> CheckResult:
    if _cmd_exists("nft"):
        return CheckResult("pass")
    return CheckResult("fail", "nftables not installed")


register(Control(
    id="3.5.1.2",
    title="Ensure nftables is installed",
    section="network",
    check=_check_nftables_installed,
    fix=lambda: pkg.install("nftables"),
))


# ---- CIS 3.5.2.1: Ensure iptables default deny firewall policy ----

def _check_iptables_default_deny() -> CheckResult:
    if not _cmd_exists("iptables"):
        return CheckResult("warn", "iptables not available")
    rules = _iptables_rules()
    # Check for default DROP or REJECT on INPUT, FORWARD, OUTPUT
    has_input_drop = "-P INPUT DROP" in rules or "-P INPUT REJECT" in rules
    has_forward_drop = "-P FORWARD DROP" in rules or "-P FORWARD REJECT" in rules
    if has_input_drop and has_forward_drop:
        return CheckResult("pass")
    issues = []
    if not has_input_drop:
        issues.append("INPUT not DROP/REJECT")
    if not has_forward_drop:
        issues.append("FORWARD not DROP/REJECT")
    # MANUAL (LSS safety): a default-deny policy is correct, but auto-applying
    # it sets INPUT to DROP before the allow-rules (loopback, ESTABLISHED, SSH)
    # exist — which severs the operator's own SSH session: an instant, no-warning
    # remote lockout. Apply by hand, ensuring these run FIRST:
    #   iptables -A INPUT -i lo -j ACCEPT
    #   iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    #   iptables -A INPUT -p tcp --dport 22 -j ACCEPT      # or your SSH port
    #   iptables -P INPUT DROP                             # only after the above
    return CheckResult(
        "manual",
        f"{'; '.join(issues)} — set default-deny by hand AFTER allowing loopback + "
        "ESTABLISHED,RELATED + SSH, or you will lock yourself out remotely",
    )


def _fix_iptables_default_deny() -> list[RollbackEntry]:
    entries = []
    rules_backup = journal.backup_file(IPTABLES_V4_RULES)
    for chain in ["INPUT", "FORWARD"]:
        subprocess.run(["iptables", "-P", chain, "DROP"], capture_output=True)
        entries.append(RollbackEntry(
            action=f"set iptables {chain} policy to DROP",
            undo=[["iptables", "-P", chain, "ACCEPT"]],
        ))
    _persist_iptables_v4()
    # Record the persisted-rules file so rollback restores it (and re-saves
    # after the runtime undos have been replayed).
    entries.append(RollbackEntry(
        action=f"persisted iptables rules to {IPTABLES_V4_RULES}",
        path=IPTABLES_V4_RULES,
        backup=rules_backup,
        undo=[] if rules_backup else [["rm", "-f", IPTABLES_V4_RULES]],
    ))
    return entries


register(Control(
    id="3.5.2.1",
    title="Ensure iptables default deny firewall policy",
    section="network",
    check=_check_iptables_default_deny,
    fix=None,  # DEFANGED: auto-applying default-deny before allow-rules = remote lockout (see check). Re-enable only with an allow-SSH-first fix verified on a real host.
))


# ---- CIS 3.5.2.2: Ensure iptables loopback traffic is configured ----

def _input_reachable_chains(rules: str) -> set[str]:
    """Collect chain names that INPUT jumps to (directly or transitively).

    UFW (and similar wrappers) split rules across chains like ufw-before-input,
    so the loopback ACCEPT may not live literally on INPUT.
    """
    jumps: dict[str, set[str]] = {}
    for line in rules.splitlines():
        toks = line.split()
        if len(toks) < 4 or toks[0] != "-A":
            continue
        chain = toks[1]
        if "-j" in toks:
            i = toks.index("-j")
            if i + 1 < len(toks):
                jumps.setdefault(chain, set()).add(toks[i + 1])
        if "-g" in toks:
            i = toks.index("-g")
            if i + 1 < len(toks):
                jumps.setdefault(chain, set()).add(toks[i + 1])
    reachable: set[str] = {"INPUT"}
    stack = ["INPUT"]
    while stack:
        c = stack.pop()
        for tgt in jumps.get(c, ()):
            if tgt in reachable:
                continue
            if tgt in {"ACCEPT", "DROP", "REJECT", "RETURN", "LOG", "QUEUE"}:
                continue
            reachable.add(tgt)
            stack.append(tgt)
    return reachable


def _accepts_established(rules: str) -> bool:
    """True if a chain reachable from INPUT ACCEPTs ESTABLISHED connections.

    Token matches throughout: the state list after `--ctstate` / `--state`
    must name ESTABLISHED (and not be negated with `!`), and the rule must jump
    to exactly ACCEPT. The old line test — `startswith("-A INPUT")` plus
    "ESTABLISHED" and "ACCEPT" anywhere — passed on a jump to a custom chain
    such as `-j ACCEPT_LOG` and on any chain whose name merely starts with
    INPUT, while failing the ufw layout, where the rule lives in
    ufw-before-input and INPUT jumps to it.
    """
    reachable = _input_reachable_chains(rules)
    for line in rules.splitlines():
        toks = line.split()
        if len(toks) < 2 or toks[0] != "-A" or toks[1] not in reachable:
            continue
        states: list[str] = []
        for flag in ("--ctstate", "--state"):
            if flag in toks:
                i = toks.index(flag)
                if i + 1 < len(toks) and toks[i - 1] != "!":
                    states.extend(toks[i + 1].split(","))
        if "ESTABLISHED" not in states or "-j" not in toks:
            continue
        i = toks.index("-j")
        if i + 1 < len(toks) and toks[i + 1] == "ACCEPT":
            return True
    return False


def _check_iptables_loopback() -> CheckResult:
    if not _cmd_exists("iptables"):
        return CheckResult("warn", "iptables not available")
    rules = _iptables_rules()
    import re
    reachable = _input_reachable_chains(rules)
    pat = re.compile(r"^-A (\S+) -i lo -j ACCEPT\s*$", re.MULTILINE)
    for m in pat.finditer(rules):
        if m.group(1) in reachable:
            return CheckResult("pass")
    return CheckResult("fail", "loopback INPUT ACCEPT rule not found")


def _fix_iptables_loopback() -> list[RollbackEntry]:
    entries = []
    rules_backup = journal.backup_file(IPTABLES_V4_RULES)

    subprocess.run(["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"], capture_output=True)
    entries.append(RollbackEntry(
        action="added iptables loopback INPUT ACCEPT",
        undo=[["iptables", "-D", "INPUT", "-i", "lo", "-j", "ACCEPT"]],
    ))
    subprocess.run(["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"], capture_output=True)
    entries.append(RollbackEntry(
        action="added iptables loopback OUTPUT ACCEPT",
        undo=[["iptables", "-D", "OUTPUT", "-o", "lo", "-j", "ACCEPT"]],
    ))
    subprocess.run(["iptables", "-A", "INPUT", "-s", "127.0.0.0/8", "-j", "DROP"], capture_output=True)
    entries.append(RollbackEntry(
        action="added iptables drop non-lo 127.0.0.0/8",
        undo=[["iptables", "-D", "INPUT", "-s", "127.0.0.0/8", "-j", "DROP"]],
    ))
    _persist_iptables_v4()
    entries.append(RollbackEntry(
        action=f"persisted iptables rules to {IPTABLES_V4_RULES}",
        path=IPTABLES_V4_RULES,
        backup=rules_backup,
        undo=[] if rules_backup else [["rm", "-f", IPTABLES_V4_RULES]],
    ))
    return entries


register(Control(
    id="3.5.2.2",
    title="Ensure iptables loopback traffic is configured",
    section="network",
    check=_check_iptables_loopback,
    fix=_fix_iptables_loopback,
))


# ---- CIS 3.5.2.3: Ensure iptables outbound and established connections are configured ----

def _check_iptables_established() -> CheckResult:
    if not _cmd_exists("iptables"):
        return CheckResult("warn", "iptables not available")
    # An ACCEPT rule for ESTABLISHED traffic on a chain reachable from INPUT,
    # not merely the word "ESTABLISHED" appearing anywhere (e.g. in a LOG rule
    # or a comment, or on an unrelated chain). See _accepts_established.
    if _accepts_established(_iptables_rules()):
        return CheckResult("pass")
    return CheckResult("fail", "no INPUT ACCEPT rule for ESTABLISHED connections found")


def _fix_iptables_established() -> list[RollbackEntry]:
    rules_backup = journal.backup_file(IPTABLES_V4_RULES)
    subprocess.run(
        ["iptables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        capture_output=True,
    )
    entries = [RollbackEntry(
        action="added iptables ESTABLISHED,RELATED ACCEPT on INPUT",
        undo=[["iptables", "-D", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"]],
    )]
    _persist_iptables_v4()
    entries.append(RollbackEntry(
        action=f"persisted iptables rules to {IPTABLES_V4_RULES}",
        path=IPTABLES_V4_RULES,
        backup=rules_backup,
        undo=[] if rules_backup else [["rm", "-f", IPTABLES_V4_RULES]],
    ))
    return entries


register(Control(
    id="3.5.2.3",
    title="Ensure iptables outbound and established connections are configured",
    section="network",
    check=_check_iptables_established,
    fix=_fix_iptables_established,
))


# ---- CIS 3.5.2.4: Ensure iptables firewall rules exist for all open ports ----

def _check_iptables_open_ports() -> CheckResult:
    if not _cmd_exists("iptables"):
        return CheckResult("warn", "iptables not available")
    # TCP and UDP listeners (CIS audits both). A failed or missing `ss`
    # prints nothing, which used to read as "no open ports" and pass.
    try:
        r = subprocess.run(["ss", "-H", "-tuln"], capture_output=True, text=True)
    except FileNotFoundError:
        return CheckResult("warn", "cannot enumerate listening ports (ss not available)")
    if r.returncode != 0:
        return CheckResult("warn", "cannot enumerate listening ports (ss failed)")
    listeners = set()
    for line in r.stdout.splitlines():
        parts = line.split()
        if not parts:
            continue
        # `ss -tuln` prints: Netid State Recv-Q Send-Q Local:Port Peer:Port
        if len(parts) < 5 or parts[0] not in ("tcp", "udp"):
            return CheckResult("warn", f"cannot parse ss output: {line.strip()[:80]}")
        host, _, port = parts[4].rpartition(":")
        # Loopback-only listeners are unreachable from the network; CIS skips
        # them too.
        if _is_loopback(host):
            continue
        listeners.add((port, parts[0]))

    # Only rules on chains reachable from INPUT govern inbound traffic. An
    # outbound rule such as `-A OUTPUT -p tcp --dport 22 -j ACCEPT` (for
    # ssh-ing out) used to mark a listening sshd as covered.
    all_rules = _iptables_rules()
    reachable = _input_reachable_chains(all_rules)
    inbound = []
    for line in all_rules.splitlines():
        toks = line.split()
        if len(toks) >= 2 and toks[0] == "-A" and toks[1] in reachable:
            inbound.append(line)
    rules = "\n".join(inbound)
    uncovered = []
    for port, proto in sorted(listeners):
        if not port.isdigit():
            continue
        # Match the port as a whole token in a --dport or --dports (multiport)
        # rule for the listener's own protocol. The old bare `port not in
        # rules` substring suppressed the warning whenever the digits appeared
        # ANYWHERE — e.g. inside an IP address or another port number.
        covered = any(
            re.search(rf"-p\s+{proto}\b", ln) and (
                re.search(rf"--dport\s+{port}\b", ln)
                or re.search(rf"--dports\s+\S*\b{port}\b", ln)
            )
            for ln in rules.splitlines()
        )
        if not covered:
            uncovered.append(f"{port}/{proto}")

    if not uncovered:
        return CheckResult("pass")
    return CheckResult("warn", f"ports without explicit rules: {','.join(uncovered[:10])}")


def _is_loopback(host: str) -> bool:
    """True if an `ss` local address (no port) is a loopback address."""
    host = host.strip("[]").split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False  # "*", "0.0.0.0" wildcards and anything unexpected
    if getattr(addr, "ipv4_mapped", None):
        addr = addr.ipv4_mapped
    return addr.is_loopback


register(Control(
    id="3.5.2.4",
    title="Ensure iptables firewall rules exist for all open ports",
    section="network",
    check=_check_iptables_open_ports,
    fix=None,  # Site-specific
))


# ---- CIS 3.5.3.1: Ensure ip6tables default deny firewall policy ----

def _check_ip6tables_default_deny() -> CheckResult:
    if not _cmd_exists("ip6tables"):
        return CheckResult("warn", "ip6tables not available")
    # If IPv6 is disabled, this is N/A
    if ipv6_disabled():
        return CheckResult("pass", "IPv6 is disabled")
    rules = _ip6tables_rules()
    has_input_drop = "-P INPUT DROP" in rules or "-P INPUT REJECT" in rules
    has_forward_drop = "-P FORWARD DROP" in rules or "-P FORWARD REJECT" in rules
    if has_input_drop and has_forward_drop:
        return CheckResult("pass")
    # Report "manual" (not "fail") so harden never auto-applies this — setting
    # INPUT/FORWARD to DROP before the loopback + ESTABLISHED + SSH allow-rules
    # (which sort after this control) severs an IPv6 SSH session mid-run. This
    # mirrors the IPv4 twin 3.5.2.1, which is intentionally defanged for the
    # exact same reason.
    return CheckResult(
        "manual",
        "ip6tables default policy is not DROP — set it by hand AFTER allowing "
        "loopback + ESTABLISHED,RELATED + SSH over IPv6, or you will lock "
        "yourself out remotely",
    )


def _fix_ip6tables_default_deny() -> list[RollbackEntry]:
    if ipv6_disabled():
        return []
    entries = []
    rules_backup = journal.backup_file(IPTABLES_V6_RULES)
    for chain in ["INPUT", "FORWARD"]:
        subprocess.run(["ip6tables", "-P", chain, "DROP"], capture_output=True)
        entries.append(RollbackEntry(
            action=f"set ip6tables {chain} policy to DROP",
            undo=[["ip6tables", "-P", chain, "ACCEPT"]],
        ))
    _persist_ip6tables_v6()
    entries.append(RollbackEntry(
        action=f"persisted ip6tables rules to {IPTABLES_V6_RULES}",
        path=IPTABLES_V6_RULES,
        backup=rules_backup,
        undo=[] if rules_backup else [["rm", "-f", IPTABLES_V6_RULES]],
    ))
    return entries


register(Control(
    id="3.5.3.1",
    title="Ensure ip6tables default deny firewall policy",
    section="network",
    check=_check_ip6tables_default_deny,
    fix=None,  # DEFANGED: auto-applying default-deny before the IPv6 allow-rules = remote lockout over IPv6 SSH (see check, and the IPv4 twin 3.5.2.1). Re-enable only with an allow-SSH-first fix verified on a real host.
))


# ---- CIS 3.5.3.2: Ensure ip6tables loopback traffic is configured ----

def _check_ip6tables_loopback() -> CheckResult:
    if not _cmd_exists("ip6tables"):
        return CheckResult("warn", "ip6tables not available")
    if ipv6_disabled():
        return CheckResult("pass", "IPv6 is disabled")
    rules = _ip6tables_rules()
    # Mirror the IPv4 sibling: a whole-line `-i lo -j ACCEPT` rule on a chain
    # reachable from INPUT. The old substring test also matched the prefix of
    # a jump to a custom chain (`-j ACCEPT_LOG`) and missed a loopback rule in
    # a chain INPUT jumps to (the ufw layout).
    reachable = _input_reachable_chains(rules)
    for m in re.finditer(r"^-A (\S+) -i lo -j ACCEPT\s*$", rules, re.MULTILINE):
        if m.group(1) in reachable:
            return CheckResult("pass")
    return CheckResult("fail", "ip6tables loopback INPUT ACCEPT not found")


def _fix_ip6tables_loopback() -> list[RollbackEntry]:
    if ipv6_disabled():
        return []
    entries = []
    rules_backup = journal.backup_file(IPTABLES_V6_RULES)
    subprocess.run(["ip6tables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"], capture_output=True)
    entries.append(RollbackEntry(
        action="added ip6tables loopback INPUT ACCEPT",
        undo=[["ip6tables", "-D", "INPUT", "-i", "lo", "-j", "ACCEPT"]],
    ))
    subprocess.run(["ip6tables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"], capture_output=True)
    entries.append(RollbackEntry(
        action="added ip6tables loopback OUTPUT ACCEPT",
        undo=[["ip6tables", "-D", "OUTPUT", "-o", "lo", "-j", "ACCEPT"]],
    ))
    subprocess.run(["ip6tables", "-A", "INPUT", "-s", "::1", "-j", "DROP"], capture_output=True)
    entries.append(RollbackEntry(
        action="added ip6tables drop non-lo ::1",
        undo=[["ip6tables", "-D", "INPUT", "-s", "::1", "-j", "DROP"]],
    ))
    _persist_ip6tables_v6()
    entries.append(RollbackEntry(
        action=f"persisted ip6tables rules to {IPTABLES_V6_RULES}",
        path=IPTABLES_V6_RULES,
        backup=rules_backup,
        undo=[] if rules_backup else [["rm", "-f", IPTABLES_V6_RULES]],
    ))
    return entries


register(Control(
    id="3.5.3.2",
    title="Ensure ip6tables loopback traffic is configured",
    section="network",
    check=_check_ip6tables_loopback,
    fix=_fix_ip6tables_loopback,
))


# ---- CIS 3.5.3.3: Ensure ip6tables outbound and established are configured ----

def _check_ip6tables_established() -> CheckResult:
    if not _cmd_exists("ip6tables"):
        return CheckResult("warn", "ip6tables not available")
    if ipv6_disabled():
        return CheckResult("pass", "IPv6 is disabled")
    # Same test as the IPv4 sibling: see _accepts_established.
    if _accepts_established(_ip6tables_rules()):
        return CheckResult("pass")
    return CheckResult("fail", "no INPUT ACCEPT rule for ESTABLISHED connections found")


def _fix_ip6tables_established() -> list[RollbackEntry]:
    if ipv6_disabled():
        return []
    rules_backup = journal.backup_file(IPTABLES_V6_RULES)
    subprocess.run(
        ["ip6tables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        capture_output=True,
    )
    entries = [RollbackEntry(
        action="added ip6tables ESTABLISHED,RELATED ACCEPT on INPUT",
        undo=[["ip6tables", "-D", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"]],
    )]
    _persist_ip6tables_v6()
    entries.append(RollbackEntry(
        action=f"persisted ip6tables rules to {IPTABLES_V6_RULES}",
        path=IPTABLES_V6_RULES,
        backup=rules_backup,
        undo=[] if rules_backup else [["rm", "-f", IPTABLES_V6_RULES]],
    ))
    return entries


register(Control(
    id="3.5.3.3",
    title="Ensure ip6tables outbound and established connections are configured",
    section="network",
    check=_check_ip6tables_established,
    fix=_fix_ip6tables_established,
))


# ---- CIS 3.5.4: Ensure iptables rules are saved ----

def _service_enabled(unit: str) -> bool:
    """True only if systemd reports `unit` enabled (started at boot)."""
    try:
        r = subprocess.run(["systemctl", "is-enabled", unit], capture_output=True, text=True)
    except FileNotFoundError:
        return False
    return r.returncode == 0 and r.stdout.strip() == "enabled"


def _ufw_enabled() -> bool:
    """ufw restores its rules at boot only with ENABLED=yes in ufw.conf
    (ufw.service is enabled by default even while ufw itself is off)."""
    try:
        text = Path(UFW_CONF).read_text()
    except OSError:
        return False
    return (
        re.search(r"^\s*ENABLED\s*=\s*\"?yes\"?\s*$", text, re.MULTILINE) is not None
        and _service_enabled("ufw")
    )


def _check_iptables_persistent() -> CheckResult:
    # A saved rules file only matters if something loads it at boot. The old
    # check passed on /etc/iptables/rules.v4 alone (which `iptables-save >`
    # creates with no loader installed), and its dpkg-query test lacked
    # -f=${Status}, so it could never match.
    loaders = (
        (IPTABLES_V4_RULES, "netfilter-persistent"),
        (SYSCONFIG_IPTABLES, "iptables"),
        (NFTABLES_CONF, "nftables"),
    )
    for path, unit in loaders:
        if Path(path).exists() and _service_enabled(unit):
            return CheckResult("pass", f"{path} loaded at boot by {unit}.service")
    if _ufw_enabled():
        return CheckResult("pass", "ufw is enabled and restores its rules at boot")
    if _service_enabled("firewalld"):
        return CheckResult("pass", "firewalld is enabled and restores its rules at boot")
    return CheckResult(
        "warn",
        "no firewall rules are loaded at boot (no saved ruleset with an enabled "
        "netfilter-persistent / iptables / nftables service, and ufw / firewalld "
        "not enabled) — rules will not survive reboot",
    )


def _fix_iptables_persistent() -> list[RollbackEntry]:
    """Save current iptables (and ip6tables if IPv6 enabled) rules to disk.

    Creates /etc/iptables/rules.v4 (and .v6) via iptables-save. Rollback
    removes the files we created and restores any prior content from backup.
    """
    if not _cmd_exists("iptables-save"):
        raise RuntimeError("iptables-save not installed")
    if not distro.is_debian_family():
        raise RuntimeError(
            "saving rules needs a boot-time loader; on this distro install and "
            "enable iptables-services (or use firewalld/nftables) by hand"
        )
    entries = []
    # The saved files do nothing at boot without a loader: install
    # netfilter-persistent (Debian's iptables-persistent) before saving, so
    # its postinst cannot overwrite the rules saved below.
    if not pkg.is_installed("iptables-persistent"):
        entries.extend(pkg.install("iptables-persistent"))
    rules_backup_v4 = journal.backup_file(IPTABLES_V4_RULES)
    _persist_iptables_v4()
    entries.append(RollbackEntry(
        action=f"persisted iptables rules to {IPTABLES_V4_RULES}",
        path=IPTABLES_V4_RULES,
        backup=rules_backup_v4,
        undo=[] if rules_backup_v4 else [["rm", "-f", IPTABLES_V4_RULES]],
    ))
    if not ipv6_disabled() and _cmd_exists("ip6tables-save"):
        rules_backup_v6 = journal.backup_file(IPTABLES_V6_RULES)
        _persist_ip6tables_v6()
        entries.append(RollbackEntry(
            action=f"persisted ip6tables rules to {IPTABLES_V6_RULES}",
            path=IPTABLES_V6_RULES,
            backup=rules_backup_v6,
            undo=[] if rules_backup_v6 else [["rm", "-f", IPTABLES_V6_RULES]],
        ))
    if not _service_enabled("netfilter-persistent"):
        r = subprocess.run(
            ["systemctl", "enable", "netfilter-persistent"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            raise RuntimeError(
                "systemctl enable netfilter-persistent failed: "
                f"{r.stderr.strip() or r.stdout.strip()}"
            )
        entries.append(RollbackEntry(
            action="enabled netfilter-persistent.service to load saved rules at boot",
            undo=[["systemctl", "disable", "netfilter-persistent"]],
        ))
    return entries


register(Control(
    id="3.5.4",
    title="Ensure iptables rules are saved",
    section="network",
    check=_check_iptables_persistent,
    fix=_fix_iptables_persistent,
))


# ---- CIS 3.5.5: Ensure unused network interfaces are disabled ----

def _check_unused_interfaces() -> CheckResult:
    try:
        r = subprocess.run(["ip", "-o", "link", "show", "up"], capture_output=True, text=True)
    except FileNotFoundError:
        return CheckResult("warn", "cannot enumerate interfaces (ip not available)")
    # A failed `ip` prints nothing, which used to read as "0 interface(s) up"
    # and pass.
    if r.returncode != 0:
        return CheckResult("warn", "cannot enumerate interfaces (ip link show failed)")
    up_interfaces = []
    for line in r.stdout.splitlines():
        parts = line.split(":")
        if len(parts) >= 2:
            name = parts[1].strip().split("@")[0]
            if name not in ("lo",):
                up_interfaces.append(name)
    # Just report — can't auto-determine which are "unused"
    if len(up_interfaces) <= 2:
        return CheckResult("pass", f"{len(up_interfaces)} interface(s) up")
    return CheckResult("warn", f"{len(up_interfaces)} interfaces up: {', '.join(up_interfaces)} — review for unused")


register(Control(
    id="3.5.5",
    title="Ensure unused network interfaces are disabled",
    section="network",
    check=_check_unused_interfaces,
    fix=None,  # Requires human review
))


# ---- CIS 3.6: Ensure wireless interfaces are disabled ----

_SYS_CLASS_NET = "/sys/class/net"

# `N: name[@parent]: <FLAG,FLAG,...> ...` — one header line per interface in
# `ip link show`; continuation lines (link/ether, altname) are indented.
_IP_LINK_HEADER = re.compile(r"^\d+:\s+([^:@\s]+)(?:@\S+)?:\s+<([^>]*)>")


def _is_wireless_iface(name: str) -> bool:
    """True if `name` is an 802.11 interface, whatever it is called.

    sysfs is authoritative when present: every 802.11 device exposes a
    `phy80211` (or legacy `wireless`) entry — the test CIS's own audit uses.
    Without sysfs, fall back to the name: systemd names every WLAN interface
    `wl*` (wlp, wlo, wls, and wlx — the default for USB adapters) and the
    legacy kernel name is wlan*. The old `"wlan" in line or "wlp" in line`
    test missed wlx/wlo/wls, so an up USB Wi-Fi adapter passed this control.
    """
    base = Path(_SYS_CLASS_NET) / name
    try:
        if base.exists():
            return (base / "phy80211").exists() or (base / "wireless").exists()
    except OSError:
        pass
    return name.startswith("wl")


def _check_wireless_disabled() -> CheckResult:
    try:
        r = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
    except FileNotFoundError:
        return CheckResult("warn", "cannot enumerate interfaces (ip not available)")
    # A failed `ip link show` prints nothing, which used to read as "no
    # wireless interfaces" and pass.
    if r.returncode != 0:
        return CheckResult("warn", "cannot enumerate interfaces (ip link show failed)")
    wireless = []
    for line in r.stdout.splitlines():
        m = _IP_LINK_HEADER.match(line)
        if not m:
            continue
        name, flags = m.group(1), m.group(2).split(",")
        if "UP" in flags and _is_wireless_iface(name):
            wireless.append(name)
    if not wireless:
        return CheckResult("pass")
    return CheckResult("warn", f"wireless interfaces up: {', '.join(wireless)}")


register(Control(
    id="3.6",
    title="Ensure wireless interfaces are disabled",
    section="network",
    check=_check_wireless_disabled,
    fix=None,
))