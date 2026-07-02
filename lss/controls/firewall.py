"""CIS Section 3.5 — Firewall configuration (iptables / nftables)."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from lss.lib import journal, pkg
from lss.lib.registry import Control, CheckResult, RollbackEntry, register

IPTABLES_V4_RULES = "/etc/iptables/rules.v4"
IPTABLES_V6_RULES = "/etc/iptables/rules.v6"


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


def _ipv6_disabled() -> bool:
    """True only if we can confirm IPv6 is disabled. If sysctl is absent we
    cannot confirm, so return False (never assume disabled → never false-pass)."""
    try:
        r = subprocess.run(
            ["sysctl", "-n", "net.ipv6.conf.all.disable_ipv6"],
            capture_output=True, text=True,
        )
    except FileNotFoundError:
        return False
    return r.stdout.strip() == "1"


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
    rules = _iptables_rules()
    # Require an actual INPUT ACCEPT rule for ESTABLISHED traffic, not merely
    # the word "ESTABLISHED" appearing anywhere (e.g. in a LOG rule or a
    # comment, or on an unrelated chain).
    for line in rules.splitlines():
        if line.startswith("-A INPUT") and "ESTABLISHED" in line and "ACCEPT" in line:
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
    # Get listening ports
    try:
        r = subprocess.run(["ss", "-H", "-tlnp"], capture_output=True, text=True)
    except FileNotFoundError:
        return CheckResult("warn", "cannot enumerate listening ports (ss not available)")
    listeners = set()
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            addr_port = parts[3]
            port = addr_port.rsplit(":", 1)[-1]
            listeners.add(port)

    rules = _iptables_rules()
    uncovered = []
    for port in sorted(listeners):
        if not port.isdigit():
            continue
        # Match the port as a whole token in a --dport or --dports (multiport)
        # rule. The old bare `port not in rules` substring suppressed the
        # warning whenever the digits appeared ANYWHERE — e.g. inside an IP
        # address or another port number — hiding genuinely uncovered ports.
        covered = (
            re.search(rf"--dport\s+{port}\b", rules)
            or re.search(rf"--dports\s+\S*\b{port}\b", rules)
        )
        if not covered:
            uncovered.append(port)

    if not uncovered:
        return CheckResult("pass")
    return CheckResult("warn", f"ports without explicit rules: {','.join(uncovered[:10])}")


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
    if _ipv6_disabled():
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
    r = subprocess.run(["sysctl", "-n", "net.ipv6.conf.all.disable_ipv6"], capture_output=True, text=True)
    if r.stdout.strip() == "1":
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
    if _ipv6_disabled():
        return CheckResult("pass", "IPv6 is disabled")
    rules = _ip6tables_rules()
    if "-A INPUT -i lo -j ACCEPT" in rules:
        return CheckResult("pass")
    return CheckResult("fail", "ip6tables loopback INPUT ACCEPT not found")


def _fix_ip6tables_loopback() -> list[RollbackEntry]:
    r = subprocess.run(["sysctl", "-n", "net.ipv6.conf.all.disable_ipv6"], capture_output=True, text=True)
    if r.stdout.strip() == "1":
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
    if _ipv6_disabled():
        return CheckResult("pass", "IPv6 is disabled")
    rules = _ip6tables_rules()
    if "ESTABLISHED" in rules:
        return CheckResult("pass")
    return CheckResult("fail", "no ESTABLISHED rule in ip6tables")


def _fix_ip6tables_established() -> list[RollbackEntry]:
    r = subprocess.run(["sysctl", "-n", "net.ipv6.conf.all.disable_ipv6"], capture_output=True, text=True)
    if r.stdout.strip() == "1":
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

def _check_iptables_persistent() -> CheckResult:
    # Check for iptables-persistent or saved rules
    for path in ["/etc/iptables/rules.v4", "/etc/sysconfig/iptables"]:
        if Path(path).exists():
            return CheckResult("pass")
    # Check if iptables-persistent is installed
    try:
        r = subprocess.run(["dpkg-query", "-W", "iptables-persistent"], capture_output=True, text=True)
        if r.returncode == 0 and "install ok installed" in r.stdout:
            return CheckResult("pass")
    except FileNotFoundError:
        pass
    try:
        r2 = subprocess.run(["rpm", "-q", "iptables-services"], capture_output=True, text=True)
        if r2.returncode == 0:
            return CheckResult("pass")
    except FileNotFoundError:
        pass
    return CheckResult("warn", "no persistent iptables rules found — rules may not survive reboot")


def _fix_iptables_persistent() -> list[RollbackEntry]:
    """Save current iptables (and ip6tables if IPv6 enabled) rules to disk.

    Creates /etc/iptables/rules.v4 (and .v6) via iptables-save. Rollback
    removes the files we created and restores any prior content from backup.
    """
    if not _cmd_exists("iptables-save"):
        raise RuntimeError("iptables-save not installed")
    entries = []
    rules_backup_v4 = journal.backup_file(IPTABLES_V4_RULES)
    _persist_iptables_v4()
    entries.append(RollbackEntry(
        action=f"persisted iptables rules to {IPTABLES_V4_RULES}",
        path=IPTABLES_V4_RULES,
        backup=rules_backup_v4,
        undo=[] if rules_backup_v4 else [["rm", "-f", IPTABLES_V4_RULES]],
    ))
    r = subprocess.run(["sysctl", "-n", "net.ipv6.conf.all.disable_ipv6"], capture_output=True, text=True)
    if r.stdout.strip() != "1" and _cmd_exists("ip6tables-save"):
        rules_backup_v6 = journal.backup_file(IPTABLES_V6_RULES)
        _persist_ip6tables_v6()
        entries.append(RollbackEntry(
            action=f"persisted ip6tables rules to {IPTABLES_V6_RULES}",
            path=IPTABLES_V6_RULES,
            backup=rules_backup_v6,
            undo=[] if rules_backup_v6 else [["rm", "-f", IPTABLES_V6_RULES]],
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

def _check_wireless_disabled() -> CheckResult:
    try:
        r = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
    except FileNotFoundError:
        return CheckResult("warn", "cannot enumerate interfaces (ip not available)")
    wireless = []
    for line in r.stdout.splitlines():
        if "wlan" in line or "wlp" in line:
            parts = line.split(":")
            if len(parts) >= 2:
                name = parts[1].strip()
                if "UP" in line:
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