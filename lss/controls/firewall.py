"""CIS Section 3.5 — Firewall configuration (iptables / nftables)."""

from __future__ import annotations

import subprocess
from pathlib import Path

from lss.lib import journal
from lss.lib.registry import Control, CheckResult, RollbackEntry, register

IPTABLES_V4_RULES = "/etc/iptables/rules.v4"


def _cmd_exists(name: str) -> bool:
    r = subprocess.run(["which", name], capture_output=True, text=True)
    return r.returncode == 0


def _iptables_rules() -> str:
    r = subprocess.run(["iptables", "-S"], capture_output=True, text=True)
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
    r = subprocess.run(["ip6tables", "-S"], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else ""


def _nft_ruleset() -> str:
    r = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True)
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
    fix=None,  # Package install
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
    fix=None,
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
    return CheckResult("fail", "; ".join(issues))


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
    fix=_fix_iptables_default_deny,
))


# ---- CIS 3.5.2.2: Ensure iptables loopback traffic is configured ----

def _check_iptables_loopback() -> CheckResult:
    if not _cmd_exists("iptables"):
        return CheckResult("warn", "iptables not available")
    rules = _iptables_rules()
    has_lo_accept = "-A INPUT -i lo -j ACCEPT" in rules
    has_lo_deny = ("-A INPUT -s 127.0.0.0/8" in rules and
                   ("DROP" in rules or "REJECT" in rules))
    if has_lo_accept:
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
    if "ESTABLISHED" in rules:
        return CheckResult("pass")
    return CheckResult("fail", "no ESTABLISHED connection rule found")


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
    r = subprocess.run(["ss", "-H", "-tlnp"], capture_output=True, text=True)
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
        if port not in rules and f"--dport {port}" not in rules:
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
    r = subprocess.run(["sysctl", "-n", "net.ipv6.conf.all.disable_ipv6"], capture_output=True, text=True)
    if r.stdout.strip() == "1":
        return CheckResult("pass", "IPv6 is disabled")
    rules = _ip6tables_rules()
    has_input_drop = "-P INPUT DROP" in rules or "-P INPUT REJECT" in rules
    has_forward_drop = "-P FORWARD DROP" in rules or "-P FORWARD REJECT" in rules
    if has_input_drop and has_forward_drop:
        return CheckResult("pass")
    return CheckResult("fail", "ip6tables default policy is not DROP")


register(Control(
    id="3.5.3.1",
    title="Ensure ip6tables default deny firewall policy",
    section="network",
    check=_check_ip6tables_default_deny,
    fix=None,  # Mirroring IPv4 fix is risky without context
))


# ---- CIS 3.5.3.2: Ensure ip6tables loopback traffic is configured ----

def _check_ip6tables_loopback() -> CheckResult:
    if not _cmd_exists("ip6tables"):
        return CheckResult("warn", "ip6tables not available")
    r = subprocess.run(["sysctl", "-n", "net.ipv6.conf.all.disable_ipv6"], capture_output=True, text=True)
    if r.stdout.strip() == "1":
        return CheckResult("pass", "IPv6 is disabled")
    rules = _ip6tables_rules()
    if "-A INPUT -i lo -j ACCEPT" in rules:
        return CheckResult("pass")
    return CheckResult("fail", "ip6tables loopback INPUT ACCEPT not found")


register(Control(
    id="3.5.3.2",
    title="Ensure ip6tables loopback traffic is configured",
    section="network",
    check=_check_ip6tables_loopback,
    fix=None,
))


# ---- CIS 3.5.3.3: Ensure ip6tables outbound and established are configured ----

def _check_ip6tables_established() -> CheckResult:
    if not _cmd_exists("ip6tables"):
        return CheckResult("warn", "ip6tables not available")
    r = subprocess.run(["sysctl", "-n", "net.ipv6.conf.all.disable_ipv6"], capture_output=True, text=True)
    if r.stdout.strip() == "1":
        return CheckResult("pass", "IPv6 is disabled")
    rules = _ip6tables_rules()
    if "ESTABLISHED" in rules:
        return CheckResult("pass")
    return CheckResult("fail", "no ESTABLISHED rule in ip6tables")


register(Control(
    id="3.5.3.3",
    title="Ensure ip6tables outbound and established connections are configured",
    section="network",
    check=_check_ip6tables_established,
    fix=None,
))


# ---- CIS 3.5.4: Ensure iptables rules are saved ----

def _check_iptables_persistent() -> CheckResult:
    # Check for iptables-persistent or saved rules
    for path in ["/etc/iptables/rules.v4", "/etc/sysconfig/iptables"]:
        if Path(path).exists():
            return CheckResult("pass")
    # Check if iptables-persistent is installed
    r = subprocess.run(["dpkg-query", "-W", "iptables-persistent"], capture_output=True, text=True)
    if r.returncode == 0 and "install ok installed" in r.stdout:
        return CheckResult("pass")
    r2 = subprocess.run(["rpm", "-q", "iptables-services"], capture_output=True, text=True)
    if r2.returncode == 0:
        return CheckResult("pass")
    return CheckResult("warn", "no persistent iptables rules found — rules may not survive reboot")


register(Control(
    id="3.5.4",
    title="Ensure iptables rules are saved",
    section="network",
    check=_check_iptables_persistent,
    fix=None,  # Requires iptables-persistent or manual save
))


# ---- CIS 3.5.5: Ensure unused network interfaces are disabled ----

def _check_unused_interfaces() -> CheckResult:
    r = subprocess.run(["ip", "-o", "link", "show", "up"], capture_output=True, text=True)
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
    r = subprocess.run(["ip", "link", "show"], capture_output=True, text=True)
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