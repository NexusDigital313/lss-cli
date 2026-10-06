# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file, 
# via any medium, is strictly prohibited without explicit written authorization.

"""Extra CIS controls to reach 204 target — network, crypto, login."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from lss.lib import distro, journal
from lss.lib.registry import Control, CheckResult, RollbackEntry, register
from lss.lib.sysctl import ipv6_disabled

# Paths read by the checks below; module-level so tests can point them at tmp.
_CRYPTO_POLICY_CONF = Path("/etc/crypto-policies/config")
_CRYPTO_POLICY_STATE = Path("/etc/crypto-policies/state/current")
_OPENSSL_CNF = Path("/etc/ssl/openssl.cnf")
_SECURETTY = Path("/etc/securetty")
_PAM_D = Path("/etc/pam.d")
_SHADOW = Path("/etc/shadow")
_LOG_DIR = "/var/log"
_SHELL_RC_FILES = [Path("/etc/profile"), Path("/etc/bashrc"), Path("/etc/bash.bashrc")]
_PROFILE_D = Path("/etc/profile.d")
_PROC_CMDLINE = Path("/proc/cmdline")


def _parse_ini_sections(text: str) -> dict[str, dict[str, str]]:
    """Very small openssl.cnf/INI reader: {section_name: {key: value}}. The
    top (nameless) section — where `openssl_conf` must live — is keyed by ''.
    OpenSSL treats `#` as a comment anywhere on a line, so inline comments are
    stripped too."""
    sections: dict[str, dict[str, str]] = {"": {}}
    cur = ""
    for line in text.splitlines():
        s = line.split("#", 1)[0].strip()
        if not s or s.startswith(";"):
            continue
        m = re.match(r"\[\s*([^\]]+?)\s*\]", s)
        if m:
            cur = m.group(1)
            sections.setdefault(cur, {})
            continue
        if "=" in s:
            k, v = s.split("=", 1)
            sections[cur][k.strip()] = v.strip()
    return sections


def _openssl_min_protocol_effective(text: str) -> str | None:
    """Return the MinProtocol OpenSSL will actually apply, tracing the wiring
    openssl_conf -> ssl_conf -> system_default -> MinProtocol. None if the
    chain isn't wired (so a bare, unreferenced [system_default_sect] does NOT
    count as compliant — that was the false-pass)."""
    sec = _parse_ini_sections(text)
    init = sec.get("", {}).get("openssl_conf")
    if not init:
        return None
    ssl = sec.get(init, {}).get("ssl_conf")
    if not ssl:
        return None
    sysdef = sec.get(ssl, {}).get("system_default")
    if not sysdef:
        return None
    return sec.get(sysdef, {}).get("MinProtocol")


def _set_key_in_section(text: str, section: str, key: str, value: str) -> str:
    """Set `key = value` inside `[section]`, creating the section if absent."""
    lines = text.splitlines(keepends=True)
    header_re = re.compile(rf"^\s*\[\s*{re.escape(section)}\s*\]")
    any_header = re.compile(r"^\s*\[[^\]]+\]")
    key_re = re.compile(rf"^\s*{re.escape(key)}\s*=")
    in_sec = False
    for i, line in enumerate(lines):
        if header_re.match(line):
            in_sec = True
            continue
        if in_sec and any_header.match(line):
            lines.insert(i, f"{key} = {value}\n")
            return "".join(lines)
        if in_sec and key_re.match(line):
            lines[i] = f"{key} = {value}\n"
            return "".join(lines)
    if in_sec:
        lines.append(f"{key} = {value}\n")
        return "".join(lines)
    tail = "" if not text or text.endswith("\n") else "\n"
    return text + tail + f"\n[{section}]\n{key} = {value}\n"


# ---- LSS-001: Ensure system-wide crypto policy is not legacy ----
# Custom (non-CIS) check that knows about both RHEL crypto-policies and
# Debian's openssl MinProtocol.

def _crypto_policy_name(text: str) -> str:
    """The policy in a crypto-policies config/state file: the first line that
    is not blank or a comment, inline `#` comment removed. "" if none."""
    for line in text.splitlines():
        s = line.split("#", 1)[0].strip()
        if s:
            return s
    return ""


def _is_legacy_policy(name: str) -> bool:
    # Subpolicy modifiers keep the base policy: LEGACY:AD-SUPPORT is LEGACY.
    return name.split(":", 1)[0].strip().upper() == "LEGACY"


def _check_crypto_policy() -> CheckResult:
    # RHEL family: /etc/crypto-policies/config is the source of truth
    p = _CRYPTO_POLICY_CONF
    if p.exists():
        try:
            val = _crypto_policy_name(p.read_text())
        except OSError:
            return CheckResult("warn", f"cannot read {p}")
        if not val:
            return CheckResult("warn", f"no policy set in {p}")
        if _is_legacy_policy(val):
            return CheckResult("fail", f"crypto policy is {val}")
        # The config only takes effect once update-crypto-policies applies
        # it; state/current records what the back-ends were generated from.
        state = _CRYPTO_POLICY_STATE
        if state.exists():
            try:
                applied = _crypto_policy_name(state.read_text())
            except OSError:
                return CheckResult("warn", f"cannot read {state}")
            if _is_legacy_policy(applied):
                return CheckResult(
                    "fail",
                    f"config says {val} but the applied policy is {applied} — "
                    f"run `update-crypto-policies --set {val}`",
                )
        return CheckResult("pass", f"crypto policy: {val}")

    # Debian family: MinProtocol only takes effect if it's wired through
    # openssl_conf -> ssl_conf -> system_default. A bare [system_default_sect]
    # that nothing references does NOT harden TLS, so trace the chain rather
    # than substring-matching (which used to false-pass on an inert block).
    ssl_conf = _OPENSSL_CNF
    if ssl_conf.exists():
        try:
            eff = _openssl_min_protocol_effective(ssl_conf.read_text())
        except OSError:
            return CheckResult("warn", "cannot read /etc/ssl/openssl.cnf")
        if eff in ("TLSv1.2", "TLSv1.3"):
            return CheckResult("pass", f"openssl MinProtocol={eff} (wired)")
        if eff is not None:
            return CheckResult("fail", f"openssl MinProtocol={eff}, recommended: >= TLSv1.2")
        return CheckResult("fail", "openssl MinProtocol not enforced (no wired system_default)")

    # No crypto policy file at all — skip rather than pass on a system we
    # can't inspect.
    return CheckResult("skip", f"no crypto policy file on {distro.detect().family} family")


def _fix_crypto_policy() -> list[RollbackEntry]:
    """On RHEL family, set crypto policy to DEFAULT if currently LEGACY.

    On Debian family, set openssl MinProtocol = TLSv1.2 in /etc/ssl/openssl.cnf.
    No-op if neither config source is available (check returns skip).
    """
    rhel_conf = _CRYPTO_POLICY_CONF
    if rhel_conf.exists():
        prev = _crypto_policy_name(rhel_conf.read_text()) or "DEFAULT"
        r = subprocess.run(
            ["update-crypto-policies", "--set", "DEFAULT"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            raise RuntimeError(f"update-crypto-policies failed: {r.stderr.strip()}")
        return [RollbackEntry(
            action=f"set crypto policy to DEFAULT (was {prev})",
            undo=[["update-crypto-policies", "--set", prev]],
        )]

    ssl_conf = _OPENSSL_CNF
    if ssl_conf.exists():
        bkp = journal.backup_file(str(ssl_conf))
        text = ssl_conf.read_text()
        sec = _parse_ini_sections(text)
        init = sec.get("", {}).get("openssl_conf")

        if init and sec.get(init, {}).get("ssl_conf"):
            # An openssl_conf -> ssl_conf chain already exists; extend it.
            ssl = sec[init]["ssl_conf"]
            sysdef = sec.get(ssl, {}).get("system_default")
            if sysdef:
                # Set MinProtocol in the EXISTING terminal section.
                text = _set_key_in_section(text, sysdef, "MinProtocol", "TLSv1.2")
            else:
                # ssl_conf section exists but has no system_default — point it
                # at an LSS section and create that section.
                text = _set_key_in_section(text, ssl, "system_default", "lss_system_default")
                text = _set_key_in_section(text, "lss_system_default", "MinProtocol", "TLSv1.2")
        else:
            # No usable chain. Build one, wiring openssl_conf if it's absent
            # (it must live in the top section, so prepend it).
            if init:
                text = _set_key_in_section(text, init, "ssl_conf", "lss_ssl_sect")
            else:
                text = "openssl_conf = lss_openssl_init\n" + text
                text = _set_key_in_section(text, "lss_openssl_init", "ssl_conf", "lss_ssl_sect")
            text = _set_key_in_section(text, "lss_ssl_sect", "system_default", "lss_system_default")
            text = _set_key_in_section(text, "lss_system_default", "MinProtocol", "TLSv1.2")

        ssl_conf.write_text(text)
        return [RollbackEntry(
            action="wired openssl MinProtocol = TLSv1.2",
            path=str(ssl_conf),
            backup=bkp,
        )]

    return []


register(Control(
    id="LSS-001",
    title="Ensure system-wide crypto policy is not legacy",
    section="kernel",
    check=_check_crypto_policy,
    fix=_fix_crypto_policy,
))


# ---- CIS 3.2.1: Ensure IP forwarding is disabled (IPv6 specific) ----

def _check_ipv6_forwarding() -> CheckResult:
    # all.disable_ipv6 = 1 alone does not disable IPv6 on an interface that
    # was re-enabled afterwards or created later; ipv6_disabled() checks them all.
    if ipv6_disabled():
        return CheckResult("pass", "IPv6 is disabled")
    try:
        r2 = subprocess.run(["sysctl", "-n", "net.ipv6.conf.all.forwarding"], capture_output=True, text=True)
    except FileNotFoundError:
        return CheckResult("warn", "sysctl not available — cannot verify IPv6 forwarding")
    if r2.returncode == 0 and r2.stdout.strip() == "0":
        return CheckResult("pass")
    return CheckResult("fail", f"net.ipv6.conf.all.forwarding={r2.stdout.strip()}")


def _fix_ipv6_forwarding() -> list[RollbackEntry]:
    from lss.lib.sysctl import set_sysctl
    # If IPv6 is disabled the check already passes — no-op.
    if ipv6_disabled():
        return []
    return [set_sysctl("net.ipv6.conf.all.forwarding", "0")]


register(Control(
    id="3.2.1",
    title="Ensure IPv6 forwarding is disabled",
    section="network",
    check=_check_ipv6_forwarding,
    fix=_fix_ipv6_forwarding,
))


# ---- CIS 5.5: Ensure root login is restricted to system console ----

def _pam_securetty_active() -> bool | None:
    """True if pam_securetty.so is an uncommented auth module for the `login`
    service (following @include / include / substack). /etc/securetty is only
    consulted through that module; without it the file is inert. None if a
    PAM file could not be read."""
    login = _PAM_D / "login"
    todo, seen = [login], set()
    while todo:
        f = todo.pop()
        if f in seen:
            continue
        seen.add(f)
        try:
            text = f.read_text()
        except FileNotFoundError:
            continue
        except OSError:
            return None
        for line in text.splitlines():
            toks = line.split("#", 1)[0].split()
            if not toks:
                continue
            if toks[0] == "@include" and len(toks) > 1:
                todo.append(_PAM_D / toks[1])
                continue
            if toks[0].lstrip("-") != "auth" or len(toks) < 3:
                continue
            if toks[1] in ("include", "substack"):
                todo.append(_PAM_D / toks[2])
                continue
            if any(t.rsplit("/", 1)[-1] == "pam_securetty.so" for t in toks[1:]):
                return True
    return False


def _root_password_locked() -> bool | None:
    """True if root's /etc/shadow password is locked (`!`/`*` prefix), so
    root cannot log in with a password on any tty. None if unreadable."""
    try:
        text = _SHADOW.read_text()
    except OSError:
        return None
    for line in text.splitlines():
        parts = line.split(":")
        if parts[0] == "root" and len(parts) > 1:
            return parts[1].startswith(("!", "*"))
    return None


def _check_securetty() -> CheckResult:
    # /etc/securetty restricts nothing unless pam_securetty reads it, and
    # pam_securetty with no file allows every tty. A locked root password
    # meets the control on its own: root cannot log in on any tty.
    active = _pam_securetty_active()
    p = _SECURETTY
    if active and p.exists():
        try:
            raw = p.read_text()
        except OSError:
            return CheckResult("warn", f"cannot read {p}")
        lines = [l.strip() for l in raw.splitlines() if l.strip() and not l.strip().startswith("#")]
        if len(lines) <= 6:
            return CheckResult("pass", f"{len(lines)} console(s) allowed")
        return CheckResult("warn", f"{len(lines)} consoles in securetty — review for excess")
    locked = _root_password_locked()
    if locked:
        return CheckResult("pass", "root password is locked — root cannot log in on any tty")
    if active is None:
        return CheckResult("warn", f"cannot read the PAM login stack in {_PAM_D}")
    if locked is None:
        return CheckResult("warn", f"cannot read root's entry in {_SHADOW}")
    if active:
        return CheckResult("warn", f"no {p} — pam_securetty allows root on every tty")
    return CheckResult(
        "warn",
        f"pam_securetty is not in the login PAM stack, so {p} is not enforced "
        "and root can log in on any tty — lock root's password or restrict it",
    )


def _fix_securetty() -> list[RollbackEntry]:
    """Trim /etc/securetty to the CIS-minimal set (console, tty1).

    Only trims — never creates the file. If /etc/securetty does not exist,
    PAM already controls access (check passes) so no-op.
    """
    p = _SECURETTY
    if not p.exists():
        return []
    bkp = journal.backup_file(str(p))
    p.write_text("console\ntty1\n")
    return [RollbackEntry(
        action="trimmed /etc/securetty to CIS-minimal (console, tty1)",
        path=str(p),
        backup=bkp,
    )]


register(Control(
    id="LSS-002",
    title="Ensure root login is restricted to system console",
    section="auth",
    check=_check_securetty,
    fix=None,  # DEFANGED: truncating /etc/securetty to console,tty1 locks root out of serial/SoL consoles on headless/remote hosts. Trim by hand, preserving the consoles you actually use.
))


# ---- CIS 4.2.3: Ensure permissions on all logfiles are configured ----

def _scan_world_accessible_logs() -> tuple[list[str], list[str]]:
    """Walk /var/log recursively, as the CIS audit's `find /var/log -type f`
    does, and return (regular files with any world bit set, directories that
    could not be read). Symlinks are not followed."""
    import os, stat
    hits: list[str] = []
    errors: list[str] = []

    def _onerror(e: OSError) -> None:
        errors.append(getattr(e, "filename", None) or _LOG_DIR)

    for root, _dirs, files in os.walk(_LOG_DIR, onerror=_onerror):
        for name in files:
            fp = os.path.join(root, name)
            try:
                st = os.lstat(fp)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            if stat.S_IMODE(st.st_mode) & 0o007:
                hits.append(fp)
    return hits, errors


def _world_accessible_logs() -> list[str]:
    """Return paths of files under /var/log with any world bits set."""
    return _scan_world_accessible_logs()[0]


def _check_log_permissions() -> CheckResult:
    hits, errors = _scan_world_accessible_logs()
    if hits:
        return CheckResult("warn", f"{len(hits)} log files under {_LOG_DIR} are world-accessible")
    if errors:
        return CheckResult("warn", f"cannot read {errors[0]} — log permissions not verified")
    return CheckResult("pass")


def _fix_log_permissions() -> list[RollbackEntry]:
    """Strip world bits from world-accessible files in /var/log top level.

    Records each file's pre-change mode so rollback restores exactly, without
    forcing a blanket 0640 on files that originally had stricter permissions.
    """
    import os, stat
    entries: list[RollbackEntry] = []
    for fp in _world_accessible_logs():
        try:
            st = os.stat(fp)
        except (OSError, PermissionError):
            continue
        prev_mode = stat.S_IMODE(st.st_mode)
        new_mode = prev_mode & ~0o007
        try:
            os.chmod(fp, new_mode)
        except (OSError, PermissionError):
            continue
        entries.append(RollbackEntry(
            action=f"stripped world bits from {fp} ({oct(prev_mode)} -> {oct(new_mode)})",
            undo=[["chmod", oct(prev_mode)[2:].zfill(4), fp]],
        ))
    return entries


register(Control(
    id="4.2.3",
    title="Ensure permissions on all logfiles are configured",
    section="logging",
    check=_check_log_permissions,
    fix=_fix_log_permissions,
))


# ---- CIS 2.4: Ensure nonessential services listening are removed ----

def _check_listening_services() -> CheckResult:
    try:
        # UDP services (snmpd, avahi, rpcbind...) count too, as in the CIS
        # audit; with -t and -u, ss prefixes each row with a Netid column.
        r = subprocess.run(["ss", "-H", "-tulnp"], capture_output=True, text=True)
    except FileNotFoundError:
        return CheckResult("warn", "ss not available — cannot enumerate listening services")
    if r.returncode != 0:
        return CheckResult("warn", f"ss failed (exit {r.returncode}) — cannot enumerate listening services")
    lines = [l for l in r.stdout.splitlines() if l.strip()]
    if not lines:
        return CheckResult("pass", "no TCP or UDP services listening")
    ports = set()
    for line in lines:
        cols = line.split()
        if len(cols) >= 5:
            addr = cols[4]
            port = addr.rsplit(":", 1)[-1]
            if port.isdigit():
                ports.add(f"{port}/{cols[0]}")
    sample = ",".join(sorted(ports, key=lambda p: (int(p.split("/")[0]), p))[:6])
    more = "…" if len(ports) > 6 else ""
    return CheckResult(
        "warn",
        f"{len(lines)} listening service(s) on port(s) {sample}{more} — review with `ss -tulnp` and remove/mask any that aren't required",
    )


register(Control(
    id="2.4",
    title="Ensure nonessential services are removed or masked",
    section="services",
    check=_check_listening_services,
    fix=None,
))


# ---- CIS 6.2.16: Ensure no users have .bash_profile that sources untrusted paths ----

_PATH_ASSIGN_RE = None  # lazy-compiled


def _path_line_is_unsafe(line: str) -> bool:
    """A PATH= assignment line is unsafe if it injects '.' or an empty component.

    Empty component (PATH=:/usr/bin or PATH=/usr/bin:) silently means '.' to
    most shells. We extract the assigned value, strip surrounding quotes and
    a leading 'export ', then split on ':' and look for '.' / '' components.
    Comment lines and prose containing 'PATH=' as a substring are ignored.
    """
    import re
    global _PATH_ASSIGN_RE
    if _PATH_ASSIGN_RE is None:
        _PATH_ASSIGN_RE = re.compile(r"^\s*(?:export\s+)?PATH=([^\s#]+)")
    stripped = line.lstrip()
    if stripped.startswith("#"):
        return False
    m = _PATH_ASSIGN_RE.match(line)
    if not m:
        return False
    val = m.group(1).strip()
    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
        val = val[1:-1]
    parts = val.split(":")
    for p in parts:
        if p == "." or p == "":
            return True
    return False


def _check_dot_files_safe() -> CheckResult:
    passwd = Path("/etc/passwd")
    if not passwd.exists():
        return CheckResult("warn", "/etc/passwd not found")
    try:
        passwd_text = passwd.read_text()
    except OSError:
        return CheckResult("warn", "cannot read /etc/passwd")
    issues = []
    for line in passwd_text.splitlines():
        parts = line.split(":")
        if len(parts) >= 6:
            user, uid_str, home = parts[0], parts[2], parts[5]
            try:
                uid = int(uid_str)
                if uid < 1000 and user != "root":
                    continue
            except ValueError:
                continue
            for dotfile in [".bash_profile", ".bashrc", ".profile"]:
                fp = Path(home) / dotfile
                try:
                    if not fp.exists():
                        continue
                    text = fp.read_text()
                except (PermissionError, OSError):
                    continue
                for ln in text.splitlines():
                    if _path_line_is_unsafe(ln):
                        issues.append(f"{user}:{dotfile}")
                        break
    if not issues:
        return CheckResult("pass")
    return CheckResult("warn", f"dot files with potential PATH issues: {', '.join(issues[:3])}")


def _fix_dot_files_safe() -> list[RollbackEntry]:
    """Comment out unsafe PATH= lines in real users' shell dotfiles.

    Matches the same heuristic as the check: a line containing `PATH=` with
    either `.:` (current directory) or `: ` (empty component). The whole
    offending line gets prefixed with `# [LSS-DISABLED]`, never deleted,
    so the operator can review it and the file's overall content survives.
    """
    passwd = Path("/etc/passwd")
    if not passwd.exists():
        return []
    entries: list[RollbackEntry] = []
    for line in passwd.read_text().splitlines():
        parts = line.split(":")
        if len(parts) < 6:
            continue
        user, _x, uid_str = parts[0], parts[1], parts[2]
        home = parts[5]
        try:
            uid = int(uid_str)
        except ValueError:
            continue
        if uid < 1000 and user != "root":
            continue
        for dotfile in [".bash_profile", ".bashrc", ".profile"]:
            fp = Path(home) / dotfile
            if not fp.exists():
                continue
            try:
                text = fp.read_text()
            except PermissionError:
                continue
            lines = text.splitlines(keepends=True)
            if not any(_path_line_is_unsafe(ln) for ln in lines):
                continue
            bkp = journal.backup_file(str(fp))
            changed = False
            for i, ln in enumerate(lines):
                if _path_line_is_unsafe(ln):
                    lines[i] = f"# [LSS-DISABLED] {ln}"
                    changed = True
            if not changed:
                continue
            fp.write_text("".join(lines))
            entries.append(RollbackEntry(
                action=f"commented unsafe PATH line(s) in {fp}",
                path=str(fp),
                backup=bkp,
            ))
    return entries


register(Control(
    id="LSS-003",
    title="Ensure no users' dot files have unsafe PATH entries",
    section="users",
    check=_check_dot_files_safe,
    fix=_fix_dot_files_safe,
))


# ---- CIS 5.4.5: Ensure default user shell timeout is configured ----

_SH_LEAD_WORDS = {"then", "else", "do", "{", "(", "!", "&&", "||"}


def _tmout_statements(line: str) -> list[tuple[str, str | None, bool, bool]]:
    """Parse the TMOUT statements on one shell line.

    Returns (raw statement, assigned value or None, readonly?, exported?)
    for each `;`-separated statement that names TMOUT. Comment lines and
    trailing `#` comments are ignored."""
    s = line.strip()
    if not s or s.startswith("#"):
        return []
    s = re.split(r"(?:^|\s)#", s, maxsplit=1)[0]
    out = []
    for stmt in s.split(";"):
        toks = stmt.split()
        while toks and toks[0] in _SH_LEAD_WORDS:
            toks = toks[1:]
        if not toks:
            continue
        names = [t for t in toks if t == "TMOUT" or t.startswith("TMOUT=")]
        if not names:
            continue
        value = None
        for t in names:
            if t.startswith("TMOUT="):
                value = t[len("TMOUT="):].strip("\"'")
        cmd = toks[0]
        flags = "".join(t[1:] for t in toks[1:] if t.startswith("-"))
        typed = cmd in ("declare", "typeset")
        readonly = cmd == "readonly" or (typed and "r" in flags)
        exported = cmd == "export" or (typed and "x" in flags)
        out.append((stmt, value, readonly, exported))
    return out


def _tmout_files() -> list[Path]:
    files = list(_SHELL_RC_FILES)
    if _PROFILE_D.is_dir():
        files.extend(sorted(_PROFILE_D.glob("*.sh")))
    return files


def _tmout_value_ok(value: str | None) -> bool | None:
    """True for 1..900, False for 0 or > 900, None when not a literal number."""
    if value is None or not value.isdigit():
        return None
    return 0 < int(value) <= 900


def _check_shell_timeout() -> CheckResult:
    """CIS 5.4.5 audit: some file a shell sources (/etc/profile, /etc/bashrc,
    /etc/bash.bashrc, /etc/profile.d/*.sh) must set TMOUT to 1..900 AND make it
    readonly AND export it, and no such file may set TMOUT to 0 or above 900.
    A plain `TMOUT=600` can be unset by any user, and a later file setting
    TMOUT=0 overrides an earlier good value. The fix writes
    /etc/profile.d/80-lss-timeout.sh, so profile.d must be scanned."""
    good_unlocked: list[str] = []
    bad: list[str] = []
    compliant = False
    for p in _tmout_files():
        if not p.exists():
            continue
        try:
            content = p.read_text()
        except OSError:
            return CheckResult("warn", f"cannot read {p} — TMOUT not verified")
        has_good = has_ro = has_export = False
        for line in content.splitlines():
            for _stmt, value, ro, exp in _tmout_statements(line):
                ok = _tmout_value_ok(value)
                if ok is False:
                    bad.append(f"TMOUT={value} in {p}")
                elif ok:
                    has_good = True
                has_ro = has_ro or ro
                has_export = has_export or exp
        if has_good and has_ro and has_export:
            compliant = True
        elif has_good:
            good_unlocked.append(str(p))
    if bad:
        return CheckResult("warn", f"{', '.join(bad[:3])} — recommended: 1-900 everywhere")
    if compliant:
        return CheckResult("pass")
    if good_unlocked:
        return CheckResult(
            "fail",
            f"TMOUT set in {good_unlocked[0]} but not both readonly and exported — "
            "users can unset it",
        )
    return CheckResult("fail", "TMOUT not set — no shell idle timeout")


def _fix_shell_timeout() -> list[RollbackEntry]:
    entries: list[RollbackEntry] = []
    conf = _PROFILE_D / "80-lss-timeout.sh"
    # A TMOUT of 0 or > 900 elsewhere would keep the check failing (and a
    # later file can override ours), so comment those lines out, as LSS-003
    # does for unsafe PATH lines.
    for p in _tmout_files():
        if p == conf or not p.exists():
            continue
        try:
            lines = p.read_text().splitlines(keepends=True)
        except OSError:
            continue
        changed = False
        for i, ln in enumerate(lines):
            if any(_tmout_value_ok(v) is False for _s, v, _r, _e in _tmout_statements(ln)):
                if not changed:
                    bkp_other = journal.backup_file(str(p))
                lines[i] = f"# [LSS-DISABLED] {ln}"
                changed = True
        if changed:
            p.write_text("".join(lines))
            entries.append(RollbackEntry(
                action=f"commented out non-compliant TMOUT line(s) in {p}",
                path=str(p),
                backup=bkp_other,
            ))
    bkp = journal.backup_file(str(conf))
    conf.write_text("# Set by LSS — shell timeout after 15 minutes of inactivity\nreadonly TMOUT=900\nexport TMOUT\n")
    entries.append(RollbackEntry(
        action="set shell TMOUT=900 in /etc/profile.d/",
        path=str(conf),
        backup=bkp,
        undo=[] if bkp else [["rm", "-f", str(conf)]],
    ))
    return entries


register(Control(
    id="5.4.5",
    title="Ensure default user shell timeout is 900 seconds or less",
    section="auth",
    check=_check_shell_timeout,
    fix=_fix_shell_timeout,
))


# ---- CIS 4.1.2: Ensure audit backlog limit is sufficient ----

def _check_audit_backlog() -> CheckResult:
    p = _PROC_CMDLINE
    if p.exists():
        try:
            text = p.read_text()
        except OSError:
            text = ""
        # Whole parameter only, and the kernel applies the LAST occurrence
        # when a parameter is repeated.
        vals = re.findall(r"(?:^|\s)audit_backlog_limit=(\d+)(?=\s|$)", text)
        val = vals[-1] if vals else None
        if val is not None and int(val) >= 8192:
            return CheckResult("pass")
        if val is not None:
            return CheckResult(
                "warn",
                f"audit_backlog_limit={val}, recommended: >= 8192. "
                f"Edit GRUB_CMDLINE_LINUX in /etc/default/grub, then run update-grub and reboot.",
            )
    return CheckResult(
        "warn",
        "audit_backlog_limit not set in /proc/cmdline. Add audit_backlog_limit=8192 to "
        "GRUB_CMDLINE_LINUX in /etc/default/grub, then run update-grub and reboot.",
    )


register(Control(
    id="4.1.2",
    title="Ensure audit backlog limit is sufficient",
    section="logging",
    check=_check_audit_backlog,
    fix=None,  # Intentionally manual: bad GRUB edits brick hosts; rollback can't reach a host that won't boot.
))


# ---- LSS-004: AppArmor service condition-skip on Live+persistence boots ----
#
# Debian's /usr/lib/systemd/system/apparmor.service ships with the condition
# `ConditionPathExists=!/run/live/overlay/work`. On a normal install /run/live
# does not exist and the condition is satisfied (service starts). On a Debian
# Live boot (or Kali Live, which derives from it) the path exists and the
# condition fails — the service is skipped, no profiles enforce, and no
# AppArmor confinement applies even though the kernel module is loaded and
# the profiles are present on disk.
#
# This still bites on Live boots with persistence enabled, where the customer
# expects a "real" install experience. It's invisible to standard CIS scanners
# because aa-status reports "module is loaded" and the kernel parameter is
# correct — only checking the systemd ConditionResult exposes the gap.
#
# Detection pairs the Live+persistence indicator with ConditionResult=no on
# apparmor.service. Remediation is a one-line systemd drop-in that wipes the
# inherited condition.

def _is_live_persistence() -> bool:
    """True if booted from Debian/Kali Live media with a persistence overlay."""
    cmdline = Path("/proc/cmdline")
    if not cmdline.exists():
        return False
    try:
        if "boot=live" not in cmdline.read_text():
            return False
    except OSError:
        return False
    persistence_dir = Path("/run/live/persistence")
    if not persistence_dir.exists():
        return False
    try:
        return any(persistence_dir.iterdir())
    except (OSError, PermissionError):
        return False


def _apparmor_service_condition_skipped() -> bool | None:
    """True if apparmor.service is loaded but skipped by a unit Condition.

    Returns False if the service is not loaded at all (different problem,
    handled by 1.6.1) or if the condition is satisfied (service runs), and
    None if systemctl failed, so the state is unknown.
    """
    try:
        r = subprocess.run(
            ["systemctl", "show", "apparmor.service",
             "--property=LoadState", "--property=ConditionResult"],
            capture_output=True, text=True,
        )
    except FileNotFoundError:
        # No systemd, so no apparmor.service unit to be condition-skipped.
        return False
    if r.returncode != 0:
        return None
    props = dict(
        l.split("=", 1) for l in r.stdout.splitlines() if "=" in l
    )
    if props.get("LoadState") != "loaded":
        return False
    return props.get("ConditionResult") == "no"


def _check_apparmor_live_condition() -> CheckResult:
    if not _is_live_persistence():
        return CheckResult("skip", "not a Debian/Kali Live + persistence system")
    skipped = _apparmor_service_condition_skipped()
    if skipped is None:
        return CheckResult("warn", "systemctl show apparmor.service failed — condition not verified")
    if not skipped:
        return CheckResult("pass", "apparmor.service condition is satisfied")
    return CheckResult(
        "fail",
        "apparmor.service is condition-skipped on this Live+persistence host. "
        "Debian's unit file has `ConditionPathExists=!/run/live/overlay/work` "
        "which prevents the service from starting whenever the Live overlay is "
        "in use — even with persistence configured. No profiles are enforcing "
        "as a result. Remediate by writing a systemd drop-in that empties the "
        "condition: `sudo install -d /etc/systemd/system/apparmor.service.d && "
        "printf '[Unit]\\nConditionPathExists=\\n' | sudo tee "
        "/etc/systemd/system/apparmor.service.d/override.conf >/dev/null && "
        "sudo systemctl daemon-reload && sudo systemctl enable --now apparmor.service`.",
    )


register(Control(
    id="LSS-004",
    title="Ensure apparmor.service is not condition-skipped on Live+persistence boots",
    section="kernel",
    check=_check_apparmor_live_condition,
    fix=None,  # Audit-only in v1.0; auto-fix planned for a future release after testing across Live distros.
))


# ---- LSS-005: Forensic-grade user execve auditing (beyond CIS 4.1.13) ----
#
# CIS 4.1.13 specifies a narrow execve audit rule that fires only on
# privilege-transition execves (effective UID becomes 0 while real UID
# differs) — covering sudo, su, pkexec, and setuid-root binaries. That
# answers "what got root" but is silent on what a user runs as themselves
# before, after, or alongside privilege use.
#
# Forensic responders typically want broader coverage: every execve performed
# by a real user (auid >= 1000). LSS-005 detects whether any such rule is
# active and surfaces a remediation if not.
#
# This is intentionally audit-only. The broader rule produces audit log
# volume proportional to user shell activity — tens to hundreds of MB per
# day on an interactive host — and should be enabled deliberately, with the
# operator's audit log rotation policy reviewed first.

_LSS005_RULES = [
    "-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=4294967295 -k user-exec",
    "-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=4294967295 -k user-exec",
]


def _is_user_execve_rule(line: str) -> bool:
    """True for a loaded `always,exit` rule on the execve syscall whose only
    filters are the arch, a key and auid (auid>=N with N <= 1000, plus any
    auid!= exclusions). Token-level, so `-S execveat` is not `execve` and
    `auid>=10000` (which skips UIDs 1000-9999) is not `auid>=1000`; other
    filters (euid=0, -C euid!=uid, exe=...) narrow it to a subset of users."""
    toks = line.split()
    action = ""
    syscalls: set[str] = set()
    fields: list[str] = []
    i = 0
    while i < len(toks):
        t = toks[i]
        arg = toks[i + 1] if i + 1 < len(toks) else ""
        if t in ("-a", "-A"):
            action = arg
        elif t == "-S":
            syscalls.update(arg.split(","))
        elif t == "-F":
            fields.append(arg)
        elif t == "-k":
            pass
        elif t in ("-w", "-p", "-C"):
            return False  # a watch, or a comparison that narrows the rule
        else:
            i += 1
            continue
        i += 2
    if set(action.split(",")) != {"always", "exit"} or "execve" not in syscalls:
        return False
    floor_ok = False
    for f in fields:
        m = re.fullmatch(r"auid>=(\d+)", f)
        if m:
            if int(m.group(1)) > 1000:
                return False
            floor_ok = True
            continue
        if f.startswith("auid!=") or f.startswith(("arch=", "key=")):
            continue
        return False
    return floor_ok


def _check_forensic_execve() -> CheckResult:
    """Pass when an active execve rule scoped to real users (auid>=1000) exists.

    Operators using a different key than `user-exec` still satisfy the
    requirement; the check looks for the syscall + auid filter combination,
    not a specific key name.
    """
    try:
        r = subprocess.run(["auditctl", "-l"], capture_output=True, text=True)
    except FileNotFoundError:
        return CheckResult("warn", "auditctl unavailable — cannot inspect loaded rules")
    if r.returncode != 0:
        return CheckResult("warn", "auditctl unavailable — cannot inspect loaded rules")
    for line in r.stdout.splitlines():
        if _is_user_execve_rule(line):
            return CheckResult("pass", "broader user-execve audit rule active")
    return CheckResult(
        "manual",
        "no broader user-execve audit rule active. CIS 4.1.13 captures only "
        "privilege-transition execves (sudo/su/pkexec/setuid). For forensic "
        "coverage of every command run as a real user, add to "
        "/etc/audit/rules.d/: "
        f"`{_LSS005_RULES[0]}` and `{_LSS005_RULES[1]}`, then `augenrules --load`. "
        "Volume warning: this rule can produce hundreds of MB of audit logs "
        "per day on an interactive host — review your audit log rotation "
        "(/etc/audit/auditd.conf max_log_file, num_logs) before enabling."
    )


register(Control(
    id="LSS-005",
    title="Forensic-grade user execve auditing (beyond CIS 4.1.13)",
    section="logging",
    check=_check_forensic_execve,
    fix=None,  # Audit-only by design — log-volume impact requires operator opt-in.
))
