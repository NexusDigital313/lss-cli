# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file, 
# via any medium, is strictly prohibited without explicit written authorization.

"""CIS Section 4 — Logging and Auditing."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from lss.lib import distro, journal, pkg
from lss.lib.registry import Control, CheckResult, RollbackEntry, register


def _systemd_is_active(unit: str) -> bool:
    r = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True)
    return r.stdout.strip() == "active"


def _systemd_is_enabled(unit: str) -> bool:
    r = subprocess.run(["systemctl", "is-enabled", unit], capture_output=True, text=True)
    return r.stdout.strip() == "enabled"


# ---- CIS 4.1.1.1: Ensure auditd is installed ----

def _check_auditd_installed() -> CheckResult:
    verified = False
    try:
        r = subprocess.run(["which", "auditd"], capture_output=True, text=True)
        verified = True
        if r.returncode == 0:
            return CheckResult("pass")
    except FileNotFoundError:
        pass
    # Check package. Query the install Status, not just the exit code:
    # `dpkg-query -W` exits 0 for a removed-but-not-purged package (status
    # `deinstall ok config-files`, auditd binary gone), so the rc alone
    # false-passed this control on a host with no auditd.
    try:
        r2 = subprocess.run(["dpkg-query", "-W", "-f=${Status}", "auditd"], capture_output=True, text=True)
        verified = True
        if r2.returncode == 0 and "install ok installed" in r2.stdout:
            return CheckResult("pass")
    except FileNotFoundError:
        pass
    try:
        r3 = subprocess.run(["rpm", "-q", "audit"], capture_output=True, text=True)
        verified = True
        if r3.returncode == 0:
            return CheckResult("pass")
    except FileNotFoundError:
        pass
    if not verified:
        return CheckResult("warn", "cannot verify auditd installation — no 'which' or package manager available")
    return CheckResult("fail", "auditd is not installed")


register(Control(
    id="4.1.1.1",
    title="Ensure auditd is installed",
    section="logging",
    check=_check_auditd_installed,
    # RHEL ships the daemon in the `audit` package; there is no `auditd`.
    fix=lambda: pkg.install("audit" if distro.is_rhel_family() else "auditd"),
))


# ---- CIS 4.1.1.2: Ensure auditd service is enabled and running ----

def _check_auditd_running() -> CheckResult:
    try:
        if not _systemd_is_enabled("auditd"):
            return CheckResult("fail", "auditd is not enabled")
        if not _systemd_is_active("auditd"):
            return CheckResult("fail", "auditd is not active")
    except FileNotFoundError:
        return CheckResult("warn", "systemctl not found — cannot verify auditd service state")
    return CheckResult("pass")


def _fix_auditd_running() -> list[RollbackEntry]:
    """Enable and start auditd. Raise if either step fails so the harden
    engine surfaces the failure rather than silently returning a partial
    rollback set that the caller would treat as success."""
    entries = []
    r_enable = subprocess.run(["systemctl", "enable", "auditd"], capture_output=True, text=True)
    if r_enable.returncode == 0:
        entries.append(RollbackEntry(action="enabled auditd", undo=[["systemctl", "disable", "auditd"]]))
    else:
        raise RuntimeError(f"systemctl enable auditd failed: {r_enable.stderr.strip()}")
    r_start = subprocess.run(["systemctl", "start", "auditd"], capture_output=True, text=True)
    if r_start.returncode == 0:
        entries.append(RollbackEntry(action="started auditd", undo=[["systemctl", "stop", "auditd"]]))
    else:
        # On RHEL family, systemd intentionally refuses systemctl start auditd;
        # fall back to the legacy service command before raising.
        r_legacy = subprocess.run(["service", "auditd", "start"], capture_output=True, text=True)
        if r_legacy.returncode == 0:
            entries.append(RollbackEntry(action="started auditd via service", undo=[["service", "auditd", "stop"]]))
        else:
            raise RuntimeError(
                f"could not start auditd: systemctl rc={r_start.returncode} ({r_start.stderr.strip()}); "
                f"service rc={r_legacy.returncode} ({r_legacy.stderr.strip()})"
            )
    return entries


register(Control(
    id="4.1.1.2",
    title="Ensure auditd service is enabled and running",
    section="logging",
    check=_check_auditd_running,
    fix=_fix_auditd_running,
))


# ---- CIS 4.1.1.3: Ensure audit log storage size is configured ----

AUDITD_CONF = Path("/etc/audit/auditd.conf")


def _auditd_conf_value(text: str, key: str) -> str | None:
    """Value of `key` in auditd.conf, or None when unset.

    auditd applies assignments in file order with no duplicate check, so the
    LAST one wins. The key is compared exactly (`max_log_file` is not
    `max_log_file_action`) and comment lines are skipped.
    """
    val = None
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, v = s.split("=", 1)
        if k.strip() == key:
            val = v.strip()
    return val


def _set_auditd_key(text: str, key: str, value: str) -> str:
    """Set every live assignment of `key` to `value` (auditd applies the last
    one, so a stale later duplicate would undo a first-only edit); append
    one when the key is unset."""
    lines = text.splitlines(keepends=True)
    found = False
    for i, line in enumerate(lines):
        s = line.strip()
        if s and not s.startswith("#") and "=" in s and s.split("=", 1)[0].strip() == key:
            lines[i] = f"{key} = {value}\n"
            found = True
    if not found:
        # Ensure the last line ends with a newline before appending — a
        # hand-edited file without one would otherwise produce
        # `prev_line<key> = …`, which auditd rejects on next startup.
        if lines and not lines[-1].endswith("\n"):
            lines[-1] = lines[-1] + "\n"
        lines.append(f"{key} = {value}\n")
    return "".join(lines)


def _check_audit_log_size() -> CheckResult:
    try:
        text = AUDITD_CONF.read_text()
    except FileNotFoundError:
        return CheckResult("warn", "auditd.conf not found")
    except OSError as e:
        return CheckResult("warn", f"cannot read auditd.conf: {e}")
    val = _auditd_conf_value(text, "max_log_file")
    if val is None:
        return CheckResult("fail", "max_log_file not set in auditd.conf")
    try:
        size = int(val)
    except ValueError:
        return CheckResult("fail", f"max_log_file={val!r} is not a number")
    if size >= 8:
        return CheckResult("pass")
    return CheckResult("warn", f"max_log_file={val}MB, recommended: ≥ 8")


def _fix_audit_log_size() -> list[RollbackEntry]:
    """Set max_log_file = 32 (MB) in /etc/audit/auditd.conf and reload auditd.

    32MB is a conservative default well above the CIS minimum of 8MB;
    operators with specific retention needs can adjust manually.

    auditd reads its config only at startup, so a config-only write would
    leave the running daemon at the old value (cosmetic-pass class).
    `service auditd reload` (which sends SIGUSR1 — the canonical reload
    signal) picks up the new value without restarting the daemon. systemd
    intentionally refuses `systemctl restart auditd` on RHEL family, so we
    use the legacy service command which works on both Debian and RHEL.
    """
    conf = AUDITD_CONF
    if not conf.exists():
        # Silently returning [] would leave the harden engine reporting
        # "Applied: 1" while the post-fix audit still warns "auditd.conf
        # not found" — cosmetic-pass class. Refuse instead so the operator
        # sees a clear actionable error and the run summary counts it as
        # failed, not applied. 4.1.1.1 (`lss harden --control 4.1.1.1`)
        # installs auditd; running the full harden pass applies that
        # control before this one.
        raise RuntimeError(
            "auditd.conf not found at /etc/audit/auditd.conf — install auditd "
            "first. On Debian/Ubuntu/Kali: `sudo apt install auditd`. On "
            "RHEL/Fedora: `sudo dnf install audit`. Or run `sudo lss harden "
            "--confirm --control 4.1.1.1` to install it via LSS."
        )
    bkp = journal.backup_file(str(conf))
    conf.write_text(_set_auditd_key(conf.read_text(), "max_log_file", "32"))
    # Reload running daemon so the new value takes effect immediately.
    # Best-effort: log but don't fail the fix if reload is unavailable
    # (e.g., auditd not yet running). The check verifies file content,
    # which is correct for the persisted policy.
    subprocess.run(["service", "auditd", "reload"], capture_output=True)
    return [RollbackEntry(
        action="set auditd max_log_file = 32 MB and reloaded auditd",
        path=str(conf),
        backup=bkp,
        # On rollback the file is restored from backup; reload again so the
        # running daemon reverts to the prior value.
        undo=[["service", "auditd", "reload"]],
    )]


register(Control(
    id="4.1.1.3",
    title="Ensure audit log storage size is configured",
    section="logging",
    check=_check_audit_log_size,
    fix=_fix_audit_log_size,
))


# ---- CIS 4.1.1.4: Ensure audit logs are not automatically deleted ----

def _check_audit_log_retention() -> CheckResult:
    try:
        text = AUDITD_CONF.read_text()
    except FileNotFoundError:
        return CheckResult("warn", "auditd.conf not found")
    except OSError as e:
        return CheckResult("warn", f"cannot read auditd.conf: {e}")
    val = _auditd_conf_value(text, "max_log_file_action")
    if val is None:
        return CheckResult("fail", "max_log_file_action not set")
    if val.lower() == "keep_logs":
        return CheckResult("pass")
    return CheckResult("fail", f"max_log_file_action={val}, recommended: keep_logs")


def _fix_audit_log_retention() -> list[RollbackEntry]:
    conf = AUDITD_CONF
    if not conf.exists():
        raise RuntimeError(
            "auditd.conf not found at /etc/audit/auditd.conf — install auditd "
            "first. On Debian/Ubuntu/Kali: `sudo apt install auditd`. On "
            "RHEL/Fedora: `sudo dnf install audit`. Or run `sudo lss harden "
            "--confirm --control 4.1.1.1` to install it via LSS."
        )
    bkp = journal.backup_file(str(conf))
    conf.write_text(_set_auditd_key(conf.read_text(), "max_log_file_action", "keep_logs"))
    return [RollbackEntry(
        action="set max_log_file_action = keep_logs",
        path=str(conf),
        backup=bkp,
    )]


register(Control(
    id="4.1.1.4",
    title="Ensure audit logs are not automatically deleted",
    section="logging",
    check=_check_audit_log_retention,
    fix=_fix_audit_log_retention,
))


# ---- journald configuration (shared by 4.2.1.x) ----
#
# journald reads its main file (the first of /etc, /run, /usr/local/lib,
# /usr/lib that exists; older systemd reads only /etc) and then every
# `*.conf` drop-in from the journald.conf.d dirs below, sorted by file name,
# a name in an earlier dir masking the same name in a later one. The last
# assignment wins; only keys inside [Journal] count; `#` and `;` start
# comments; whitespace around `=` is allowed. Reading only the first
# `Key=` line of /etc/systemd/journald.conf missed all of that.

JOURNALD_CONF = Path("/etc/systemd/journald.conf")
JOURNALD_MAIN_FALLBACKS = (
    Path("/run/systemd/journald.conf"),
    Path("/usr/local/lib/systemd/journald.conf"),
    Path("/usr/lib/systemd/journald.conf"),
)
JOURNALD_DROPIN_DIRS = (
    Path("/etc/systemd/journald.conf.d"),
    Path("/run/systemd/journald.conf.d"),
    Path("/usr/local/lib/systemd/journald.conf.d"),
    Path("/usr/lib/systemd/journald.conf.d"),
)
JOURNAL_DIR = Path("/var/log/journal")


def _journald_files() -> tuple[Path | None, list[Path]]:
    """(main file or None, drop-ins in the order journald applies them).
    Raises OSError when a drop-in dir exists but cannot be listed."""
    main = next((p for p in (JOURNALD_CONF, *JOURNALD_MAIN_FALLBACKS) if p.exists()), None)
    dropins: dict[str, Path] = {}
    for d in JOURNALD_DROPIN_DIRS:
        try:
            entries = sorted(d.iterdir())
        except (FileNotFoundError, NotADirectoryError):
            continue
        for p in entries:
            if p.name.endswith(".conf") and not p.is_dir():
                dropins.setdefault(p.name, p)
    return main, [dropins[n] for n in sorted(dropins)]


def _journald_assignments(path: Path) -> list[tuple[str, str]]:
    """(key, value) pairs inside [Journal], in file order. Raises OSError."""
    out: list[tuple[str, str]] = []
    section = None
    for line in path.read_text().splitlines():
        s = line.strip()
        if not s or s[0] in "#;":
            continue
        if s.startswith("[") and s.endswith("]"):
            section = s[1:-1].strip()
            continue
        if section == "Journal" and "=" in s:
            k, v = s.split("=", 1)
            out.append((k.strip(), v.strip()))
    return out


def _journald_effective(key: str) -> tuple[str | None, Path | None, bool]:
    """(value, file that set it, any config found). Raises OSError."""
    main, dropins = _journald_files()
    val = src = None
    for f in ([main] if main else []) + dropins:
        for k, v in _journald_assignments(f):
            if k == key:
                val, src = v, f
    return val, src, bool(main or dropins)


def _journald_set(text: str, key: str, value: str, append: bool) -> str:
    """Set every live [Journal] assignment of `key`. With `append`, a file
    that has none gets one (in place of Debian's commented default when
    present), under a [Journal] header."""
    lines = text.splitlines(keepends=True)
    section = None
    replaced = False
    commented = None
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            section = s[1:-1].strip()
            continue
        if section != "Journal":
            continue
        if s and s[0] not in "#;" and "=" in s and s.split("=", 1)[0].strip() == key:
            lines[i] = f"{key}={value}\n"
            replaced = True
        elif commented is None and s[:1] == "#" and s[1:].lstrip().startswith(key + "="):
            commented = i
    if not replaced and append:
        if commented is not None:
            lines[commented] = f"{key}={value}\n"
        else:
            if lines and not lines[-1].endswith("\n"):
                lines[-1] = lines[-1] + "\n"
            if section != "Journal":
                lines.append("[Journal]\n")
            lines.append(f"{key}={value}\n")
    return "".join(lines)


def _journald_fix(key: str, value: str, ok, undo: list[list[str]]) -> list[RollbackEntry]:
    """Write `key=value` to /etc/systemd/journald.conf and to every
    /etc drop-in that assigns the key, so the effective value is `value`.
    Refuses up front when a drop-in LSS does not edit (/run, /usr/lib) would
    still override it — the post-fix check would otherwise keep failing."""
    _main, dropins = _journald_files()
    etc_dir = JOURNALD_DROPIN_DIRS[0]
    targets = [p for p in dropins
               if p.parent == etc_dir and any(k == key for k, _ in _journald_assignments(p))]
    final, final_src = value, JOURNALD_CONF
    for p in dropins:
        for k, v in _journald_assignments(p):
            if k == key:
                final, final_src = (value, p) if p in targets else (v, p)
    if not ok(final):
        raise RuntimeError(
            f"journald {key}={final} is set by {final_src}, which overrides "
            f"/etc/systemd/journald.conf; set {key}={value} there, or in a "
            f"drop-in in {etc_dir} that sorts after it"
        )
    entries: list[RollbackEntry] = []
    for path in [JOURNALD_CONF, *targets]:
        bkp = journal.backup_file(str(path))
        text = path.read_text() if path.exists() else "[Journal]\n"
        path.write_text(_journald_set(text, key, value, append=(path == JOURNALD_CONF)))
        entries.append(RollbackEntry(
            action=f"set journald {key}={value} in {path}",
            path=str(path),
            backup=bkp,
            # Undo on the main file only: rollback runs in reverse, so the
            # drop-ins are restored before journald is restarted.
            undo=undo if path == JOURNALD_CONF else [],
        ))
    return entries


# ---- CIS 4.2.1.1: Ensure journald is configured to write to persistent storage ----

def _storage_ok(val: str) -> bool:
    return val == "persistent"


def _check_journald_persistent() -> CheckResult:
    try:
        val, src, found = _journald_effective("Storage")
    except OSError as e:
        return CheckResult("warn", f"cannot read journald configuration: {e}")
    if not found:
        return CheckResult("warn", "journald.conf not found")
    if val is not None:
        if _storage_ok(val):
            return CheckResult("pass")
        return CheckResult("fail", f"Storage={val} (set in {src}), recommended: persistent")
    # Default behavior (Storage=auto) — persistent iff /var/log/journal exists
    if JOURNAL_DIR.exists():
        return CheckResult("pass", "persistent by default")
    return CheckResult("fail", "journald Storage not set to persistent")


def _fix_journald_persistent() -> list[RollbackEntry]:
    # Track whether WE create /var/log/journal: journald treats its mere
    # existence as "persistent" (the check does too), so if we leave the
    # directory behind on rollback the change is not actually reversed even
    # after journald.conf is restored. `rmdir` only removes an EMPTY
    # directory, so it can never delete logs journald has since written
    # there (it just no-ops with an error we surface, which is the safe
    # outcome). Rollback also restarts journald so the previous setting
    # takes effect again.
    created_dir = not JOURNAL_DIR.exists()
    undo: list[list[str]] = []
    if created_dir:
        undo.append(["rmdir", str(JOURNAL_DIR)])
    undo.append(["systemctl", "restart", "systemd-journald"])
    entries = _journald_fix("Storage", "persistent", _storage_ok, undo)
    JOURNAL_DIR.mkdir(exist_ok=True)
    # Restart journald to pick up the change
    subprocess.run(["systemctl", "restart", "systemd-journald"], capture_output=True)
    return entries


register(Control(
    id="4.2.1.1",
    title="Ensure journald is configured to write to persistent storage",
    section="logging",
    check=_check_journald_persistent,
    fix=_fix_journald_persistent,
))


# ---- CIS 4.2.1.2: Ensure journald is configured to compress large log files ----

_BOOL_TRUE = {"1", "yes", "y", "true", "t", "on"}
_BOOL_FALSE = {"0", "no", "n", "false", "f", "off"}


def _compress_ok(val: str) -> bool:
    """journald's Compress= takes a boolean or a size threshold (which
    enables compression); an empty value resets it to the default, yes."""
    v = val.lower()
    if v == "" or v in _BOOL_TRUE:
        return True
    if v in _BOOL_FALSE:
        return False
    return re.fullmatch(r"\d+(\.\d+)?\s*[kmgtpe]?(i?b)?", v) is not None


def _check_journald_compress() -> CheckResult:
    try:
        val, src, found = _journald_effective("Compress")
    except OSError as e:
        return CheckResult("warn", f"cannot read journald configuration: {e}")
    if not found:
        return CheckResult("warn", "journald.conf not found")
    if val is None:
        # Default is yes in most distros
        return CheckResult("pass", "default is yes")
    if _compress_ok(val):
        return CheckResult("pass")
    return CheckResult("fail", f"Compress={val} (set in {src})")


def _fix_journald_compress() -> list[RollbackEntry]:
    main, dropins = _journald_files()
    if main is None and not dropins:
        raise RuntimeError(
            "journald.conf not found at /etc/systemd/journald.conf — systemd is "
            "not installed or not the active init. journald is required for this "
            "control; nothing to harden on a non-systemd host."
        )
    entries = _journald_fix(
        "Compress", "yes", _compress_ok, [["systemctl", "restart", "systemd-journald"]],
    )
    subprocess.run(["systemctl", "restart", "systemd-journald"], capture_output=True)
    return entries


register(Control(
    id="4.2.1.2",
    title="Ensure journald is configured to compress large log files",
    section="logging",
    check=_check_journald_compress,
    fix=_fix_journald_compress,
))


# ---- CIS 4.2.2.1: Ensure rsyslog is installed ----

def _check_rsyslog() -> CheckResult:
    verified = False
    try:
        r = subprocess.run(["which", "rsyslogd"], capture_output=True, text=True)
        verified = True
        if r.returncode == 0:
            return CheckResult("pass")
    except FileNotFoundError:
        pass
    try:
        # -f=${Status}: plain `dpkg-query -W` prints only name/version, so the
        # "install ok installed" guard below could never match.
        r2 = subprocess.run(["dpkg-query", "-W", "-f=${Status}", "rsyslog"], capture_output=True, text=True)
        verified = True
        if r2.returncode == 0 and "install ok installed" in r2.stdout:
            return CheckResult("pass")
    except FileNotFoundError:
        pass
    try:
        r3 = subprocess.run(["rpm", "-q", "rsyslog"], capture_output=True, text=True)
        verified = True
        if r3.returncode == 0:
            return CheckResult("pass")
    except FileNotFoundError:
        pass
    if not verified:
        return CheckResult("warn", "cannot verify rsyslog installation — no 'which' or package manager available")
    return CheckResult("warn", "rsyslog not installed — journald may be sole log source")


register(Control(
    id="4.2.2.1",
    title="Ensure rsyslog is installed",
    section="logging",
    check=_check_rsyslog,
    fix=lambda: pkg.install("rsyslog"),
))
