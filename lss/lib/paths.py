"""User-facing artifact path resolution.

LSS runs as root (audit/harden need it), but the operator who invoked
`sudo lss ...` is the human who needs to read the HTML report. Reports
must therefore land somewhere readable by the invoking user — not in
/var/log/lss/, which is intentionally root-only for tamper-evident
JSON audit logs.
"""

from __future__ import annotations

import os
import pwd
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class InvokingUser:
    uid: int
    gid: int
    name: str
    home: Path


def resolve_invoking_user() -> Optional[InvokingUser]:
    """Identify the human who invoked the current process.

    When running under `sudo`, env carries SUDO_UID/SUDO_GID/SUDO_USER.
    When running as a real login user (not via sudo), use the current uid.
    When running as root with no calling user (cron, systemd unit, container
    entrypoint), return None — caller should fall back to /var/log/lss/.
    """
    sudo_uid = os.environ.get("SUDO_UID")
    sudo_gid = os.environ.get("SUDO_GID")
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_uid and sudo_gid and sudo_user and sudo_user != "root":
        try:
            pw = pwd.getpwnam(sudo_user)
            # Take uid/gid from the passwd DB, NOT the env SUDO_UID/SUDO_GID,
            # which are attacker-spoofable (e.g. SUDO_USER=lowpriv with a
            # mismatched SUDO_UID would chown reports to an arbitrary uid).
            return InvokingUser(pw.pw_uid, pw.pw_gid, sudo_user, Path(pw.pw_dir))
        except (KeyError, ValueError):
            return None

    if os.geteuid() != 0:
        try:
            pw = pwd.getpwuid(os.geteuid())
            return InvokingUser(pw.pw_uid, pw.pw_gid, pw.pw_name, Path(pw.pw_dir))
        except KeyError:
            return None

    return None


def default_html_report_dir() -> Path:
    """Return the directory where HTML reports should be written by default.

    Precedence:
      1. Invoking user's XDG data dir: $HOME/.local/share/lss/reports
      2. Fallback for true-root contexts (cron, container): /var/log/lss
    """
    user = resolve_invoking_user()
    if user is not None:
        return user.home / ".local" / "share" / "lss" / "reports"
    return Path("/var/log/lss")


def ensure_report_dir(path: Path) -> Path:
    """Create the report directory with correct ownership.

    Records which ancestors did not exist before we touched them, then
    creates the tree and chowns only those new directories. Pre-existing
    paths (the user's $HOME, ~/.local, possibly ~/.local/share) are left
    untouched — we never alter ownership of dirs we didn't create.
    """
    user = resolve_invoking_user()
    created: list[Path] = []
    cur = path
    while not cur.exists() and cur != cur.parent:
        created.append(cur)
        cur = cur.parent
    path.mkdir(parents=True, exist_ok=True)

    if user is None or os.geteuid() != 0:
        return path
    for p in created:
        try:
            os.chown(p, user.uid, user.gid, follow_symlinks=False)
        except (PermissionError, FileNotFoundError):
            pass
    return path


def chown_to_invoking_user(path: Path) -> None:
    """Chown a single file/dir to the invoking user, mode 0640.

    No-op when not running as root or when there's no invoking user.
    Failures are silent — the file is already written; ownership is a
    convenience, not a correctness requirement.
    """
    user = resolve_invoking_user()
    if user is None or os.geteuid() != 0:
        return
    # Operate on an O_NOFOLLOW fd, never a path. The report dir lives under the
    # invoking user's own $HOME, so a path-based chown/chmod could be aimed at a
    # symlink to a root-owned file (e.g. /etc/shadow) — a local privesc. Opening
    # O_NOFOLLOW refuses symlinks (ELOOP) and closes the TOCTOU window.
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return
    try:
        os.fchown(fd, user.uid, user.gid)
        os.fchmod(fd, 0o640)
    except OSError:
        pass
    finally:
        os.close(fd)


def file_uri(path: Path) -> str:
    """Render a Path as a clickable file:// URL for terminal output."""
    return "file://" + str(path.resolve())


def open_in_browser(path: Path) -> bool:
    """Open `path` in the invoking user's default browser.

    When running under sudo we drop privileges so xdg-open finds the
    user's session bus / desktop environment, not root's empty one.
    Returns True on apparent success, False otherwise. Browser errors
    after launch (sandbox warnings, GLib chatter) are not our concern.
    """
    if not shutil.which("xdg-open"):
        return False

    user = resolve_invoking_user()
    cmd = ["xdg-open", str(path)]
    env = os.environ.copy()

    try:
        if user is not None and os.geteuid() == 0:
            # Drop privileges and rebuild a sane session env for the human.
            env["HOME"] = str(user.home)
            env["USER"] = user.name
            env["LOGNAME"] = user.name
            # Reuse DBus / display from the invoking sudo session if present.
            for key in ("DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR",
                        "DBUS_SESSION_BUS_ADDRESS", "XAUTHORITY"):
                if key not in env and os.environ.get(key):
                    env[key] = os.environ[key]
            if "XDG_RUNTIME_DIR" not in env:
                env["XDG_RUNTIME_DIR"] = f"/run/user/{user.uid}"
            subprocess.Popen(
                cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                preexec_fn=lambda: (os.setgid(user.gid), os.setuid(user.uid)),
                start_new_session=True,
            )
        else:
            subprocess.Popen(
                cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        return True
    except (OSError, PermissionError):
        return False
