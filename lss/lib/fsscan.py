# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file,
# via any medium, is strictly prohibited without explicit written authorization.

"""Run a `find` predicate across every local mounted filesystem.

`find / -xdev` stays on the root filesystem, so a separate /home, /var or
/tmp (tmpfs included) was never scanned. The CIS audit runs find per local
mount point (`df --local`); this does the same from /proc/self/mounts,
skipping network and pseudo filesystems, with -xdev on each mount point.
"""

from __future__ import annotations

import subprocess
import time

PROC_MOUNTS = "/proc/self/mounts"

# Pseudo / virtual filesystems with no on-disk files worth auditing, plus
# read-only media and vfat (no Unix modes), as the CIS audit excludes them.
PSEUDO_FS = {
    "proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2", "securityfs",
    "pstore", "bpf", "debugfs", "tracefs", "configfs", "fusectl", "mqueue",
    "hugetlbfs", "autofs", "binfmt_misc", "efivarfs", "selinuxfs",
    "rpc_pipefs", "nsfs", "nfsd", "squashfs", "iso9660", "udf", "vfat",
    "ramfs", "overlay",
}
NETWORK_FS = {
    "nfs", "nfs4", "cifs", "smb3", "smbfs", "ncpfs", "afs", "ceph",
    "glusterfs", "9p", "lustre", "gfs2", "ocfs2", "davfs", "sshfs",
}

_PRUNE = ["-not", "-path", "/proc/*", "-not", "-path", "/sys/*"]


def _unescape(field: str) -> str:
    # /proc/mounts escapes space, tab, newline and backslash as \ooo.
    out, i = [], 0
    while i < len(field):
        if field[i] == "\\" and i + 3 < len(field) and field[i + 1:i + 4].isdigit():
            out.append(chr(int(field[i + 1:i + 4], 8)))
            i += 4
        else:
            out.append(field[i])
            i += 1
    return "".join(out)


def local_mounts() -> list[str] | None:
    """Local mount points to scan, root first, or None if unreadable."""
    try:
        with open(PROC_MOUNTS) as fh:
            text = fh.read()
    except OSError:
        return None
    seen: list[str] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        mnt, fstype = _unescape(parts[1]), parts[2]
        base = fstype.split(".", 1)[0]
        if fstype in PSEUDO_FS or fstype in NETWORK_FS or base == "fuse":
            # fuse.* (sshfs, gvfs, rclone...) is treated as non-local.
            if not (mnt == "/" and fstype == "overlay"):  # container root
                continue
        if mnt.startswith(("/proc", "/sys")) or mnt in seen:
            continue
        seen.append(mnt)
    if "/" in seen:
        seen.remove("/")
    return ["/"] + seen


def find_all(predicate: list[str], timeout: int = 120) -> tuple[list[str], str]:
    """Run `find <mnt> -xdev <predicate>` on every local mount.

    Returns (paths, note). `note` is "" for a complete scan, or says what was
    not covered (timed-out mounts, or mounts unreadable so only / was scanned).
    The overall time budget is `timeout` seconds, as for the old single find.
    Raises FileNotFoundError if find is missing.
    """
    mounts = local_mounts()
    notes = []
    if mounts is None:
        mounts = ["/"]
        notes.append("mount table unreadable; scanned / only")
    deadline = time.monotonic() + timeout
    found: list[str] = []
    seen: set[str] = set()
    timed_out: list[str] = []
    for mnt in mounts:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out.append(mnt)
            continue
        try:
            r = subprocess.run(
                ["find", mnt, "-xdev", *predicate, *_PRUNE],
                capture_output=True, text=True, timeout=remaining,
            )
        except subprocess.TimeoutExpired as e:
            timed_out.append(mnt)
            out = e.stdout or ""
            if isinstance(out, bytes):
                out = out.decode(errors="replace")
        else:
            out = r.stdout
        for f in out.splitlines():
            if f and f not in seen:
                seen.add(f)
                found.append(f)
    if timed_out:
        notes.append("scan timed out on " + ", ".join(timed_out))
    return found, "; ".join(notes)
