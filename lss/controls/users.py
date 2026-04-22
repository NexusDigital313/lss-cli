"""CIS Section 6.2 — User and Group Settings."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from lss.lib.registry import Control, CheckResult, RollbackEntry, register


# ---- CIS 6.2.3: Ensure all groups in /etc/passwd exist in /etc/group ----

def _check_groups_exist() -> CheckResult:
    import grp
    passwd = Path("/etc/passwd")
    if not passwd.exists():
        return CheckResult("warn", "/etc/passwd not found")
    group_gids = set()
    try:
        for g in grp.getgrall():
            group_gids.add(g.gr_gid)
    except Exception:
        return CheckResult("warn", "could not read /etc/group")

    missing = []
    for line in passwd.read_text().splitlines():
        parts = line.split(":")
        if len(parts) >= 4:
            try:
                gid = int(parts[3])
                if gid not in group_gids:
                    missing.append(f"{parts[0]}(gid={gid})")
            except ValueError:
                continue
    if not missing:
        return CheckResult("pass")
    return CheckResult("fail", f"users with non-existent group: {', '.join(missing[:5])}")


register(Control(
    id="6.2.3",
    title="Ensure all groups in /etc/passwd exist in /etc/group",
    section="users",
    check=_check_groups_exist,
    fix=None,  # Requires human review
))


# ---- CIS 6.2.4: Ensure no duplicate UIDs exist ----

def _check_duplicate_uids() -> CheckResult:
    passwd = Path("/etc/passwd")
    if not passwd.exists():
        return CheckResult("warn", "/etc/passwd not found")
    uid_map: dict[str, list[str]] = {}
    for line in passwd.read_text().splitlines():
        parts = line.split(":")
        if len(parts) >= 3:
            uid = parts[2]
            uid_map.setdefault(uid, []).append(parts[0])
    dupes = {uid: users for uid, users in uid_map.items() if len(users) > 1}
    if not dupes:
        return CheckResult("pass")
    detail = "; ".join(f"UID {uid}: {','.join(users)}" for uid, users in list(dupes.items())[:3])
    return CheckResult("fail", f"duplicate UIDs: {detail}")


register(Control(
    id="6.2.4",
    title="Ensure no duplicate UIDs exist",
    section="users",
    check=_check_duplicate_uids,
    fix=None,
))


# ---- CIS 6.2.5: Ensure no duplicate GIDs exist ----

def _check_duplicate_gids() -> CheckResult:
    group = Path("/etc/group")
    if not group.exists():
        return CheckResult("warn", "/etc/group not found")
    gid_map: dict[str, list[str]] = {}
    for line in group.read_text().splitlines():
        parts = line.split(":")
        if len(parts) >= 3:
            gid = parts[2]
            gid_map.setdefault(gid, []).append(parts[0])
    dupes = {gid: groups for gid, groups in gid_map.items() if len(groups) > 1}
    if not dupes:
        return CheckResult("pass")
    detail = "; ".join(f"GID {gid}: {','.join(groups)}" for gid, groups in list(dupes.items())[:3])
    return CheckResult("fail", f"duplicate GIDs: {detail}")


register(Control(
    id="6.2.5",
    title="Ensure no duplicate GIDs exist",
    section="users",
    check=_check_duplicate_gids,
    fix=None,
))


# ---- CIS 6.2.6: Ensure no duplicate user names exist ----

def _check_duplicate_usernames() -> CheckResult:
    passwd = Path("/etc/passwd")
    if not passwd.exists():
        return CheckResult("warn", "/etc/passwd not found")
    names: dict[str, int] = {}
    for line in passwd.read_text().splitlines():
        name = line.split(":")[0]
        names[name] = names.get(name, 0) + 1
    dupes = [n for n, c in names.items() if c > 1]
    if not dupes:
        return CheckResult("pass")
    return CheckResult("fail", f"duplicate usernames: {', '.join(dupes[:5])}")


register(Control(
    id="6.2.6",
    title="Ensure no duplicate user names exist",
    section="users",
    check=_check_duplicate_usernames,
    fix=None,
))


# ---- CIS 6.2.7: Ensure no duplicate group names exist ----

def _check_duplicate_groupnames() -> CheckResult:
    group = Path("/etc/group")
    if not group.exists():
        return CheckResult("warn", "/etc/group not found")
    names: dict[str, int] = {}
    for line in group.read_text().splitlines():
        name = line.split(":")[0]
        names[name] = names.get(name, 0) + 1
    dupes = [n for n, c in names.items() if c > 1]
    if not dupes:
        return CheckResult("pass")
    return CheckResult("fail", f"duplicate group names: {', '.join(dupes[:5])}")


register(Control(
    id="6.2.7",
    title="Ensure no duplicate group names exist",
    section="users",
    check=_check_duplicate_groupnames,
    fix=None,
))


# ---- CIS 6.2.8: Ensure root PATH integrity ----

def _check_root_path() -> CheckResult:
    path = os.environ.get("PATH", "")
    issues = []
    for entry in path.split(":"):
        if not entry or entry == ".":
            issues.append("empty or '.' in PATH")
            continue
        p = Path(entry)
        if not p.is_absolute():
            issues.append(f"relative path: {entry}")
            continue
        if p.exists():
            st = p.stat()
            if st.st_mode & stat.S_IWGRP:
                issues.append(f"group-writable: {entry}")
            if st.st_mode & stat.S_IWOTH:
                issues.append(f"world-writable: {entry}")
    if not issues:
        return CheckResult("pass")
    return CheckResult("fail", "; ".join(issues[:3]))


register(Control(
    id="6.2.8",
    title="Ensure root PATH integrity",
    section="users",
    check=_check_root_path,
    fix=None,  # PATH is set by shell config — too many sources to auto-fix safely
))


# ---- CIS 6.2.9: Ensure all users' home directories exist ----

def _check_home_dirs_exist() -> CheckResult:
    passwd = Path("/etc/passwd")
    if not passwd.exists():
        return CheckResult("warn", "/etc/passwd not found")
    missing = []
    for line in passwd.read_text().splitlines():
        parts = line.split(":")
        if len(parts) >= 6:
            user, uid, home = parts[0], parts[2], parts[5]
            try:
                if int(uid) < 1000 and user != "root":
                    continue  # skip system accounts
            except ValueError:
                continue
            if home and not Path(home).exists():
                missing.append(f"{user}({home})")
    if not missing:
        return CheckResult("pass")
    return CheckResult("fail", f"missing home dirs: {', '.join(missing[:5])}")


register(Control(
    id="6.2.9",
    title="Ensure all users' home directories exist",
    section="users",
    check=_check_home_dirs_exist,
    fix=None,  # mkhomedir_helper or manual
))


# ---- CIS 6.2.10: Ensure users own their home directories ----

def _check_home_ownership() -> CheckResult:
    passwd = Path("/etc/passwd")
    if not passwd.exists():
        return CheckResult("warn", "/etc/passwd not found")
    issues = []
    for line in passwd.read_text().splitlines():
        parts = line.split(":")
        if len(parts) >= 6:
            user, uid_str, home = parts[0], parts[2], parts[5]
            try:
                uid = int(uid_str)
                if uid < 1000 and user != "root":
                    continue
            except ValueError:
                continue
            p = Path(home)
            if p.exists():
                st = p.stat()
                if st.st_uid != uid:
                    issues.append(f"{user}: {home} owned by uid {st.st_uid}")
    if not issues:
        return CheckResult("pass")
    return CheckResult("fail", "; ".join(issues[:3]))


register(Control(
    id="6.2.10",
    title="Ensure users own their home directories",
    section="users",
    check=_check_home_ownership,
    fix=None,
))


# ---- CIS 6.2.11: Ensure users' home directory permissions are 750 or more restrictive ----

def _check_home_perms() -> CheckResult:
    passwd = Path("/etc/passwd")
    if not passwd.exists():
        return CheckResult("warn", "/etc/passwd not found")
    issues = []
    for line in passwd.read_text().splitlines():
        parts = line.split(":")
        if len(parts) >= 6:
            user, uid_str, home = parts[0], parts[2], parts[5]
            try:
                uid = int(uid_str)
                if uid < 1000 and user != "root":
                    continue
            except ValueError:
                continue
            p = Path(home)
            if p.exists():
                mode = stat.S_IMODE(p.stat().st_mode)
                if mode & 0o027:  # more permissive than 750
                    issues.append(f"{user}: {home} mode={oct(mode)}")
    if not issues:
        return CheckResult("pass")
    return CheckResult("warn", "; ".join(issues[:3]))


register(Control(
    id="6.2.11",
    title="Ensure users' home directory permissions are 750 or more restrictive",
    section="users",
    check=_check_home_perms,
    fix=None,  # Too risky to auto-chmod home dirs
))


# ---- CIS 6.2.12: Ensure no users have .forward files ----

def _check_dot_forward() -> CheckResult:
    passwd = Path("/etc/passwd")
    if not passwd.exists():
        return CheckResult("warn", "/etc/passwd not found")
    found = []
    for line in passwd.read_text().splitlines():
        parts = line.split(":")
        if len(parts) >= 6:
            user, home = parts[0], parts[5]
            fwd = Path(home) / ".forward"
            if fwd.exists():
                found.append(user)
    if not found:
        return CheckResult("pass")
    return CheckResult("fail", f"users with .forward: {', '.join(found[:5])}")


register(Control(
    id="6.2.12",
    title="Ensure no users have .forward files",
    section="users",
    check=_check_dot_forward,
    fix=None,
))


# ---- CIS 6.2.13: Ensure no users have .netrc files ----

def _check_dot_netrc() -> CheckResult:
    passwd = Path("/etc/passwd")
    if not passwd.exists():
        return CheckResult("warn", "/etc/passwd not found")
    found = []
    for line in passwd.read_text().splitlines():
        parts = line.split(":")
        if len(parts) >= 6:
            user, home = parts[0], parts[5]
            netrc = Path(home) / ".netrc"
            if netrc.exists():
                found.append(user)
    if not found:
        return CheckResult("pass")
    return CheckResult("fail", f"users with .netrc: {', '.join(found[:5])}")


register(Control(
    id="6.2.13",
    title="Ensure no users have .netrc files",
    section="users",
    check=_check_dot_netrc,
    fix=None,
))


# ---- CIS 6.2.14: Ensure no users have .rhosts files ----

def _check_dot_rhosts() -> CheckResult:
    passwd = Path("/etc/passwd")
    if not passwd.exists():
        return CheckResult("warn", "/etc/passwd not found")
    found = []
    for line in passwd.read_text().splitlines():
        parts = line.split(":")
        if len(parts) >= 6:
            user, home = parts[0], parts[5]
            rhosts = Path(home) / ".rhosts"
            if rhosts.exists():
                found.append(user)
    if not found:
        return CheckResult("pass")
    return CheckResult("fail", f"users with .rhosts: {', '.join(found[:5])}")


register(Control(
    id="6.2.14",
    title="Ensure no users have .rhosts files",
    section="users",
    check=_check_dot_rhosts,
    fix=None,
))


# ---- CIS 6.2.15: Ensure all users have a valid shell ----

def _check_valid_shells() -> CheckResult:
    shells_file = Path("/etc/shells")
    if not shells_file.exists():
        return CheckResult("warn", "/etc/shells not found")
    valid_shells = set()
    for line in shells_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            valid_shells.add(line)
    # nologin and false are acceptable for service accounts
    valid_shells.add("/usr/sbin/nologin")
    valid_shells.add("/bin/false")
    valid_shells.add("/sbin/nologin")

    passwd = Path("/etc/passwd")
    issues = []
    for line in passwd.read_text().splitlines():
        parts = line.split(":")
        if len(parts) >= 7:
            user, uid_str, shell = parts[0], parts[2], parts[6]
            try:
                uid = int(uid_str)
                if uid < 1000 and user != "root":
                    continue
            except ValueError:
                continue
            if shell and shell not in valid_shells:
                issues.append(f"{user}: {shell}")
    if not issues:
        return CheckResult("pass")
    return CheckResult("warn", f"invalid shells: {'; '.join(issues[:3])}")


register(Control(
    id="6.2.15",
    title="Ensure all users have a valid shell",
    section="users",
    check=_check_valid_shells,
    fix=None,
))


# ---- CIS 5.4.2: Ensure no accounts have empty passwords ----

def _check_empty_passwords() -> CheckResult:
    shadow = Path("/etc/shadow")
    if not shadow.exists():
        return CheckResult("warn", "/etc/shadow not found")
    empty = []
    for line in shadow.read_text().splitlines():
        parts = line.split(":")
        if len(parts) >= 2:
            user, pw = parts[0], parts[1]
            if pw == "" or pw == "!":
                # "!" means locked, which is fine
                if pw == "":
                    empty.append(user)
    if not empty:
        return CheckResult("pass")
    return CheckResult("fail", f"accounts with empty password: {', '.join(empty[:5])}")


register(Control(
    id="5.4.2",
    title="Ensure no accounts have empty passwords",
    section="auth",
    check=_check_empty_passwords,
    fix=None,  # Requires human decision — lock or set password
))


# ---- CIS 5.4.3: Ensure default group for root is GID 0 ----

def _check_root_default_group() -> CheckResult:
    passwd = Path("/etc/passwd")
    if not passwd.exists():
        return CheckResult("warn", "/etc/passwd not found")
    for line in passwd.read_text().splitlines():
        parts = line.split(":")
        if parts[0] == "root" and len(parts) >= 4:
            if parts[3] == "0":
                return CheckResult("pass")
            return CheckResult("fail", f"root default group GID={parts[3]}, expected: 0")
    return CheckResult("fail", "root not found in /etc/passwd")


register(Control(
    id="5.4.3",
    title="Ensure default group for the root account is GID 0",
    section="auth",
    check=_check_root_default_group,
    fix=None,
))