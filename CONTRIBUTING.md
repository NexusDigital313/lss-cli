<!--
  Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
  Proprietary and Confidential.

  Unauthorized reproduction, copying, modification, distribution,
  redistribution, publication, reverse engineering, decompilation, or
  disassembly of this file, in whole or in part, via any medium, is
  strictly prohibited without explicit prior written authorization.
-->

# Contributing to LSS

Pull requests are welcome for bug fixes and documentation improvements. New
controls and broader feature work require prior discussion — open an issue
first.

## Code rules

These are non-negotiable. CI enforces them; reviewers will reject PRs that
break any of them.

### No `shell=True`

Every external command is a `subprocess.run` argv list. Never a shell string.
This is enforced by regression test (see `tests/test_smoke.py::test_no_shell_true`).

```python
# Good
subprocess.run(["systemctl", "restart", "auditd"], check=True)

# Bad
subprocess.run("systemctl restart auditd", shell=True, check=True)
```

### Backup before modify

Every fix that edits an existing file must call `journal.backup_file(path)`
before writing. The backup is stored under `/var/log/lss/journal/backups/<run-id>/`
and is what `lss rollback` restores from.

```python
from lss.lib import journal

def _fix_example() -> list[RollbackEntry]:
    conf = Path("/etc/some/config")
    bkp = journal.backup_file(str(conf))   # take backup first
    # ... edit conf ...
    return [RollbackEntry(action="...", path=str(conf), backup=bkp, undo=...)]
```

### Argv-list undos

`RollbackEntry.undo` is a list of argv lists, never a shell string. The
rollback engine refuses to execute string-form undos at all (legacy 0.2-era
journals get a warning, not a shell invocation). This is enforced by
`tests/test_smoke.py::test_no_undo_strings_in_registry`.

```python
# Good
undo=[["rm", "-f", "/etc/lss-foo.conf"]]

# Bad
undo=["rm -f /etc/lss-foo.conf"]   # string form — refused at rollback time
```

### Refuse, don't cosmetic-pass

If a fix's prerequisite is missing (config file absent, helper binary not
installed), `raise RuntimeError` with an actionable error message.
**Do not** silently `return []` — the harden engine will count that as
"Applied" and the post-fix audit will then re-fail, leaving the operator
confused.

```python
# Good
def _fix_example() -> list[RollbackEntry]:
    conf = Path("/etc/some/config")
    if not conf.exists():
        raise RuntimeError(
            "Config file not found at /etc/some/config — install foo first. "
            "On Debian/Ubuntu: `sudo apt install foo`."
        )
    # ... do the work ...
```

### Idempotent fixes

Re-running a fix on a host that's already in the desired state must be
a no-op. Don't append the same line to a config file twice; match-and-replace.

```python
lines = conf.read_text().splitlines(keepends=True)
found = False
for i, line in enumerate(lines):
    if re.match(rf"^\s*#?\s*{key}\s*=", line):
        lines[i] = f"{key} = {value}\n"
        found = True
        break
if not found:
    lines.append(f"{key} = {value}\n")
```

## Tests

Run the suite locally before submitting:

```bash
python3 -m venv ~/lss-venv
~/lss-venv/bin/pip install -e ".[dev]"
~/lss-venv/bin/pytest tests/ -x
```

The suite is non-root and side-effect free; CI runs it on every push.
Per-control on-system effects (the actual hardening behavior) are covered
by the pre-launch test plan, not unit tests.

If you fix a bug, add a regression test that would have caught it.

## Commit style

One concern per commit. Squash trivial fixups before submitting. The first
line is a short imperative ("Fix 5.4.5 cosmetic-fail on /etc/profile.d
files"); the body explains *why*, since the *what* is in the diff.

## Reporting bugs

For non-security bugs, email `blckgrndntional313proton.me@proton.me` with:
- Distro + version (`cat /etc/os-release`)
- LSS version (`lss --version`)
- The exact command you ran and its full output
- A relevant excerpt from `/var/log/lss/audit-*.json` if applicable

For security issues, see [SECURITY.md](SECURITY.md). Do not disclose
publicly until coordinated.
