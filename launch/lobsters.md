# Lobsters draft

## Title

```
Linux Security Suite — CIS hardening + audit + reversible rollback in one Python CLI
```

## URL

```
https://linuxsecuritysuite.com
```

## Tags

```
linux, security, release
```

## Suggested invitation comment (Lobsters requires the submitter to comment first if it's their own work)

```
Author here. Built this because every CIS hardening tool I tried was either a free script with no rollback or an enterprise platform priced for Fortune 500.

Three things I think are worth a Lobsters audience:

1. Rollback design. Every fix returns a `RollbackEntry(action, undo: list[list[str]], path, backup)`. The harden engine takes a backup before the fix runs, appends the entry to a per-run journal under /var/log/lss/journal/, and writes everything atomically (temp + fsync + os.replace). Rollback restores from backup first (with an mtime check that warns if the file's been modified since), then runs argv-list undos with shell=False. The earlier version stored undos as shell strings interpolated via f-strings and ran them with shell=True — that was a real shell-injection bug, fixed in v0.3, with a regression test that confirms a malicious `touch /tmp/sentinel` legacy undo is not executed.

2. CIS ID honesty. I caught myself mislabeling 6 custom controls as if they were CIS, and one off-by-one (5.4.1.5 doesn't exist in CIS Debian 12 v1.0.0; the inactive-lock control is 5.4.1.4). Fixed and renamed to LSS-001/002/003 namespace so anyone cross-referencing the official PDF doesn't get surprised.

3. sshd Match block awareness. `sshd -T` resolves Match against the invoking user, so a control may pass for root and still be wrong for everyone else. There's a `setting_in_global_scope()` helper that reads the actual config files (including /etc/ssh/sshd_config.d/*) and warns when a value is correct but only via Match scope. Used in PermitRootLogin so far; planned for the rest in v0.3.x.

Commercial — $149/$499/$1,499. Source readable for evaluation. Honest tradeoffs in the README and the v0.3 changelog.
```

## Notes

- Lobsters audience is small but very technical. Architecture details outrank marketing every time.
- The Lobsters mods will tag-edit if needed. Don't argue with them.
- A Lobsters front-page hit is ~500 visitors but conversion is 2-5x HN.
