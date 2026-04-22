# Show HN draft

## Title (use exactly — HN scoring favors short, no clickbait)

```
Show HN: Linux Security Suite – CIS hardening with one-command rollback
```

(64 chars. Stays under HN's title-length penalty.)

## URL field

```
https://linuxsecuritysuite.com
```

## Post body

```
I built this because every CIS hardening tool I tried fell into one of two camps: free GitHub scripts with no rollback, no report, no support; or enterprise platforms with seat licenses that start at $20k. Nothing in between.

The Linux Security Suite is one binary that:

- audits 204 CIS Benchmark controls (Debian 12 Level 1 Server profile, RHEL coming) in about two minutes, read-only
- applies the auto-fix for failures with one command, recording every change in a rollback journal
- gives you a printable HTML report you can hand to a client or auditor
- and `lss rollback --last` reverses everything in the opposite order it was applied — file-restore first, then runtime undo, all without shell=True

Why I'm posting it: I just finished a substantial security pass on it. The earlier version had two real bugs that made me uncomfortable shipping — XSS in the HTML report (hostname interpolated raw) and shell injection in the rollback engine (undo commands stored as f-string shell strings). Both are fixed in v0.3.0. The undo storage is now `list[list[str]]` argv that runs with `shell=False`, the rollback engine refuses to execute legacy string undos, and there's a regression test that confirms a malicious `touch /tmp/sentinel` legacy undo is not executed.

Honest tradeoffs:
- 79 of the 204 controls are audit-only — I don't auto-fix things where the safe fix is site-specific (which UID 0 accounts to remove, what to do with world-writable files you might actually need world-writable).
- It's commercial. $149 single host, $499 up to 25 hosts (Pro), $1,499 unlimited (Enterprise). Source is readable for evaluation. Free CIS scripts exist; this one is for ops teams who'd rather pay than maintain a homegrown one.
- v1.0 ships when I have an attorney-drafted EULA and the per-control test suite is fleshed out. v0.3 is beta, sold with that disclaimer.

Architecture in three sentences: a control registry of dataclass `Control(id, title, section, check, fix)`; fixes return `RollbackEntry` records that the harden engine writes to a journal under `/var/log/lss/journal/`; rollback replays the journal in reverse, restoring file backups via `shutil.copy2` and running argv-list undos with `shell=False`. The whole thing is ~5k lines of Python plus the rich library.

Repo: https://github.com/<USERNAME>/lss
Landing page + pricing: https://linuxsecuritysuite.com

Happy to answer anything about the architecture, the threat model, or why I picked the choices I did.
```

## Posting tips

- **Best window**: Tuesday or Wednesday, 9:00–11:00am ET. Avoid Mondays (PM), Fridays, and weekends.
- **Don't ask for upvotes**, anywhere. HN detects vote rings and will downrank or shadow-ban.
- **Reply to every top-level comment in the first 90 minutes.** HN ranking heavily weights early engagement velocity.
- **Don't be defensive** about the price. Anyone who wants free has Lynis, OpenSCAP, and the CIS PDF.
- **The architecture-sentence paragraph** is the part that converts engineers to "huh, this person knows what they're doing." Don't cut it for length.
- If you get flagged or downranked, don't repost — reach out via hn@ycombinator.com with one polite sentence.

## What to do BEFORE posting

1. Confirm the GitHub repo URL is live and the README renders well.
2. Confirm the landing page Buy buttons work (Gumroad URLs wired up).
3. Have a terminal recording or screenshot of `lss audit` ready in case someone asks.
4. Be at your computer for the next 4 hours. Comment velocity > upvote count for ranking.
