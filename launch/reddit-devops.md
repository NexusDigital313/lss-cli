# r/devops draft

## Title

```
LSS: a one-binary CIS hardening + audit + rollback tool for Debian/Ubuntu/Kali
```

## Body

```
TL;DR: 204 CIS Benchmark controls, three subcommands (audit / harden / rollback), every change journaled and reversible, $149 single-host or $499 for up to 25 hosts.

The problem I built it for: small ops teams that need to demonstrate CIS compliance to a customer or auditor and don't want to either (a) maintain a homegrown bash hardening script that nobody trusts to roll back, or (b) buy a six-figure GRC platform.

The architecture:

- Control registry of `dataclass Control(id, title, section, check, fix)` — 204 of them across 19 modules.
- `lss audit` runs every check read-only in ~2 min, writes results to /var/log/lss/audit-<ts>.json.
- `lss harden --confirm` runs the fixes for failing controls, each fix returns `RollbackEntry(action, undo: list[list[str]], path, backup)` records appended to a per-run journal.
- `lss harden --dry-run` shows what would change without applying.
- `lss rollback --last` (or `--run-id <id>` or `--control <id>`) replays the journal in reverse: shutil.copy2 the backup over the live file (with mtime check + warning if it's been modified since), then run any argv-list undos with shell=False.
- `lss report` renders the last audit as a printable HTML page (escaped properly — `html.escape()` everywhere, learned the hard way).

What's interesting from an ops perspective:

- iptables changes are persisted to /etc/iptables/rules.v4 via iptables-save automatically, so they survive reboot.
- Mount remounts merge with existing options instead of stripping them — no more losing your `errors=continue` because you wanted `noexec` on /var/tmp.
- Auditd rules register both `arch=b64` AND `arch=b32` variants where applicable.
- Every harden + rollback emits LOG_AUTHPRIV syslog events for forensic trail.
- Pre-flight warning before harden lists destructive service-disable controls (dovecot, postfix, apache, etc.) so you can ctrl-C if you're actually using them.

CIS alignment: full Debian 12 v1.0.0 Level 1 Server profile, plus 3 LSS-namespaced custom controls (LSS-001/002/003) clearly labeled as non-CIS so anyone cross-referencing the official PDF doesn't get surprised.

What v1.0 ships with: per-control test coverage across every control (989 passing, 58 skipped) on top of the engine smoke + rollback regression tests. Still on the roadmap and stated plainly: config-drift detection, broader distro-aware skips, RHEL/Rocky support (v1.1), and an attorney-drafted EULA for the Enterprise tier — the current LICENSE is a defensible placeholder.

Source is readable for evaluation — git clone + run the audit without buying anything. Pay only if you want the harden/rollback/report subcommands in production.

Repo: https://github.com/<USERNAME>/lss
Landing page: https://linuxsecuritysuite.com
```

## Notes

- r/devops will pick at the architecture more than the marketing. Lean into the technical detail.
- Expected questions: "How does it handle config drift?" (it doesn't yet — a v1.1 roadmap item), "Why not Ansible/Salt?" (LSS is the *what*, not the *how* — Ansible can call it), "Does it work on RHEL?" (planned for v1.1).
