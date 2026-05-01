# Changelog

All notable changes to LSS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-04-30

Initial public release.

### What it does

- 206 hardening controls (201 CIS Benchmark-aligned + LSS-001..LSS-005 extras).
- Three commands: `audit` (read-only), `harden` (apply fixes), `rollback` (reverse a previous harden run by run-id, last-run, or single control).
- HTML reports with optional baseline-delta mode.

### Safety architecture

- **Argv-list rollback journal.** Every fix records its undo as a `subprocess.run` argv list, never a shell string. Legacy string-form undos are refused, not executed. `shell=True` is forbidden in the codebase, enforced by regression test.
- **Backup-before-modify.** Every file edit snapshots the original first; rollback restores from the backup. When the same file is modified by multiple controls in one run, each backup is uniquely numbered (`.NNNN` counter) so the chain rebuilds the original state exactly in reverse.
- **Reverse-order rollback.** Outer loop walks controls in reverse application order, inner loop walks each control's actions in reverse — the only correct order when N controls modified the same file.
- **Refuses to silently no-op.** Fixes that depend on missing prerequisites (e.g. auditd not installed) raise `RuntimeError` with an actionable install command rather than returning empty and being counted as "Applied".

### Status vocabulary

Audit results use five status categories:

- `pass` — control is satisfied.
- `warn` — soft non-compliance the operator should review.
- `fail` — non-compliant; `harden` will attempt to fix.
- `manual` — non-compliant **and** auto-fix is intentionally not provided. Used where automated remediation is unsafe (PAM stack edits — lockout risk) or requires explicit opt-in (audit log volume). Reported as a separate bucket from `fail` so the operator can distinguish "broken" from "needs me to take a step." Three controls ship as `manual`: CIS 5.3.2 (pam_faillock stack enable), CIS 5.3.3 (pam_pwhistory stack enable), LSS-005 (forensic-grade execve auditing).
- `skip` — control not applicable on this system.

### Two-score audit summary

- **Hardened score** = `passes / (pass + warn + fail)` — what `harden` auto-applied.
- **Compliance score** = `passes / (pass + warn + fail + manual)` — full CIS posture.

The gap between the two scores is exactly the `manual` controls. Manuals do not count against the hardened score, because punishing the score for LSS's own opt-in restraint creates the wrong incentive.

### HTML report user-home output

- HTML reports default to `~/.local/share/lss/reports/report-<timestamp>.html` of the
  invoking user (resolved via `SUDO_UID`/`SUDO_GID`/`SUDO_USER`), written mode
  `0640` and chowned to that user.
- `audit` auto-emits an HTML report alongside the JSON audit log unless
  `--no-report` is passed. JSON continues to land in `/var/log/lss/`
  (`0750 root:root`) so the tamper-evident audit trail stays root-only.
- New flags: `audit --open`, `audit --no-report`, `report --open`. `--open`
  drops privileges (setgid/setuid back to the invoking user) before invoking
  `xdg-open` so the user's session bus / display are reachable.
- True-root contexts with no invoking user (cron, systemd unit, container
  entrypoint) fall back to `/var/log/lss/` for the HTML output.

### Distro support

- Debian 12 / Kali / Ubuntu: full coverage. 172 of 206 controls auto-fixable; the remaining 34 are audit-only by design (`manual` status) or require operator policy decisions.
- RHEL / Fedora / Rocky / Alma: audit coverage complete; auto-fix coverage partial. Full parity targeted for a future release.
- Bundled `pam_faillock` profile installed at `/usr/share/pam-configs/faillock` for stock Debian/Ubuntu hosts that don't ship one in `libpam-runtime`. Conservative defaults: `Default: no` (operator opts in via `pam-auth-update --enable`); `[default=ignore]` so a missing or broken `pam_faillock.so` cannot break the auth chain.

### Known limitations

- LSS does not yet take a global lock — do not run two `lss harden` in parallel.
