# Changelog

All notable changes to LSS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

False-pass sweep across the control set: checks that reported a control as compliant on evidence that did not prove it was enforced.

### Safety

- **GDM controls no longer pass vacuously.** GDM detection ran `dpkg-query -W` without `-f=${Status}`, so it never saw GDM as installed on Debian and all eight 1.8.x controls reported "GDM not installed". 1.8.2–1.8.4 now require the key's own uncommented value instead of `true` appearing anywhere in the file; 1.8.5 and 1.8.7 require a real lock on a key that governs the control (a lock on `automount-open` alone no longer satisfies 1.8.7). 1.8.2 also reads the file `lss harden` writes, so harden can turn it green on Debian.
- **Commented-out config no longer counts.** 5.3.4 and 5.3.7 (PAM `minlen` / `retry`), 2.1.2 (chrony `server` / `pool`), 1.3.2 (AIDE cron), 1.2.2 (`signed-by`), 1.2.1 (`sources.list`), the usb-storage blacklist and the GDM dconf checks all skip comment lines and match whole tokens.
- **A loaded kernel module is never "disabled".** A module nulled in modprobe.d but still resident now fails its control instead of passing on the config alone.
- **Package checks read the install status.** 4.1.1.1 passed on a removed-but-not-purged auditd (`dpkg-query -W` exits 0 for `deinstall ok config-files`). The 4.2.2.1 rsyslog, 1.3.1 AIDE and 1.6.1 AppArmor checks had a status guard that could never match; all now query `${Status}`.
- **Audit-rule controls match the rule's key.** 4.1.3–4.1.15 accepted any loaded rule containing the key word anywhere — 4.1.14's `-S delete_module` alone satisfied 4.1.11 (`delete`). The persisted-rule scan also ignores commented-out rules.
- **ip6tables ESTABLISHED check requires a real `-A INPUT … ACCEPT` rule**, matching the IPv4 check, instead of the word appearing anywhere in the ruleset.

## [1.0.2] — 2026-07-02

Safety and UX overhaul across all control modules (+1,351 / −434 lines, 1047 tests passing).

### Safety

- **IPv6 lockout disarmed.** Firewall hardening no longer risks locking the operator out over IPv6.
- **Durable rollback journal.** Journal writes are flushed and fsync'd so an interrupted harden run stays reversible.
- **sshd reload on rollback.** Reversing an sshd control now reloads the daemon so the undo actually takes effect.

### UX

- **Streaming audit output** — results render as controls are evaluated instead of after the full pass.
- Redesigned, more legible audit/harden output across every control module.

### Packaging

- `build.sh` — one command produces the wheel, sdist, and `SHA256SUMS` in `dist/` (builds in a throwaway venv; no wheel is checked into the repo).
- Install docs rewritten to cover build-from-source vs. release-bundle paths.

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
