# Changelog

All notable changes to LSS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/).

## [1.0.1] — 2026-06-25

Safety hardening of the harden/rollback path, plus a redesigned audit experience.
No change to the control set; auto-fix count is 166 (was 167) because the IPv6
default-deny control is now audit-only — see below.

### Fixed (lockout / data-loss safety)

- **IPv6 firewall lockout (3.5.3.1).** `ip6tables` default-deny was auto-applied
  while its IPv4 twin (3.5.2.1) was deliberately audit-only. Setting INPUT/FORWARD
  to DROP before the loopback / ESTABLISHED / SSH allow-rules (which sort after it)
  could sever an IPv6 SSH session mid-harden. `3.5.3.1` is now `fix=None` and its
  check returns `manual`, mirroring `3.5.2.1`. **Auto-fix count 167 → 166.**
- **Rollback journal could be lost on a hard stop.** The journal was written only at
  the end of a run, so a `SIGKILL`/OOM/power loss or `Ctrl-C` during a non-interactive
  `--confirm` lost the rollback record for every change already applied. The journal is
  now flushed incrementally after each control, and the non-interactive loop is guarded
  with `KeyboardInterrupt` → save partial journal and exit 130.
- **Rollback now reloads sshd.** Reverting an `/etc/ssh/*` file restored it on disk but
  left the running daemon enforcing the hardened settings until a manual reload. Rollback
  now reloads sshd after restoring any SSH config so the revert takes effect immediately.

### Changed (audit UX)

- `lss audit` now **fades in the wordmark and streams each control's result live**, grouped
  under section headers, instead of hiding the scan behind a transient progress bar. Set
  `LSS_NO_ANIM=1` (or pipe to a non-TTY / use `--json`) to disable the animation.

### Added (licensing)

- **Real license enforcement** via Lemon Squeezy. The free tier — `audit`, `report`, `list`,
  and `harden --dry-run` (preview) — is never gated. Applying changes (`harden --confirm`)
  requires a valid, activated license key. **`rollback` is deliberately free**: the undo path
  must never be withheld, or a lapsed license could trap a host in a hardened state.
- New `lss license activate <KEY>` / `lss license status` / `lss license deactivate`.
  Activation makes one online call, then caches to `/etc/lss/license.json` (or `~/.config/lss/`)
  so the binary keeps working offline — re-validates online every 14 days when reachable, and
  honors the cached validation for up to 90 days fully offline.
- Enforcement is on by default; `LSS_ENFORCE_LICENSE=0` disables it for self-hosting / dev.
  Key resolution order: `--license-key` → `LSS_LICENSE_KEY` → `/etc/lss/license.key`.

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
