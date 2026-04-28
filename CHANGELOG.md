# Changelog

All notable changes to The Linux Security Suite are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] — 2026-04-23

### Added
- **47 new auto-fix functions** covering CIS controls that were previously audit-only, plus **2 new LSS-extra detection controls**. New fixes:
  - **services (2.3.1–2.3.5):** NIS/rsh/talk/telnet/LDAP client packages are now removed via `apt-get remove` (rollback reinstalls with configs preserved).
  - **banners (1.7.4–1.7.6):** `/etc/motd`, `/etc/issue`, `/etc/issue.net` get chmod 0644 + chown root:root with pre-change ownership/mode recorded for exact rollback.
  - **network (3.2.1, 3.5.1.1, 3.5.1.2, 3.5.3.1–3, 3.5.4):** IPv6 forwarding disabled via sysctl, iptables/nftables installed on demand, ip6tables default-deny + loopback + established mirroring the IPv4 fixes, and iptables-save now persists rules to `/etc/iptables/rules.{v4,v6}` automatically.
  - **logging (4.1.1.1, 4.1.1.3, 4.2.1.2, 4.2.2.1, 4.2.3):** auditd and rsyslog install fixes, auditd `max_log_file = 32` MB default, journald `Compress=yes`, and world-readable `/var/log` files get their world bits stripped (per-file mode recorded for exact rollback).
  - **auth/pam (5.2.12, 5.3.2, 5.3.5, 5.3.6, LSS-002):** SSH `ClientAliveInterval` restored to 300s when it's 0, faillock policy written to `/etc/security/faillock.conf`, login.defs `ENCRYPT_METHOD SHA512` and `PASS_MIN_DAYS 1`, and `/etc/securetty` trimmed to (console, tty1) when over-permissive.
  - **filesystem/kernel (1.3.1, 1.3.2, 1.6.1, LSS-001):** AIDE and AppArmor install via the shared package helper; `/etc/cron.daily/aide` installed for CIS 1.3.2 periodic integrity checks; RHEL crypto-policies reset to DEFAULT, or Debian openssl `MinProtocol = TLSv1.2`.
  - **filesystem perms (6.1.9):** world-writable files have the `o+w` bit stripped with per-file original mode recorded for exact rollback.
  - **users (5.4.3, 6.2.2, 6.2.9, 6.2.10, 6.2.11, 6.2.12, 6.2.13, 6.2.14, LSS-003):** root's default GID forced to 0 via usermod; missing home directories created with `/etc/skel` contents and correct owner/mode; top-level home-dir ownership and 0750 mode fixed with per-entry rollback; `.forward`, `.netrc`, and `.rhosts` renamed to `.lss-disabled` (not deleted); shell-dotfile lines with unsafe `PATH=` get commented with `# [LSS-DISABLED]` prefix after backup.
  - **GDM (1.8.2–1.8.8):** seven dconf-database fixes — login banner, `disable-user-list`, idle screen lock + override lock, removable-media automount + override lock, `autorun-never`. Each writes into `/etc/dconf/db/{gdm,local}.d/`, runs `dconf update`, and records the file for rollback.
  - **boot (2.1.2):** when chronyd is active but `chrony.conf` has no `server`/`pool` lines, append `pool 2.pool.ntp.org iburst` and `pool time.nist.gov iburst` as a safe starting point.
- `lss/lib/pkg.py` shared helper: `install(pkg)` / `remove(pkg)` / `is_installed(pkg)` with Debian + RHEL backends, noninteractive env, and argv-list rollback.
- **LSS-004 — AppArmor service condition-skip detection on Debian/Kali Live+persistence boots.** Debian's `/usr/lib/systemd/system/apparmor.service` ships with `ConditionPathExists=!/run/live/overlay/work`, which makes the service skip on Live boots — including persistent-overlay Live boots where the operator expects a normal install experience. No standard CIS scanner catches this because the kernel module is loaded and `aa-status` reports normally; only inspecting the systemd `ConditionResult` exposes the gap. Audit-only in v0.5; the detail string includes a one-line systemd drop-in remediation.
- **LSS-005 — Forensic-grade user execve auditing (beyond CIS 4.1.13).** CIS 4.1.13 captures only privilege-transition execves (sudo/su/pkexec/setuid binaries — the `euid!=uid && euid=0` filter). LSS-005 detects whether a broader rule covering every real-user execve (`auid >= 1000`) is loaded and surfaces the gap with a remediation note. Audit-only by design — the broader rule produces audit log volume proportional to user shell activity (potentially hundreds of MB per day on an interactive host) and should be enabled deliberately, not as part of a default harden pass.
- **`lss harden --interactive` (`-i`).** Per-control y/N approval gate. With `--confirm --interactive`, the harden engine prints each failing control's id, title, current state, and (for destructive-service controls) a warning, then prompts y/N before applying the fix. Default response is N (skip), so an accidental Enter on a live customer box doesn't apply a fix. Ctrl-C aborts the run cleanly, journals partial state, and exits 130. EOF (Ctrl-D) treats the current control as declined and continues. Refuses to start if stdin isn't a TTY.
- **`lss report --baseline <path>`.** Renders a before/after delta against a previous audit JSON. New table columns show the prior status (Before), the current status (After), and a Change pill (`Fixed` / `Regressed` / `Still failing` / `Unchanged` / `New`). A delta-summary block above the per-control table aggregates the counts. Without `--baseline`, the report renders current-state-only (existing behavior).

### Changed
- Control 2.4 (nonessential services) detail now lists actual listening ports and points to `ss -tlnp` instead of a bare count.
- Control 4.1.2 (audit backlog) now tells the operator exactly what to add to `GRUB_CMDLINE_LINUX` and warns that GRUB edits are intentionally manual (bad kernel-param edits can brick a host and rollback can't reach a box that won't boot).
- Control 1.4.2 (bootloader password) detail now names `grub-mkpasswd-pbkdf2` and the `set superusers` line explicitly.
- Control 1.4.4 (single-user mode auth) detail now suggests `passwd root` or sulogin rescue-service wiring.
- Control 1.9 (updates available) detail now names the exact command and reminds the operator to read changelogs first.

### Intentionally not auto-fixed (31 controls — documented in code)
- **Partition layout (1.1.2–1.1.7):** moving `/tmp`, `/var`, `/var/tmp`, `/var/log`, `/var/log/audit`, `/home` to separate filesystems requires repartitioning — not something a hardening tool can do without downtime and a recovery plan.
- **Bootloader / kernel-param edits (1.4.2, 1.6.2, 4.1.2):** a bad GRUB write can render the host unbootable and rollback can't reach a machine that doesn't boot. Detail strings name the exact command to run.
- **AppArmor enforcement (1.6.3):** moving a profile from complain to enforce can break running apps. Operator must review each profile first.
- **User-merge decisions (6.2.1, 6.2.3–6.2.7):** duplicate UIDs/GIDs/usernames/groupnames require an operator to decide which account is real. Detail strings name the offending IDs.
- **Account-state decisions (5.4.2 empty passwords, 6.2.15 invalid shells):** no safe auto-choice between `passwd -l`, `passwd -d`, `/usr/sbin/nologin`, or a real password — getting this wrong locks users out.
- **File-ownership scans that could mask evidence (6.1.10, 6.1.11, 6.1.13):** auto-chowning an unowned file or stripping a SUID bit can destroy evidence of a compromise. These stay audit-only by design.
- **Site-specific (1.2.1 repos, 1.2.2 GPG keys, 2.4 nonessential services, 3.5.2.4 firewall rules per port, 3.5.5 unused interfaces, 3.6 wireless, 6.2.8 root PATH):** organizationally-driven choices, not a compliance checkbox.
- **Workstation choices (1.8.1 GDM removal):** would strip the user's desktop.
- **Big-hammer actions (1.9 apt upgrade, 1.4.4 root password):** interactive or too disruptive for an unattended pass.
- **PAM stack edits (5.3.3 password reuse limit):** correctly editing the PAM password stack across Debian (pam-auth-update profile mechanism), RHEL/Fedora (authselect), and bare Linux (direct edit with `pam_unix` success-jump arithmetic) is its own subsystem of work. Earlier LSS versions wrote `remember=5` to `/etc/security/pwquality.conf`, which `pam_pwquality.so` does not actually process — the policy was never enforced. Rather than ship another half-correct fix that could lock customers out of their own auth, 5.3.3 is documented audit-only with a precise remediation command in the detail string. Full automated remediation is planned for v0.5.1.

### Correctness fixes
- **5.3.2 (faillock) check tightened.** Previous check returned `pass` if `/etc/security/faillock.conf` had a `deny` line, even when `pam_faillock.so` was not active in the PAM auth stack — the same cosmetic-pass class that hit 5.3.3. Check now requires an uncommented `pam_faillock` (or `pam_tally2`) line in `/etc/pam.d/common-auth` or `/etc/pam.d/system-auth` and includes a precise pam-auth-update / authselect remediation command in the fail detail. The fix continues to write `faillock.conf` so once `pam_faillock` is enabled, the policy is in place.
- **1.8.x (GDM dconf) — `dconf update` failure now surfaces.** `_dconf_write` previously ignored the return code of `subprocess.run(["dconf", "update"])`, so on systems without the `dconf-cli` package (a separate package from `gdm3` on Debian) the keyfile was written successfully but the compiled `/etc/dconf/db/gdm` was never regenerated — GDM at next login showed no banner / user-list / screen-lock. LSS's own check then passed because it reads the keyfile directly. Same cosmetic-pass class as 5.3.3. Fix now preflight-checks `which dconf` and raises `RuntimeError` if `dconf update` returns nonzero.
- **4.1.1.3 (auditd log size) — now reloads auditd.** auditd reads `/etc/audit/auditd.conf` only at startup. The previous fix wrote the file but never reloaded the daemon, so the running auditd kept rotating at the old (likely 8MB default) limit while LSS reported the control as passing. Fix now invokes `service auditd reload` after the write (using the legacy `service` command because systemd intentionally refuses `systemctl restart auditd` on RHEL family). Same cosmetic-pass class as 5.3.3. Also: pre-write newline normalization so a hand-edited config without trailing newline doesn't get a syntax-error append.
- **4.1.1.2 (auditd running) — partial-failure now raises.** Previously, if `systemctl enable auditd` succeeded but `systemctl start auditd` failed, the fix returned the partial rollback set and the caller treated it as success — leaving the operator's report saying the fix worked while auditd was disabled. Now raises explicitly. On RHEL where systemd refuses `systemctl start auditd`, falls back to legacy `service auditd start` before raising.
- **pkg.py environment — Ubuntu 22.04+ apt hang fixed.** `_NONINTERACTIVE_ENV` was *replacing* the entire process environment with just `DEBIAN_FRONTEND` and `PATH`. On Ubuntu 22.04+ with `needrestart` installed (which is the default), `apt-get install` hangs on a needrestart prompt even with `DEBIAN_FRONTEND=noninteractive` — needrestart prompts out-of-band. Fix now inherits `os.environ`, layers `NEEDRESTART_MODE=a`, `APT_LISTCHANGES_FRONTEND=none`, and `LC_ALL=C.UTF-8` on top. Also resolves perl-postinst locale warnings on stock Debian.
- **pkg.py install rollback — now uses purge.** The undo for an LSS-installed package is `apt-get purge` (not `remove`) so config files created by the package install are cleaned up on rollback. Previously `remove` left config files behind, treating LSS-owned package state as customer-owned. Note: rollback still does NOT remove transitive dependencies — that needs a snapshot-and-diff dpkg approach planned for v0.5.1.

All audit-only controls have specific detail strings telling the operator the exact command to run.

### Changed (existing checks)
- 1.6.2, 1.6.3 (AppArmor) detail strings now name `apparmor=1 security=apparmor` as the GRUB addition and `aa-enforce /etc/apparmor.d/<profile>` as the per-profile remediation.
- 1.8.8 (GDM autorun-never) check now prefers the dconf db file over `gsettings`, which returns "no such key" when run from root's non-session shell even after the system default is correct.

### Package installs vs. removals that affect a running service
CUPS/NFS/Apache/Postfix/etc. (2.2.x) remain gated by the existing destructive-service warning in `harden.py`.

## [0.4.0] — 2026-04-22

### Added
- License-key gate (`lss/lib/license.py`) — currently in BOOTSTRAP mode (permissive with one-time evaluation notice). Flip `BOOTSTRAP_MODE = False` and fill in the three Gumroad product slugs to enforce. Calls Gumroad's license verify API on `harden`/`rollback`/`report`. Supports `--license-key` flag, `LSS_LICENSE_KEY` env var, and `/etc/lss/license.key` fallback.
- Bash and zsh shell completions in `completions/`.
- `SECURITY.md` with private-disclosure policy, response SLAs, and cosign verification instructions.
- `CONTRIBUTING.md` with hard rules (no `shell=True`, backup-before-modify, argv undos).
- `SUPPORT.md` distinguishing community vs commercial support tiers.
- GitHub issue templates (bug, feature, security redirect) + PR template + Dependabot.
- `.github/workflows/ci.yml` runs pytest on Python 3.10–3.13 plus a Bandit static analysis pass and a wheel install smoke test.
- `examples/sample-audit-report.html` — synthetic but realistic 204-control report so prospects can preview the deliverable before buying.
- `launch/wire-gumroad-urls.sh` — one-shot script that swaps the three Buy CTAs in the landing page once Gumroad URLs are known.
- `tests/test_per_control.py` — auto-generated per-control sanity tests (ID shape, title, section, level, check function doesn't crash). 200+ parameterized cases.

### Changed
- Project author in `pyproject.toml` is now "The Linux Security Suite" (project-name attribution rather than personal name).
- Git history rewritten to use Proton email and project-name commit author.

## [0.3.0] — 2026-04-22

### Added
- `skip` status for controls that aren't applicable to the current distro (cleaner than the old false-pass behavior).
- `lss audit --json` now suppresses all decorative rich output so stdout is clean for `| jq` piping. Status messages still go to stderr.
- Syslog audit trail: every `harden` and `rollback` invocation logs to `LOG_AUTHPRIV` for forensic compliance.
- `lss/lib/sshd.py:setting_in_global_scope()` distinguishes global vs `Match`-scoped sshd settings; `PermitRootLogin` warns when the value is correct only via a `Match` block.
- `[dev]` optional install: `pip install lss[dev]` pulls `pytest` and `build`.
- GitHub Actions release workflow with cosign keyless signing on `v*.*.*` tag push. Produces `.whl`, `.tar.gz`, `.sig`, `.crt`, and `SHA256SUMS` automatically.

### Changed
- `5.4.1.5` (inactive password lock) renumbered to `5.4.1.4` to match official CIS Debian 12 v1.0.0 numbering.
- Custom non-CIS controls moved to the `LSS-xxx` namespace so the CIS alignment claim is honest:
  - `1.10` → `LSS-001` (crypto policy)
  - `5.5` → `LSS-002` (root console restriction via securetty)
  - `6.2.16` → `LSS-003` (dotfile PATH integrity)
- Registry sort key now handles non-numeric IDs gracefully.
- `audit-latest.json` symlink swap is now atomic (`tmp + os.replace`) instead of `unlink + symlink_to`.
- `distro.detect()` is cached — repeat calls during a single audit no longer re-parse `/etc/os-release`.

### Fixed
- `output.warn()` and `output.err()` previously called `Console.print(..., stderr=True)` which `rich` doesn't support. Both now use a dedicated stderr `Console` instance.

## [0.2.0] — 2026-04-22

### Security (Critical)
- **XSS in HTML report** (`lss/report.py`) — all interpolated values are now `html.escape()`d. Reports were previously vulnerable to script execution via hostnames, kernel strings, and audit detail messages.
- **Shell injection in rollback** (`lss/rollback.py`, all `lss/controls/*.py`) — `RollbackEntry.undo` is now `list[list[str]]` instead of a shell string. Every `subprocess.run` uses `shell=False`. The rollback engine refuses to execute legacy shell-string undos and warns the operator (covered by a regression test).

### Added
- Atomic journal writes (`lss/lib/journal.py`): write-temp + `fsync` + `os.replace`.
- `journal.backup_file(path)` — snapshots a file before any modification, used by every fix that touches a file. Backups stored under `/var/log/lss/journal/backups/<run_id>/`.
- Module-level current-run context (`journal.set_current_run_id`) so control fixes can call `backup_file()` without a `run_id` parameter.
- iptables rules persisted to `/etc/iptables/rules.v4` via `iptables-save` after every change — they no longer vanish on reboot.
- 32-bit syscall variants (`-F arch=b32`) added to audit rules in 4.1.9, 4.1.10, 4.1.11, 4.1.14, 4.1.15.
- Mount remount preserves existing options instead of stripping `relatime`, `errors=continue`, etc.
- Rollback warns when restoring a file that was modified after the backup was taken (mtime check).
- `lss harden --dry-run` mode shows what would change without applying.
- Pre-flight warning before `harden` lists destructive service-disable controls (dovecot, postfix, apache, etc.) so unattended hardening doesn't break customer production.
- `lss/lib/sysctl.py` and `lss/lib/sshd.py` — shared helpers, removing duplicate code from kernel/network/filesystem_perms and ssh/misc.
- `journal.write_run` now always writes, even on no-op runs, so `rollback --last` has stable semantics.
- 7 smoke tests covering registry, atomic journal + backup, rollback shell-injection regression, HTML XSS escaping, CLI list, and `--dry-run` parser.

### Changed
- Project structure and version bumped to v0.2.0.

## [0.1.0] — 2026-04-21

### Added
- Initial release with 204 CIS-aligned controls across 19 modules.
- Six CLI subcommands: `audit`, `harden`, `rollback`, `report`, `list`, `help-all`.
- Rollback journal, control registry, distro detection, rich + JSON output, HTML report.
- `pyproject.toml`, `README.md`, `LICENSE` (proprietary, evaluation-permitted).
