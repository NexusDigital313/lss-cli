# Changelog

All notable changes to The Linux Security Suite are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
