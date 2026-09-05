<!--
  Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
  Proprietary and Confidential.

  Unauthorized reproduction, copying, modification, distribution,
  redistribution, publication, reverse engineering, decompilation, or
  disassembly of this file, in whole or in part, via any medium, is
  strictly prohibited without explicit prior written authorization.
-->

# Linux Security Suite

**Audit, harden, and roll back Linux hosts against the CIS Benchmark — with a safety net.**

[![Version](https://img.shields.io/badge/version-1.0.2-blue.svg)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-Commercial-lightgrey.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)

LSS scans your Linux host against **206 CIS-aligned hardening controls**, auto-fixes **166 of them**, and records every change in a rollback journal so a bad pass is one command away from being reversed. No agent, no cloud, no six-figure GRC platform — a single CLI for operators who want CIS-grade hardening they can actually undo.

```
$ sudo lss audit                     # writes JSON to /var/log/lss/, HTML to your home, owned by you
$ sudo lss harden --confirm          # applies 166 auto-fixes, skips the 40 that shouldn't be automated
$ sudo lss rollback --last           # something broke? reverse it
$ sudo lss report --open             # regenerate HTML and open it in your browser
```

> **Preview the output**: [`examples/sample-audit-report.html`](examples/sample-audit-report.html) is a synthetic full-coverage report rendered from real LSS output. Open it in a browser to see what a customer-facing audit deliverable looks like.

---

## Install

LSS is a Python package. You install it from a built **wheel** — that wheel
is not checked into the repo, you produce it (or download it from a release).
If you cloned the source and there's no `.whl` next to you, that's expected:
run the build first.

### Option A — build from source, then install (clone / no release bundle)

```bash
./build.sh                        # writes dist/lss-<version>.whl + .tar.gz + SHA256SUMS
pip install dist/lss-*.whl        # install the wheel you just built
```

`build.sh` needs **Python 3.10+** and builds inside a throwaway virtualenv, so
it works on Homebrew/Debian "externally-managed" Pythons and never touches your
global packages. If your default `python3` is older, point it at a newer one:

```bash
PYTHON=python3.12 ./build.sh
```

### Option B — install from a release bundle (you downloaded `dist/`)

A release bundle ships the wheel, the sdist, and `SHA256SUMS`. Verify, then install:

```bash
cd dist
shasum -a 256 -c SHA256SUMS       # confirms the files are intact
pip install lss-*.whl             # or: pip install lss-*.tar.gz
```

`lss --version` should print the installed version once either path completes.

---

## Quick start

```bash
# Read-only audit — JSON saved to /var/log/lss/, HTML auto-emitted to your home
sudo lss audit

# Same, but open the HTML report in your default browser when finished
sudo lss audit --open

# Skip the HTML and only emit JSON (for scripts / CI pipelines)
sudo lss audit --no-report

# Apply every available auto-fix (166 of 206 controls)
sudo lss harden --confirm

# Same, but prompt y/N before each fix
sudo lss harden --confirm --interactive

# Preview what harden would do, without touching the system
sudo lss harden --dry-run

# Cherry-pick controls
sudo lss harden --confirm --control 5.2.3 --control 5.4.1.1

# Undo the most recent harden run
sudo lss rollback --last

# Undo a single control across any past run
sudo lss rollback --control 5.2.3

# Machine-readable audit output (stdout is pure JSON; decorative output on stderr)
sudo lss audit --json > audit.json

# Regenerate HTML from the latest audit and open it in a browser
sudo lss report --open

# Before/after delta — shows what changed since a previous audit
sudo lss report --baseline /var/log/lss/audit-<earlier-ts>.json -o delta.html

# Full command reference with consequences called out
lss help-all
```

### Where files land

| Artifact | Path | Owner / mode |
|---|---|---|
| JSON audit log | `/var/log/lss/audit-<ts>.json` | `root:root` `0640` (tamper-evident; root-only) |
| HTML report (default) | `~/.local/share/lss/reports/report-<ts>.html` | invoking user, `0640` |
| Rollback journal | `/var/log/lss/journal/<run-id>/` | `root:root` |
| File backups (for rollback) | `/var/log/lss/journal/backups/<run-id>/` | `root:root` |

When invoked under `sudo`, LSS resolves the human operator via `SUDO_UID`/`SUDO_GID`/`SUDO_USER` and writes HTML reports into that user's home so they're readable without `sudo`. In true-root contexts (cron, systemd unit, container entrypoint) the HTML falls back to `/var/log/lss/`.

---

## Coverage

**206 hardening controls** across 11 sections — 201 CIS-aligned plus 5 LSS-XXX detection controls for situations standard CIS scanners miss. The honest breakdown:

| | Count | What it means |
|---|---|---|
| **Automated fix** | 166 (81%) | `lss harden` applies the fix and records a rollback entry |
| **Audit-only by design** | 40 (19%) | Flagged with an exact remediation command in the detail string |

**Why 40 controls stay audit-only** (and won't be auto-fixed):

- **Bootloader/kernel-param edits** (1.4.2, 1.6.2, 4.1.2) — a bad GRUB write can render the host unbootable, and rollback can't reach a box that won't boot
- **Partition layout** (1.1.2–1.1.7) — separating `/tmp`, `/var`, `/home` requires repartitioning with downtime and a recovery plan
- **AppArmor enforce** (1.6.3) — moving a profile from complain → enforce can break running apps; operator must review
- **PAM stack edits** (5.3.3) — correctly editing the PAM password stack across Debian (pam-auth-update profile), RHEL (authselect), and bare Linux is its own subsystem; full automation deferred to a future release
- **Duplicate UIDs/usernames/groupnames** (6.2.1, 6.2.3–6.2.7) — requires an operator to decide which account is real
- **Account-state decisions** (5.4.2, 6.2.15) — no safe auto-choice between `passwd -l` vs `passwd -d` vs `/usr/sbin/nologin`
- **Evidence-destruction risks** (6.1.10, 6.1.11, 6.1.13) — auto-chowning an unowned file or stripping SUID can destroy forensic evidence
- **Site-specific policies** (repos, firewall rules per port, unused interfaces, wireless) — not a compliance checkbox
- **Big-hammer actions** (`apt upgrade`, setting root password) — too disruptive for an unattended pass
- **Forensic recommendations** (LSS-004, LSS-005) — detection-only by design; LSS-005 in particular has log-volume implications that should be enabled deliberately, not as part of a default harden pass

See the [full list](CHANGELOG.md) and the [`examples/`](examples/) directory for what you actually get.

### Modules

| Area | Examples |
|---|---|
| Filesystem | mount options, partition layout, sticky bits, permissions |
| Kernel | sysctl hardening, ASLR, kernel module restrictions |
| Network | IPv4/IPv6 hardening, ICMP, source routing |
| Firewall | UFW / nftables / iptables baseline, IPv4+IPv6 persistence |
| Services | unnecessary daemons, NTP, MTA, NIS/rsh/telnet/talk/LDAP removal |
| SSH | ciphers, MACs, login restrictions, idle timeout, faillock |
| Auth & PAM | password quality, lockout, pwquality history, login.defs |
| Logging & Audit | auditd rules, journald compression, log permissions |
| Users | shell, account expiry, home directory creation, forward/netrc/rhosts |
| Boot | GRUB password, single-user auth, bootloader hardening |
| GDM | login banner, user-list, screen lock, removable-media policy |
| Banners, cron, file perms, extras | … |

Run `lss list` to see every control with its ID, section, and whether it has an auto-fix.

---

## How rollback works

Every change made by `lss harden` is appended to a journal under `/var/log/lss/journal/`. Each entry records:

- The control that made the change
- An **argv-list undo command** (never a shell string — no `shell=True` anywhere in the codebase, enforced by regression test)
- A backup of any modified file
- A run ID so you can target a specific harden run later

`lss rollback --last` replays the journal in reverse order. `lss rollback --run-id <id>` targets a specific past run. `lss rollback --control <id>` undoes a single control across any run.

Legacy pre-v0.3 journal entries with string-form undos are **refused, not executed** — rollback warns the operator rather than invoking a shell. That guarantee is regression-tested.

---

## How it compares

| | **LSS** | Lynis | OpenSCAP | Chef InSpec |
|---|---|---|---|---|
| CIS Benchmark coverage | 206 controls | ~270 tests | SCAP content (varies) | Depends on profile |
| **Automated remediation** | ✅ 166/206 | ❌ audit-only | ⚠️ via SCAP remediation | ⚠️ via custom wrappers |
| **Built-in rollback** | ✅ journaled, argv-undo | ❌ | ❌ | ❌ |
| Dry-run mode | ✅ | N/A (audit-only) | ⚠️ content-dependent | ✅ |
| Machine-readable output | ✅ JSON | partial | XML/ARF | JSON |
| License | Commercial (eval permitted) | AGPL (enterprise paid) | LGPL | Apache 2.0 (Chef paid) |
| Target user | VPS operators, indie hackers, small ops teams | Same + enterprise | Enterprise / gov / compliance | Enterprise DevOps |

**Where LSS wins**: rollback, honest coverage story, modern CLI ergonomics, single-binary-ish install.
**Where Lynis wins**: mature ecosystem, more checks, strong enterprise brand.
**Where OpenSCAP wins**: official SCAP content, DISA-STIG integration.

If you're a Fortune 500 buying through procurement, buy OpenSCAP or InSpec. If you operate a handful of VPS hosts and want something you can audit-and-undo in your sleep, LSS is built for you.

---

## Requirements

- Linux — Debian 12, Ubuntu 22.04/24.04, Kali (primary targets). RHEL / Rocky / Alma supported for a subset of controls; full parity in a future release.
- Python 3.10+
- Root for `audit`, `harden`, `rollback`, `report`. Read-only commands (`list`, `help-all`, `--version`) run unprivileged.

---

## License

LSS is commercial software. See [LICENSE](LICENSE) for the full terms.

The codebase ships with a license-key gate (`lss/lib/license.py`) currently in
permissive bootstrap mode — every command runs without a key but a one-time
notice is printed. The gate is wired so an operator can flip enforcement on by
setting a license-verify endpoint URL and the `LSS_ENFORCE_LICENSE` env var.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md). Releases follow [Semantic Versioning](https://semver.org/).

---

## Codebase rules

For developers extending LSS, [CONTRIBUTING.md](CONTRIBUTING.md) documents the
code rules enforced by the regression test suite: no `shell=True`,
backup-before-modify, argv-list rollback undos, and refuse-don't-cosmetic-pass
on missing prerequisites.
