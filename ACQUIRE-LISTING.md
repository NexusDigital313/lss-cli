# LSS — Asset Overview for Acquisition

A one-page summary for acquirers' technical and commercial diligence teams.
Written for an Acquire.com asset listing; deeper material is in the rest of
this repository.

## What it is

**Linux Security Suite (LSS)** is a commercial Python CLI that audits and
hardens Linux hosts against the CIS Benchmark, with a journaled rollback
journal — so a bad hardening pass can be reversed with one command.

The differentiator versus existing tools (Lynis, OpenSCAP, Chef InSpec) is
**built-in argv-list rollback**: every change is recorded as a structured
undo command, never a shell string, with a backed-up file alongside. No other
CIS tool in the comparison ships rollback. See `README.md` § "How it
compares" for the full table.

## What's included in the asset

| Category | Contents |
|---|---|
| **Source code** | `lss-1.0.0/lss/` — Python 3.10+ codebase, ~7,500 lines, no third-party runtime deps beyond `rich` for terminal output. |
| **Test suite** | `lss-1.0.0/tests/` — 1,024 passing unit tests + 23 platform-skipped, parameterized per-control coverage. |
| **Pre-launch test plan** | `PRE_LAUNCH_TEST_PLAN.md` — operator-facing QA checklist for shipping releases. |
| **Sample output** | `examples/sample-audit-report.html` — real audit report, opens in any browser. |
| **Build artifacts** | `lss-1.0.0-py3-none-any.whl`, `lss-1.0.0.tar.gz`, `SHA256SUMS`. |
| **Documentation** | `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `LICENSE`. |
| **License scaffolding** | `lss/lib/license.py` — license-key gate stub. Default returns valid (no enforcement); buyer wires the body of `check_license` to their preferred provider (Paddle / Stripe Billing / Lemon Squeezy / custom HTTP endpoint), or removes the gate entirely. |

## What is NOT included (buyer should clarify with seller)

- **Trademark / brand**: status of the "Linux Security Suite" / "LSS" mark
  is not represented in the asset itself.
- **Domain**: `linuxsecuritysuite.com` (referenced in older draft README,
  removed from current) — confirm ownership separately.
- **Customers / revenue**: zero — this is a pre-launch asset.
- **Existing distribution channel**: none active. The codebase is portable
  to any channel (PyPI, paid download, marketplace listing, embed in an
  MSP product, etc.).
- **Hosted infrastructure**: none — LSS is a single-binary CLI, no servers
  required.

## Codebase signals

- **Coverage**: 206 hardening controls registered (201 CIS-aligned + 5
  LSS-XXX). 172 of 206 (83.5%) are auto-fixable; the remaining 34 are
  audit-only by design (each documents *why* in the source — bootloader
  edits, partition layout, PAM stack edits, evidence-destruction risks).
- **Tests**: 1,024 passing unit tests (23 platform-skipped). The `test_per_control.py`
  parameterized suite exercises every registered control's check function.
- **Defensive engineering**: `shell=True` is forbidden in the codebase
  (regression-tested). Every fix backs up modified files before write.
  Rollback uses argv-list undo commands — legacy string-form undos in old
  journals are *refused, not executed*.
- **No CI yet**: tests pass locally; setting up GitHub Actions (or
  equivalent) is a half-day task for the buyer's team.

## Tech stack

- Python 3.10+, single dependency at runtime (`rich` for terminal output).
- Standard-library `subprocess`, `pathlib`, `urllib`, `json` for everything else.
- Distribution as a single wheel; install with `pip install lss-1.0.0-py3-none-any.whl`.
- Journal format is JSON (per-run files under `/var/log/lss/journal/`),
  v1.0.0-compatible with v0.5.x journals.

## Target market

Operators who want CIS-grade hardening **without** the friction of
SCAP-content authoring or six-figure GRC platforms:

- Small ops teams running Debian/Ubuntu fleets (primary target).
- MSPs hardening client environments where every change must be reversible.
- Security-conscious VPS operators (indie SaaS, hobby-but-paid services).
- Internal tooling for compliance-adjacent companies that need a CIS pass
  but not full DISA-STIG.

LSS is **not** a fit for Fortune-500 procurement (those buyers want SCAP +
official content, served by OpenSCAP/InSpec) or DISA-STIG environments.

## Maturity / current state

- Version 1.0.0 (latest), shipped 2026-04-30.
- Customer-facing bugs surfaced by the pre-launch test plan were closed
  across the 0.5.x series; the 0.5.2 fix-set added byte-identical
  state-restore regression tests to lock the rollback-correctness guarantee
  in. 1.0.0 lands the user-home HTML report path resolver (JSON stays
  root-only at `/var/log/lss/`; HTML lands at the invoking user's
  `~/.local/share/lss/reports/`, owned by them and openable without sudo).
  See `CHANGELOG.md`.
- Primary platforms are Debian 12, Ubuntu 22.04/24.04, Kali. RHEL/Rocky/Alma
  support partial; full RHEL parity is a future milestone.
- Pre-launch QA: unit suite passes; full per-control on-host validation
  against a fresh Debian 12 droplet is the operator's final sign-off step
  before any customer-facing launch (see `PRE_LAUNCH_TEST_PLAN.md`).

## What a buyer can do in week one

- Read README + CHANGELOG (~30 min).
- Run `pytest tests/` (~2 min — confirms 1,024 tests still green in the
  buyer's environment).
- Run `PRE_LAUNCH_TEST_PLAN.md` against a fresh Debian 12 droplet (~10
  minutes, ~$0.01 spend).
- Open `examples/sample-audit-report.html` in a browser to see the deliverable
  format.
- Decide on licensing model and wire `lss/lib/license.py` to the buyer's
  preferred provider — or remove the gate entirely if going OSS / freemium /
  embedded-in-larger-product.

## Author / IP provenance

- Single author per `LICENSE`: J. Parmenter, copyright 2026.
- Copyright transfer is handled in the acquisition agreement, not in the
  source files themselves.
- Codebase has no third-party copyrighted material beyond the BSD-licensed
  `rich` runtime dependency (declared in `pyproject.toml`).
