# LSS Roadmap — work to elevate v1.0.0 toward $10k-tier ship

Compiled 2026-05-01 from in-session discussion. Items are tiered by impact at the $10k commercial-sale tier (vendor security review, regulated-industry buyer). Add to this list each session; do not ship until the P0 block is closed.

---

## P0 — would tank the sale

1. **Bound scan timeouts on 6.1.10 / 6.1.11 / 6.1.13** (SUID, world-writable, unowned). Chunked walks, configurable scan roots, partial-result reporting. Eliminate the hang on deep filesystems.
2. **Concurrency lock on `lss harden`.** Flock on a known path; second concurrent run errors cleanly with the first PID instead of corrupting the journal.
3. **Apt transitive-dependency rollback.** Snapshot dpkg installed-set pre/post, restore the delta on rollback. Currently named-package removes succeed but auto-installed deps stay.
4. **RHEL scope decision.** Either ship full RHEL/Rocky/Alma 9 parity at v1.1 (~6 weeks of work) or scope v1.0 as Debian-family only and put RHEL on its own v1.x SKU. "Partial" doesn't sell at this tier.

## P1 — eval friction

5. **`lss diagnose` bundle.** Single command that collects journal + last audit + sanitized system metadata into a tarball for support tickets.
6. **Tamper-evident journal.** HMAC chain or signed entries on `/var/log/lss/journal/` so the buyer's auditor can prove it wasn't post-edited.
7. **5.3.3 password reuse — full PAM stack auto-fix.** pam-auth-update profile + authselect feature management + cross-distro safety. Currently audit-only.
8. **Eval mode license tier.** 14-day audit-only, no payment, so a buyer can evaluate before signing.

## P2 — closes the deal

9. **Operator runbooks.** Install, audit, harden, rollback, troubleshoot — five short markdown docs aimed at the buyer's ops team, not the developer.
10. **White-label HTML report header.** Customer logo + name in the report so it's hand-off-ready to their auditor.
11. **Offline license activation flow.** For buyer machines that don't reach the internet.

## Other items raised in this chat

12. **`launch/*.md` v1.0 rewrite.** Current files are v0.3-era narrative arcs even after numeric edits — need real rewrite for the v1.0 pitch.
13. **`PRE_LAUNCH_TEST_PLAN.md` reframe.** Currently a smoke plan; needs to become a release plan covering signing flow, multi-host signing, and customer-facing acceptance criteria.
14. **`lss/lib/license.py` placeholder slugs.** Re-target once the payment platform is picked. Gumroad is rejected per `feedback_no_gumroad.md` — alternatives: Stripe Payment Links, Paddle, Lemon Squeezy, Polar.sh, manual invoice + key delivery.
15. **Attorney-drafted EULA.** Replace the self-drafted LICENSE placeholder before high-tier sales. Should include indemnification, limitation of liability, and use-restriction language acceptable to enterprise procurement.
16. **Long-running reliability testing.** Multi-day run with reboots between, per the test-plan "not covered" section. Needed for any buyer who'll run LSS as part of their build pipeline.
17. **Per-control on-system unit tests.** Current 1023-test suite covers engine + parameterized smoke, not each fix's actual on-system effect. Missing: real-host integration coverage for every individual fix.
