# LSS Roadmap — work to elevate v1.0.1 toward $10k-tier ship

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

## False-pass sweep — round 2 (fixed on `claude/false-pass-fixes`, 2026-10-05)

Second-pass audit, 2026-10-04: checks that report pass while the control is not enforced. Fix each test-first (a test that fails on the old code), tick it when committed.

**auth.py / pam.py**
- [x] 5.3.2 faillock passes on any pam_faillock line; without `preauth` nothing is ever locked out. LSS's own pam-config profile lacks preauth (profile needs live-host rework).
- [x] 5.3.1 / 5.3.4 / 5.3.7 pwquality: module arguments win over the conf; last value across pwquality.conf + pwquality.conf.d wins; 5.3.4 / 5.3.7 must require the module to be loaded.
- [x] login.defs: checks read the first occurrence, shadow applies the last; `pam._set_login_defs` rewrites Debian's stock `#\tPASS_MIN_DAYS` comment and leaves the real line in force. pwquality fixers rewrite comment lines too.
- [x] 5.6 `pam_wheel.so deny group=nosu` passes. 5.3.5 reads RHEL's auth pam_unix line, never the password line. Inline `#` comments in PAM lines still count.
- [x] 6.2.1 / 6.2.2 compare UIDs as strings (`00` is root). 5.4.4 umask compared numerically (`070` passes); shell-file `umask` overrides ignored. 5.4.1.1–5.4.1.4 check only new-account defaults, never existing accounts in /etc/shadow.

**users.py / cron.py / ssh.py / lib/sshd.py**
- [x] Numeric UID/GID everywhere (6.2.4, 5.4.2); empty /etc/passwd password field passes; 6.2.8 checks sudo's secure_path instead of root's login PATH and never checks directory ownership; at.allow owner/mode unchecked.
- [x] `sshd -T` without `-C` applies no Match blocks, so a Match block re-enabling root login passes; `ClientAliveCountMax 0` disables termination (5.2.16, and 5.2.12 in misc.py); weak MAC list lacks hmac-sha1 / umac-128; 5.2.18 passes when the Banner file is missing.

**misc.py**
- [x] 1.1.15: lsmod prints `usb_storage`, so the loaded check never fires; `/usr/bin/false` rejected; blacklist-only counted as disabled; modprobe.d `glob("*")` reads `.bak` / `.dpkg-old`.
- [x] 1.6.3 `"0 processes are unconfined"` matches "10 processes…"; 2.3.x Debian-only package names (`inetutils-telnet`, RHEL `ypbind` / `openldap-clients`); 1.3.2 counts cron files run-parts never runs; 1.9 passes on stale apt lists.

**filesystem.py / kernel.py / *_perms.py**
- [x] Kernel-module controls: blacklist alone counted as disabled (dccp still autoloads); `.bak` files read; module names not normalized.
- [x] 1.4.1 counts `ftp hard core 0` and ignores later limits.d; 6.1.9–6.1.13 `find / -xdev` never scans a separate /home, /var or /tmp.

**gdm.py / firewall.py**
- [x] 1.8.4–1.8.8: local.d keyfiles only apply with `system-db:local` in /etc/dconf/profile/user, which stock Debian lacks and the fixes don't create; 1.8.4 / 1.8.5 should check CIS's session idle-delay + lock-delay; the 1.8.4 fix writes idle-delay under the wrong schema.
- [x] 3.5.3.x trust `all.disable_ipv6` alone (use `lss.lib.sysctl.ipv6_disabled()`, done); 3.5.4 passes on a rules file with no boot-time loader; 3.5.2.4 ignores UDP listeners and `ss` failure.

Every item above has tests that fail on the pre-fix code (tests/test_false_pass_r2_*.py). The IPv6 trust in extras.py 3.2.1 and network.py is fixed too.

**Needs a live-host pass before a release tag:** the faillock profile (lockout tested only in a debian:12 container with pamtester), `sshd -T -C` on older OpenSSH, `modprobe --showconfig` and the mount scan on real hosts, the GNOME dconf profile after `lss harden`, iptables-persistent install on Debian, and the aa-status format on AppArmor 4.

## False-pass sweep — round 3 (done on `claude/false-pass-fixes`, 2026-10-05)

The modules round 2 did not audit: logging.py, audit_rules.py, extras.py, services.py, network.py, boot.py. 25 findings were fixed, each pinned in tests/test_false_pass_r3_*.py and failing on the pre-fix code. Every control module has now had a false-pass pass.

**Needs a live-host pass as well:** journald drop-in order against `systemd-analyze cat-config`, the `auditctl -l` rule rendering and `ausyscall` unknown-syscall handling (aarch64), the RHEL `audit` package install, GRUB user.cfg on RHEL, and the socket-activated service units.

**Fixed, 2026-10-05:** 4.1.16 (`-e 2`) never passed at runtime, because `auditctl -l` does not print the enable flag. It now reads the `enabled` flag from `auditctl -s` (`_audit_enabled_flag()`): pass on `enabled 2`, warn when `-e 2` is persisted but not yet active, manual otherwise. Pinned in tests/test_false_pass_audit_rules.py.
