# Pre-launch test plan

What to verify on a real Debian 12 host before sending v1.0.1 to a paying customer. This checklist exists because the per-control fixes have not all been individually exercised against a clean install.

## Where to run this

A fresh Debian 12 host. Cheapest paths if you don't have hardware:
- DigitalOcean / Vultr / Hetzner $5/month droplet, billed hourly (~$0.01 per test session)
- Spin up, run the suite, destroy

Do NOT run this on the Kali Live host where LSS was developed — too many controls already remediated; you won't get fresh-install signal.

## Setup (one-time, on the test host)

```bash
# Copy the wheel onto the host
scp /home/kali/00-Active-Products/LSS/Build/lss-1.0.1-py3-none-any.whl \
    /home/kali/00-Active-Products/LSS/Build/SHA256SUMS \
    debian@<host>:~/

# On the host: verify the artifact
ssh debian@<host>
sha256sum -c SHA256SUMS

# Install
sudo apt update && sudo apt install -y python3-pip python3-venv
python3 -m venv ~/lss-venv
~/lss-venv/bin/pip install ~/lss-1.0.1-py3-none-any.whl
sudo ln -sf ~/lss-venv/bin/lss /usr/local/sbin/lss
```

## License gate (2 minutes)

Free tier (`audit`, `report`, `list`, `harden --dry-run`, `rollback`) needs no key —
only `harden --confirm` is gated. Verify enforcement:

```bash
# 1. Blocked without a key
sudo lss harden --confirm --control 5.4.5     # EXIT 2, "applying hardening requires a license"

# 2. A bad key is rejected online (not a network error)
sudo lss license activate NOT-A-REAL-KEY      # "license_key not found"

# 3. A real key activates (use a Lemon Squeezy TEST-mode key)
sudo lss license activate <TEST-KEY>
sudo lss license status                       # "license valid (...)"
sudo lss harden --confirm --control 5.4.5     # now allowed

# 4. rollback is ALWAYS free — even after deactivation
sudo lss license deactivate
sudo lss rollback --last                      # still works; undo is never gated
```

> For the smoke test below, keep a key activated **or** `export LSS_ENFORCE_LICENSE=0`
> so `harden --confirm` isn't gated during QA.

## The smoke test (5 minutes)

```bash
# 1. Version + counts
sudo lss --version                                # should print: lss 1.0.1
sudo lss list | tail -3                           # should report: 206 controls

# 2. Read-only audit baseline — capture this for the delta later
sudo lss audit
ls -la /var/log/lss/audit-*.json | tail -1        # note this path as BASELINE

# 3. Dry-run preview
sudo lss harden --dry-run | tail -10              # should show "Would fix: N"

# 4. Interactive sanity — apply 2-3 controls one at a time
sudo lss harden --confirm --interactive --control 5.4.5 --control 1.7.4
# Should prompt y/N before each. Type 'y' for both.

# 5. Verify the fix took effect
grep TMOUT /etc/profile.d/80-lss-timeout.sh        # should show readonly TMOUT=900
ls -la /etc/motd                                   # should be 0644 root:root

# 6. Rollback
sudo lss rollback --last
# Re-check — TMOUT file should be gone, motd back to its prior mode

# 7. Full harden (this is the big one — touches a lot)
sudo lss harden --confirm | tee /tmp/harden-output.log
# Watch for any RuntimeError tracebacks. None should occur.

# 8. Post-harden audit + delta report
sudo lss audit
sudo lss report --baseline $BASELINE -o /tmp/delta-report.html
# Open delta-report.html in a browser. Verify:
#   - Fixed/Improved/Regressed counts roughly match what step 7 reported
#   - Specifically: NOT 0 fixed (would mean the fixes didn't take effect)
#   - LSS-004 should remain "skip" on a non-Live system
#   - LSS-005 should fail (broader execve audit not configured)

# 9. Full rollback
sudo lss rollback --last
sudo lss audit
# Score should return roughly to the pre-harden baseline
```

## Targeted checks for the BLOCKER-class bugs we just fixed

These confirm the v1.0.1 QA pass actually closed the holes it claims to close.

### 5.3.2 (faillock) — must NOT cosmetic-pass
```bash
# Fresh Debian 12 won't have pam_faillock in common-auth by default.
sudo lss audit --control 5.3.2
# Expected: FAIL with "pam_faillock not active in PAM auth stack — to enable: ..."
# If this shows PASS, the cosmetic-pass fix didn't land.

# Now enable faillock and re-audit
sudo pam-auth-update --enable faillock --package
sudo lss audit --control 5.3.2
# Expected: PASS with "pam_faillock active in /etc/pam.d/common-auth"
```

### 5.3.3 (password reuse) — must be audit-only with remediation
```bash
sudo lss audit --control 5.3.3
# Expected: FAIL with the full pam-auth-update remediation command in detail
# Look for: "to remediate on Debian/Ubuntu/Kali: install a pam-configs profile..."
```

### 1.8.x (GDM) — must error if dconf-cli is missing
```bash
# Only run this if GDM is actually installed (gdm3 package).
# On a stock minimal install, GDM is not present and the checks pass with "GDM not installed".
sudo apt install -y gdm3                          # if testing
sudo apt remove -y dconf-cli                      # simulate the broken case
sudo lss harden --confirm --control 1.8.2 || echo "fix correctly raised"
# Expected: RuntimeError with "dconf binary not found — install dconf-cli (Debian/Ubuntu)..."
# If the fix returns success without dconf-cli, the cosmetic-pass bug is back.
sudo apt install -y dconf-cli                     # restore
```

### 4.1.1.3 (audit log size) — must reload auditd
```bash
sudo lss harden --confirm --control 4.1.1.3
sudo auditctl -s | grep -i max_log_file 2>/dev/null || echo "auditctl reports inline"
# Verify the running daemon picked up the new value:
sudo cat /etc/audit/auditd.conf | grep max_log_file
# Should show 32. The reload happened in the fix.
```

### pkg.py NEEDRESTART_MODE — must not hang on Ubuntu 22.04
This is most easily tested by running `sudo lss harden --confirm --control 1.6.1` (AppArmor install) on a fresh **Ubuntu 22.04** server. If the fix completes within the 5-minute timeout, the NEEDRESTART_MODE=a fix is working. If it hangs, debug.

## Pass / fail criteria

The test passes if all of:
- Steps 1-9 complete without traceback or hang.
- Delta report shows a meaningful Fixed count (> 30 controls flipped to pass).
- Rollback in step 9 returns the score to within 5 points of the pre-harden baseline.
- The 4 BLOCKER-bug regression checks all behave as documented above.

The test fails if any:
- A fix raises a RuntimeError unexpectedly.
- A fix completes "successfully" but the corresponding control still fails on re-audit.
- Rollback leaves the system in a measurably different state than baseline.
- pam_pwquality, pam_pwhistory, or pam_faillock checks pass without the corresponding module being active in the PAM stack.

## What this plan does NOT cover

- Per-control unit tests on every fix (the 1023-test suite covers the engine + parameterized smoke; not each fix's actual on-system effect)
- RHEL / Fedora coverage (v1.0 primary target is Debian-family; RHEL parity is v1.1)
- Long-running reliability (multi-day run with reboots between)
- Concurrent harden runs (LSS does not yet take a global lock; do not run two `lss harden` in parallel)

If a customer hits a bug not listed here, that's the v1.0.1 work item.
