# r/selfhosted draft

## Title

```
I built a CIS hardening tool with one-command rollback because I was tired of running random GitHub scripts on my VPS
```

## Body

```
Every time I spin up a new VPS I go through the same motions: read the CIS Benchmark PDF, run some hardening script from a GitHub repo with 47 stars, hope it doesn't break SSH, regret it when it does, spend 20 minutes restoring from backup.

So I built the thing I wanted: **The Linux Security Suite** — `lss audit` runs 204 CIS controls in two minutes read-only, `lss harden --confirm` applies the fixes, and `lss rollback --last` reverses everything if anything breaks.

The rollback is the part I cared about most. Every change is recorded in a journal under /var/log/lss/journal/ with a backup of the file before it was modified. Rollback restores from those backups (with an mtime check so it warns you if you've manually edited the file since), then replays argv-form undo commands. No `shell=True`, no f-string interpolation into shell strings — those are the two bugs I fixed in the last few days that made me wait to launch.

What it covers: filesystem mount options, kernel sysctls, network parameters, iptables (with iptables-save persistence — they survive reboot), services to disable, SSH hardening, PAM, auditd rules with both b64 and b32 syscall variants, cron permissions, login banners, all the standard CIS sections.

What it doesn't auto-fix: anything where the right answer depends on what you're running. It'll flag world-writable files but won't chmod them. It'll flag duplicate UIDs but won't delete an account. 79 of the 204 controls are audit-only for that reason.

Pricing: $149 for a single host with 12 months of updates, $499 for up to 25 hosts with lifetime updates (this is the tier I'd pick if I had a small homelab/agency setup), $1,499 for unlimited. Source is readable for evaluation — you can git clone the repo and run the audit (read-only, no changes) before paying anything.

Landing page: https://linuxsecuritysuite.com
GitHub: https://github.com/<USERNAME>/lss

Built it because I needed it. Posting it because maybe someone else does too.
```

## Notes

- r/selfhosted hates obvious marketing. The opening "I was tired of..." is the right tone — keep it.
- Reply to comments within 30 min, especially the ones questioning price. The most common objection will be "why not Lynis/OpenSCAP" — be ready: Lynis is a scanner, no fix/rollback. OpenSCAP is enterprise-grade but has a 200-page learning curve.
- If a mod removes it as commercial, message them with: "Happy to remove if it violates the rules — the README says it's commercial and free for evaluation, posting because the homelab demographic is exactly who I built it for."
