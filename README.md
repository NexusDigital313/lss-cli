# The Linux Security Suite

**Audit, harden, and roll back Linux hosts against the CIS Benchmark — in one command.**

LSS scans your system against **204 CIS Benchmark controls**, fixes the failures, records every change in a rollback journal, and produces a printable HTML report. Built for VPS operators, indie hackers, and small ops teams who want CIS-grade hardening without a six-figure GRC platform.

```
$ sudo lss audit
$ sudo lss harden --confirm
$ sudo lss rollback --last        # something broke? undo it
$ sudo lss report -o audit.html
```

## What it covers

19 control modules, 204 controls total:

| Area | Examples |
| --- | --- |
| Filesystem | mount options, partition layout, sticky bits, permissions |
| Kernel | sysctl hardening, ASLR, kernel module restrictions |
| Network | IPv4/IPv6 hardening, ICMP, source routing |
| Firewall | UFW / nftables baseline rules |
| Services | unnecessary daemons, time sync, MTA |
| SSH | ciphers, MACs, login restrictions, idle timeout |
| Auth & PAM | password quality, lockout, sudo logging |
| Logging & Audit | auditd rules, journald, log retention |
| Users | shell, account expiry, root login |
| Boot | GRUB password, single-user auth |
| Banners, cron, GDM, file perms, misc, extras | … |

Run `lss list` to see every control with its ID, section, and whether it has an automatic fix.

## Install

```
pip install lss
```

Or from a release tarball:

```
pip install lss-0.1.0.tar.gz
```

## Quick start

```
# Read-only audit — no changes
sudo lss audit

# Apply every available auto-fix
sudo lss harden --confirm

# Cherry-pick controls
sudo lss harden --confirm --control 5.2.3 --control 5.4.1.1

# Undo the most recent harden run
sudo lss rollback --last

# Undo a single control
sudo lss rollback --control 5.2.3

# Generate a printable HTML report from the last audit
sudo lss report -o ~/audit.html

# Full command reference with consequences
lss help-all
```

## How rollback works

Every change made by `lss harden` is appended to a journal under `/var/log/lss/journal/`. Each entry records:

- Which control made the change
- The exact undo command
- A backup of any modified file
- A run ID so you can target a specific harden run later

`lss rollback --last` replays the journal in reverse. `lss rollback --run-id <id>` targets a specific past run. `lss rollback --control <id>` undoes a single control.

## CIS profiles

```
sudo lss audit --profile server         # default
sudo lss audit --profile workstation
sudo lss audit --profile hardened
```

## Output

- Colored terminal output by default (powered by `rich`)
- `--no-color` for piping to files or scripts
- `--json` for machine-readable output (works with `audit`)
- `lss report` renders a styled, printable HTML report

## Requirements

- Linux (Debian, Ubuntu, Kali tested; RHEL / Rocky in v1.1)
- Python 3.10+
- Root for `audit`, `harden`, `rollback`, `report` (read-only commands like `list` and `help-all` do not require root)

## License

Commercial. See [LICENSE](LICENSE). Evaluation use is permitted on a single host in audit-only mode; production use requires a paid license.

For pricing and licensing: <https://linuxsecuritysuite.com>
