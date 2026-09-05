<!--
  Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
  Proprietary and Confidential.

  Unauthorized reproduction, copying, modification, distribution,
  redistribution, publication, reverse engineering, decompilation, or
  disassembly of this file, in whole or in part, via any medium, is
  strictly prohibited without explicit prior written authorization.
-->

# Getting Support

## Free / Community Support

| What | Where |
| --- | --- |
| Bug reports | GitHub Issues, using the bug report template |
| Feature requests | GitHub Issues, using the feature request template |
| Questions about CIS controls in general | The official [CIS Benchmark documentation](https://www.cisecurity.org/cis-benchmarks) |
| Questions about LSS architecture | Read [README.md](README.md) and [CHANGELOG.md](CHANGELOG.md) first; if the answer isn't there, open a Discussion |

Response time on free support: best-effort. We aim for under a week but make no commitment.

## Commercial Support

Included with paid licenses:

| Tier | Support included |
| --- | --- |
| **Solo** ($149) | 12 months of patch updates. Email support, 5 business day response target. |
| **Pro** ($499) | Lifetime patch updates. Email support, 2 business day response target. |
| **Enterprise** ($1,499) | Lifetime patch updates. Email + scheduled video support, next-business-day response. One 1-hour audit-day call per year. Source-available license. |

Commercial support email: `support@linuxsecuritysuite.com`

When emailing commercial support, include:

- Your license key (or the email the license was issued to)
- LSS version
- Distribution and version
- The command you ran and its output
- For `harden` / `rollback` issues: attach `/var/log/lss/journal/<run-id>.json`

## Security Issues

See [SECURITY.md](SECURITY.md). Do **not** report security vulnerabilities through GitHub Issues or commercial support email — use the dedicated `security@` address.

## What We Don't Support

- Custom CIS profile extensions beyond what ships in the published benchmarks
- Integrations with proprietary GRC platforms (Drata, Vanta, etc.) — those vendors should integrate with LSS, not the other way around
- Migrating from competing tools (Lynis, OpenSCAP) — LSS runs alongside them, no migration needed
- Changes to fix functions for site-specific needs — fork the source (Enterprise tier) or maintain a wrapper script
