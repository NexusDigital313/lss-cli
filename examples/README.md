# Examples

## sample-audit-report.html

A sample LSS audit report rendered from synthetic data — what an operator sees after running `sudo lss audit && sudo lss report`. Open it in a browser to evaluate the report quality before purchasing.

The data is synthetic (deterministic seed) and represents a typical fresh Debian 12 box: 116 pass / 33 warn / 44 fail / 11 skip across 204 controls, score 60%. A real audit on a hardened box would obviously score higher.
