"""HTML report generator for LSS audit results."""

from __future__ import annotations

import html
import json
import socket
from datetime import datetime, timezone
from pathlib import Path

from lss import __version__
from lss.lib.output import info, err, DIM, RESET


RESULTS_DIR = Path("/var/log/lss")


def _h(value) -> str:
    """HTML-escape any value (handles None/non-strings safely)."""
    return html.escape(str(value if value is not None else ""), quote=True)


def run_report(args) -> int:
    """Generate an HTML report from the most recent audit."""
    latest = RESULTS_DIR / "audit-latest.json"
    if not latest.exists():
        err("no audit results found — run 'lss audit' first")
        return 1

    data = json.loads(latest.read_text())

    ts = data["timestamp"]
    host = data["host"]
    summary = data["summary"]
    controls = data["controls"]

    output_path = args.output or str(RESULTS_DIR / f"report-{ts}.html")

    html = _render(ts, host, summary, controls)
    Path(output_path).write_text(html)

    info(f"Report: {output_path}")
    return 0


def _status_pill(status: str) -> str:
    css_class = {"pass": "pass", "warn": "warn", "fail": "fail"}.get(status, "fail")
    return f'<span class="pill {css_class}">{_h(status).upper()}</span>'


def _render(ts: str, host: dict, summary: dict, controls: list[dict]) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    rows = ""
    for c in controls:
        rows += f"""      <tr>
        <td>{_h(c.get('id'))}</td>
        <td>{_h(c.get('title'))}</td>
        <td>{_status_pill(c.get('status', ''))}</td>
        <td class="detail">{_h(c.get('detail', ''))}</td>
      </tr>\n"""

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>LSS Audit Report — {_h(host.get('name', 'unknown'))}</title>
<style>
  :root {{
    --bg: #ffffff;
    --ink: #1c2330;
    --ink2: #5b6675;
    --line: #e7ebf1;
    --surface: #f2f5f9;
    --pass: #0c8a5a;
    --pass-bg: #dff7ec;
    --warn: #8a6300;
    --warn-bg: #fff1d6;
    --fail: #b3263a;
    --fail-bg: #fde2e6;
    --blue: #2a5fcc;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 14px; line-height: 1.5; color: var(--ink);
    max-width: 960px; margin: 0 auto; padding: 40px 28px;
  }}
  .header {{
    display: flex; justify-content: space-between; align-items: flex-start;
    border-bottom: 3px solid var(--ink); padding-bottom: 20px; margin-bottom: 32px;
  }}
  .header h1 {{ font-size: 22px; letter-spacing: -0.01em; }}
  .header .meta {{ text-align: right; font-size: 12px; color: var(--ink2);
    font-family: 'Courier New', monospace; }}
  .stat-row {{
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px;
  }}
  .stat {{
    text-align: center; padding: 16px 8px; border-radius: 8px; background: var(--surface);
  }}
  .stat .n {{ font-size: 28px; font-weight: 700; }}
  .stat .l {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em;
    color: var(--ink2); margin-top: 4px; }}
  .stat.ok .n {{ color: var(--pass); }}
  .stat.warn .n {{ color: var(--warn); }}
  .stat.bad .n {{ color: var(--fail); }}
  table {{
    width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 32px;
  }}
  th {{
    text-align: left; padding: 10px 10px; background: var(--surface);
    font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em;
    color: var(--ink2); font-weight: 600; border-bottom: 2px solid var(--line);
  }}
  td {{
    padding: 10px 10px; border-bottom: 1px solid var(--line);
  }}
  td.detail {{ color: var(--ink2); font-family: 'Courier New', monospace; font-size: 12px; }}
  .pill {{
    display: inline-block; padding: 2px 10px; border-radius: 4px;
    font-size: 11px; font-weight: 600; letter-spacing: 0.04em;
  }}
  .pill.pass {{ background: var(--pass-bg); color: var(--pass); }}
  .pill.warn {{ background: var(--warn-bg); color: var(--warn); }}
  .pill.fail {{ background: var(--fail-bg); color: var(--fail); }}
  .footer {{
    border-top: 1px solid var(--line); padding-top: 16px; margin-top: 40px;
    font-size: 12px; color: var(--ink2);
  }}
  @media print {{
    body {{ padding: 20px; }}
    .stat-row {{ break-inside: avoid; }}
    tr {{ break-inside: avoid; }}
  }}
</style>
</head>
<body>

<div class="header">
  <div>
    <div style="font-size:12px;text-transform:uppercase;letter-spacing:0.1em;color:var(--ink2);margin-bottom:6px;font-weight:600">
      Hardening Audit Report
    </div>
    <h1>{_h(host.get('name', 'unknown'))}</h1>
  </div>
  <div class="meta">
    {_h(ts)}<br/>
    Linux Security Suite v{_h(__version__)}<br/>
    Kernel: {_h(host.get('kernel', 'unknown'))}
  </div>
</div>

<div class="stat-row">
  <div class="stat ok"><div class="n">{int(summary.get('pass', 0))}</div><div class="l">Pass</div></div>
  <div class="stat warn"><div class="n">{int(summary.get('warn', 0))}</div><div class="l">Warn</div></div>
  <div class="stat bad"><div class="n">{int(summary.get('fail', 0))}</div><div class="l">Fail</div></div>
  <div class="stat"><div class="n">{int(summary.get('score', 0))}%</div><div class="l">Score</div></div>
</div>

<table>
  <thead>
    <tr><th>ID</th><th>Control</th><th>Status</th><th>Detail</th></tr>
  </thead>
  <tbody>
{rows}  </tbody>
</table>

<div class="footer">
  Generated {now} by The Linux Security Suite &mdash; linuxsecuritysuite.com
</div>

</body>
</html>"""
