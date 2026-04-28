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
    """Generate an HTML report from the most recent audit.

    With --baseline <path>, renders a before/after delta showing which
    controls flipped status between the baseline audit and the latest one.
    """
    latest = RESULTS_DIR / "audit-latest.json"
    if not latest.exists():
        err("no audit results found — run 'lss audit' first")
        return 1

    data = json.loads(latest.read_text())

    ts = data["timestamp"]
    host = data["host"]
    summary = data["summary"]
    controls = data["controls"]

    baseline_data = None
    baseline_path = getattr(args, "baseline", None)
    if baseline_path:
        bp = Path(baseline_path)
        if not bp.exists():
            err(f"baseline file not found: {baseline_path}")
            return 1
        try:
            baseline_data = json.loads(bp.read_text())
        except json.JSONDecodeError as exc:
            err(f"baseline file is not valid JSON: {exc}")
            return 1

    output_path = args.output or str(RESULTS_DIR / f"report-{ts}.html")

    html_text = _render(ts, host, summary, controls, baseline_data)
    Path(output_path).write_text(html_text)

    if baseline_data:
        info(f"Report (with delta vs {baseline_path}): {output_path}")
    else:
        info(f"Report: {output_path}")
    return 0


def _compute_delta(baseline_controls: list[dict], latest_controls: list[dict]) -> dict:
    """Build a status-transition map keyed by control id.

    Returns a dict: id -> {'before': status, 'after': status, 'change': category}
    where change is one of: 'fixed', 'regressed', 'still_failing', 'unchanged_pass',
    'unchanged_warn', 'unchanged_skip', 'new', 'removed'.
    """
    base_by_id = {c["id"]: c for c in baseline_controls}
    latest_by_id = {c["id"]: c for c in latest_controls}

    delta = {}
    all_ids = set(base_by_id) | set(latest_by_id)
    for cid in all_ids:
        b = base_by_id.get(cid)
        a = latest_by_id.get(cid)
        if b and not a:
            delta[cid] = {"before": b["status"], "after": None, "change": "removed"}
            continue
        if a and not b:
            delta[cid] = {"before": None, "after": a["status"], "change": "new"}
            continue
        before, after = b["status"], a["status"]
        if before == after:
            change = f"unchanged_{after}"
        elif before in ("fail", "warn") and after == "pass":
            change = "fixed"
        elif before == "pass" and after in ("fail", "warn"):
            change = "regressed"
        elif before == "fail" and after == "warn":
            change = "fixed"  # partial improvement counts as a fix
        elif before == "warn" and after == "fail":
            change = "regressed"
        else:
            change = f"unchanged_{after}"
        delta[cid] = {"before": before, "after": after, "change": change}
    return delta


def _delta_summary(delta: dict) -> dict:
    """Aggregate counts for the delta summary block."""
    counts = {"fixed": 0, "regressed": 0, "still_failing": 0, "unchanged_pass": 0,
              "unchanged_warn": 0, "unchanged_skip": 0, "new": 0, "removed": 0}
    for entry in delta.values():
        change = entry["change"]
        # Normalize "still_failing" — anything that started fail/warn and stayed fail/warn.
        if change in ("unchanged_fail", "unchanged_warn"):
            counts["still_failing"] += 1
            continue
        counts[change] = counts.get(change, 0) + 1
    return counts


def _status_pill(status: str) -> str:
    css_class = {"pass": "pass", "warn": "warn", "fail": "fail", "skip": "skip"}.get(status, "fail")
    label = _h(status).upper() if status else "—"
    return f'<span class="pill {css_class}">{label}</span>'


def _delta_block_html(delta_summary: dict | None, baseline_data: dict | None) -> str:
    """Render the before/after summary block. Empty string when no baseline."""
    if not delta_summary or not baseline_data:
        return ""
    baseline_ts = baseline_data.get("timestamp", "unknown")
    return f"""<div class="section-label">Change vs baseline ({_h(baseline_ts)})</div>
<div class="delta-row">
  <div class="stat fixed"><div class="n">{delta_summary.get('fixed', 0)}</div><div class="l">Fixed</div></div>
  <div class="stat regressed"><div class="n">{delta_summary.get('regressed', 0)}</div><div class="l">Regressed</div></div>
  <div class="stat still"><div class="n">{delta_summary.get('still_failing', 0)}</div><div class="l">Still failing</div></div>
  <div class="stat unchanged"><div class="n">{delta_summary.get('unchanged_pass', 0)}</div><div class="l">Unchanged pass</div></div>
</div>"""


def _table_head_html(with_delta: bool) -> str:
    if with_delta:
        return "    <tr><th>ID</th><th>Control</th><th>Before</th><th>After</th><th>Change</th><th>Detail</th></tr>"
    return "    <tr><th>ID</th><th>Control</th><th>Status</th><th>Detail</th></tr>"


def _change_pill(change: str) -> str:
    """Render the delta-change category as a styled pill."""
    label_map = {
        "fixed": ("Fixed", "fixed"),
        "regressed": ("Regressed", "regressed"),
        "still_failing": ("Still failing", "still"),
        "unchanged_pass": ("Unchanged", "still"),
        "unchanged_warn": ("Unchanged", "still"),
        "unchanged_skip": ("N/A", "still"),
        "new": ("New", "new"),
        "removed": ("Removed", "still"),
    }
    label, css = label_map.get(change, ("—", "still"))
    return f'<span class="pill change-{css}">{label}</span>'


def _render(ts: str, host: dict, summary: dict, controls: list[dict],
            baseline_data: dict | None = None) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    delta = None
    delta_summary = None
    if baseline_data is not None:
        delta = _compute_delta(baseline_data.get("controls", []), controls)
        delta_summary = _delta_summary(delta)

    rows = ""
    for c in controls:
        cid = c.get("id")
        if delta is not None:
            entry = delta.get(cid, {})
            before = entry.get("before")
            change = entry.get("change", "")
            rows += f"""      <tr>
        <td>{_h(cid)}</td>
        <td>{_h(c.get('title'))}</td>
        <td>{_status_pill(before) if before else '<span class="pill new">NEW</span>'}</td>
        <td>{_status_pill(c.get('status', ''))}</td>
        <td>{_change_pill(change)}</td>
        <td class="detail">{_h(c.get('detail', ''))}</td>
      </tr>\n"""
        else:
            rows += f"""      <tr>
        <td>{_h(cid)}</td>
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
  .pill.skip {{ background: var(--surface); color: var(--ink2); }}
  .pill.new {{ background: #e7eefe; color: var(--blue); }}
  .pill.change-fixed {{ background: var(--pass-bg); color: var(--pass); }}
  .pill.change-regressed {{ background: var(--fail-bg); color: var(--fail); }}
  .pill.change-still {{ background: var(--surface); color: var(--ink2); }}
  .pill.change-new {{ background: #e7eefe; color: var(--blue); }}
  .delta-row {{
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px;
  }}
  .delta-row .stat.fixed .n {{ color: var(--pass); }}
  .delta-row .stat.regressed .n {{ color: var(--fail); }}
  .delta-row .stat.still .n {{ color: var(--warn); }}
  .delta-row .stat.unchanged .n {{ color: var(--ink2); }}
  .section-label {{
    font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em;
    color: var(--ink2); font-weight: 600; margin: 24px 0 8px 0;
  }}
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

{_delta_block_html(delta_summary, baseline_data)}

<table>
  <thead>
{_table_head_html(delta is not None)}
  </thead>
  <tbody>
{rows}  </tbody>
</table>

<div class="footer">
  Generated {now} by The Linux Security Suite &mdash; linuxsecuritysuite.com
</div>

</body>
</html>"""
