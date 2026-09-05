# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized reproduction, copying, modification, distribution,
# redistribution, publication, reverse engineering, decompilation, or
# disassembly of this file, in whole or in part, via any medium, is
# strictly prohibited without explicit prior written authorization.

"""HTML report generator for LSS audit results."""

from __future__ import annotations

import html
import json
import socket
from datetime import datetime, timezone
from pathlib import Path

from lss import __version__
from lss.lib.output import info, err, warn, DIM, RESET
from lss.lib.paths import (
    chown_to_invoking_user,
    default_html_report_dir,
    ensure_report_dir,
    file_uri,
    open_in_browser,
)


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
        # Schema check — older LSS versions may have used different shapes,
        # and a corrupted JSON could parse but lack the expected keys.
        if not isinstance(baseline_data, dict) or "controls" not in baseline_data:
            err(f"baseline file has unrecognized schema (no 'controls' key): "
                f"{baseline_path}. May be from an older LSS version; re-run "
                f"audit on the prior state to regenerate, or use a newer baseline.")
            return 1
        if not isinstance(baseline_data.get("controls"), list):
            err(f"baseline 'controls' field is not a list in {baseline_path}.")
            return 1
        # Cross-host warning — control IDs match between hosts but the
        # comparison only makes sense on the same host. Surface a soft warning
        # rather than block, since some compliance workflows compare
        # equivalently-configured fleets intentionally.
        base_host = baseline_data.get("host", {})
        if isinstance(base_host, dict) and base_host.get("name") and base_host.get("name") != host.get("name"):
            warn(f"baseline host '{base_host.get('name')}' differs from current host "
                 f"'{host.get('name')}' — delta may compare unrelated configurations.")

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        report_dir = ensure_report_dir(default_html_report_dir())
        output_path = report_dir / f"report-{ts}.html"

    html_text = _render(ts, host, summary, controls, baseline_data)
    output_path.write_text(html_text)
    chown_to_invoking_user(output_path)

    label = f"Report (with delta vs {baseline_path})" if baseline_data else "Report"
    info(f"{label}: {file_uri(output_path)}")

    if getattr(args, "open", False):
        if not open_in_browser(output_path):
            warn("could not launch a browser; open the URL above manually")

    return 0


def write_html_report(data: dict, baseline_data: dict | None = None,
                      output_path: Path | None = None) -> Path:
    """Render and persist an HTML report. Returns the path written.

    Used by `lss audit` to emit a customer-readable report alongside the
    JSON audit log without going through the `lss report` CLI gate.
    Caller is responsible for printing the path.
    """
    ts = data["timestamp"]
    if output_path is None:
        report_dir = ensure_report_dir(default_html_report_dir())
        output_path = report_dir / f"report-{ts}.html"
    else:
        output_path.parent.mkdir(parents=True, exist_ok=True)

    html_text = _render(ts, data["host"], data["summary"], data["controls"],
                        baseline_data)
    output_path.write_text(html_text)
    chown_to_invoking_user(output_path)
    return output_path


_KNOWN_STATUSES = {"pass", "fail", "warn", "manual", "skip"}

_SECTION_TITLES = {
    "filesystem": "Filesystem", "kernel": "Kernel Hardening",
    "banners": "Warning Banners", "boot": "Boot & Packages",
    "services": "Services", "network": "Network & Firewall",
    "logging": "Logging & Auditing", "cron": "Cron & Scheduling",
    "ssh": "SSH Server", "auth": "Authentication & Passwords",
    "users": "Users & Groups",
}


def _compute_delta(baseline_controls: list[dict], latest_controls: list[dict]) -> dict:
    """Build a status-transition map keyed by control id.

    Returns a dict: id -> {'before': status, 'after': status, 'change': category}
    where change is one of: 'fixed', 'improved', 'regressed', 'still_failing',
    'unchanged_pass', 'unchanged_skip', 'new', 'removed', 'malformed', 'unknown'.

    Distinguishes 'fixed' (X -> pass) from 'improved' (fail -> warn) so a
    partial improvement isn't misreported to a compliance auditor as a full
    pass. Unknown/missing status values are bucketed separately rather than
    silently classified — a future status would otherwise vanish into the
    'unchanged_<status>' fallback.
    """
    base_by_id = {c.get("id"): c for c in baseline_controls if c.get("id")}
    latest_by_id = {c.get("id"): c for c in latest_controls if c.get("id")}

    delta = {}
    all_ids = set(base_by_id) | set(latest_by_id)
    for cid in all_ids:
        b = base_by_id.get(cid)
        a = latest_by_id.get(cid)

        before = b.get("status") if b else None
        after = a.get("status") if a else None

        if before is not None and after is None:
            delta[cid] = {"before": before, "after": None, "change": "removed"}
            continue
        if after is not None and before is None:
            delta[cid] = {"before": None, "after": after, "change": "new"}
            continue
        if before is None and after is None:
            delta[cid] = {"before": None, "after": None, "change": "malformed"}
            continue

        if before not in _KNOWN_STATUSES or after not in _KNOWN_STATUSES:
            change = "unknown"
        elif before == after:
            change = f"unchanged_{after}"
        elif after == "pass":
            change = "fixed"
        elif before == "pass":
            change = "regressed"
        elif before == "fail" and after == "warn":
            change = "improved"
        elif before == "warn" and after == "fail":
            change = "regressed"
        elif before == "skip" or after == "skip":
            change = "changed"
        else:
            change = "changed"

        delta[cid] = {"before": before, "after": after, "change": change}
    return delta


def _delta_summary(delta: dict) -> dict:
    """Aggregate counts for the delta summary block.

    `still_failing` folds in unchanged_fail and unchanged_warn (a control that
    was failing and is still failing/warning is the actionable category for
    the operator). unchanged_warn is intentionally NOT a separate top-level
    count to avoid double-counting against still_failing.
    """
    counts = {
        "fixed": 0, "improved": 0, "regressed": 0, "still_failing": 0,
        "unchanged_pass": 0, "unchanged_skip": 0,
        "new": 0, "removed": 0,
        "changed": 0, "unknown": 0, "malformed": 0,
    }
    for entry in delta.values():
        change = entry["change"]
        if change in ("unchanged_fail", "unchanged_warn"):
            counts["still_failing"] += 1
        else:
            counts[change] = counts.get(change, 0) + 1
    return counts


def _status_pill(status: str) -> str:
    css_class = {
        "pass": "pass", "warn": "warn", "fail": "fail",
        "manual": "manual", "skip": "skip",
    }.get(status, "fail")
    label = _h(status).upper() if status else "—"
    return f'<span class="pill {css_class}">{label}</span>'


def _change_pill(change: str) -> str:
    """Render the delta-change category as a styled pill."""
    label_map = {
        "fixed": ("Fixed", "fixed"),
        "improved": ("Improved", "improved"),
        "regressed": ("Regressed", "regressed"),
        "still_failing": ("Still failing", "still"),
        "unchanged_pass": ("Unchanged", "still"),
        "unchanged_warn": ("Still warning", "still"),
        "unchanged_fail": ("Still failing", "still"),
        "unchanged_skip": ("N/A", "still"),
        "new": ("New", "new"),
        "removed": ("Removed", "still"),
        "changed": ("Changed", "still"),
        "unknown": ("Unknown", "still"),
        "malformed": ("Malformed", "still"),
    }
    label, css = label_map.get(change, ("—", "still"))
    return f'<span class="pill change-{css}">{label}</span>'


def _delta_block_html(delta_summary: dict | None, baseline_data: dict | None) -> str:
    """Render the before/after summary block. Empty string when no baseline."""
    if not delta_summary or not baseline_data:
        return ""
    baseline_ts = _human_ts(baseline_data.get("timestamp", "unknown"))
    improved = delta_summary.get('improved', 0)
    improved_block = (
        f'  <div class="stat improved"><div class="n">{improved}</div>'
        f'<div class="l">Improved</div></div>\n'
    ) if improved else ""
    return f"""<div class="section-label">Change vs baseline ({baseline_ts})</div>
<div class="delta-row">
  <div class="stat fixed"><div class="n">{delta_summary.get('fixed', 0)}</div><div class="l">Fixed</div></div>
{improved_block}  <div class="stat regressed"><div class="n">{delta_summary.get('regressed', 0)}</div><div class="l">Regressed</div></div>
  <div class="stat still"><div class="n">{delta_summary.get('still_failing', 0)}</div><div class="l">Still failing</div></div>
  <div class="stat unchanged"><div class="n">{delta_summary.get('unchanged_pass', 0)}</div><div class="l">Unchanged pass</div></div>
</div>"""


# ---------------------------------------------------------------------------
# New report building blocks
# ---------------------------------------------------------------------------
def _human_ts(ts) -> str:
    """Parse an audit timestamp into a human-readable date; fall back to raw."""
    for fmt in ("%Y%m%dT%H%M%SZ", "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H-%M-%S"):
        try:
            return datetime.strptime(str(ts), fmt).strftime("%B %d, %Y · %H:%M UTC")
        except (ValueError, TypeError):
            continue
    return _h(ts)


def _verdict(score: int) -> tuple[str, str]:
    if score >= 90:
        return "Hardened", "good"
    if score >= 70:
        return "Needs work", "warn"
    return "At risk", "bad"


def _grouped(controls: list[dict]):
    """Yield (section_title, [controls]) in canonical CIS order, extras last."""
    buckets: dict[str, list] = {}
    for c in controls:
        buckets.setdefault(c.get("section", ""), []).append(c)
    seen = set()
    for key in _SECTION_TITLES:
        if key in buckets:
            seen.add(key)
            yield _SECTION_TITLES[key], buckets[key]
    for key, items in buckets.items():
        if key not in seen:
            yield (_SECTION_TITLES.get(key) or (key.title() if key else "Other"), items)


def _remediation_rows(items: list[dict]) -> str:
    rows = ""
    for c in items:
        rows += (
            f'      <tr><td class="cid">{_h(c.get("id"))}</td>'
            f'<td>{_h(c.get("title"))}</td>'
            f'<td class="rem">{_h(c.get("detail", "")) or "&mdash;"}</td></tr>\n'
        )
    return rows


def _priority_html(controls: list[dict]) -> str:
    fails = [c for c in controls if c.get("status") == "fail"]
    if not fails:
        return ('<div class="section-label">Fix these first</div>'
                '<p class="ok-note">&#10003; No failing controls — nothing to auto-fix.</p>')
    return f"""<div class="section-label">Fix these first &nbsp;·&nbsp; {len(fails)} failing, all auto-fixable</div>
<p class="lead">Apply every fix below with one command. Each change is journaled and reversible
with <code>sudo lss rollback --last</code>.</p>
<pre class="cmd">sudo lss harden --confirm</pre>
<table class="grid">
  <thead><tr><th>ID</th><th>Control</th><th>What&rsquo;s wrong</th></tr></thead>
  <tbody>
{_remediation_rows(fails)}  </tbody>
</table>"""


def _manual_html(controls: list[dict]) -> str:
    manuals = [c for c in controls if c.get("status") == "manual"]
    if not manuals:
        return ""
    return f"""<div class="section-label">Manual review required &nbsp;·&nbsp; {len(manuals)}</div>
<p class="lead">LSS will not auto-apply these — they carry a lockout or breakage risk and need an
operator decision. Remediation guidance is included for each.</p>
<table class="grid">
  <thead><tr><th>ID</th><th>Control</th><th>How to remediate</th></tr></thead>
  <tbody>
{_remediation_rows(manuals)}  </tbody>
</table>"""


def _coverage_html(controls: list[dict]) -> str:
    agg: dict[str, list] = {}
    for c in controls:
        if c.get("status") == "skip":
            continue
        a = agg.setdefault(c.get("section", ""), [0, 0])
        a[1] += 1
        if c.get("status") == "pass":
            a[0] += 1
    if not agg:
        return ""
    order = [k for k in _SECTION_TITLES if k in agg] + [k for k in agg if k not in _SECTION_TITLES]
    rows = ""
    for k in order:
        passed, applicable = agg[k]
        pct = round(passed / applicable * 100) if applicable else 0
        cls = "good" if pct >= 90 else "warn" if pct >= 60 else "bad"
        name = _SECTION_TITLES.get(k) or (k.title() if k else "Other")
        rows += (
            f'  <div class="cov-row"><div class="cov-name">{_h(name)}</div>'
            f'<div class="cov-track"><div class="cov-fill {cls}" style="width:{pct}%"></div></div>'
            f'<div class="cov-n">{passed}/{applicable}</div></div>\n'
        )
    return f'<div class="section-label">Coverage by section</div>\n<div class="cov">\n{rows}</div>'


def _full_table_html(controls: list[dict], delta: dict | None) -> str:
    with_delta = delta is not None
    span = 6 if with_delta else 4
    head = ("<tr><th>ID</th><th>Control</th><th>Before</th><th>After</th><th>Change</th><th>Detail</th></tr>"
            if with_delta else "<tr><th>ID</th><th>Control</th><th>Status</th><th>Detail</th></tr>")
    body = ""
    for title, items in _grouped(controls):
        body += f'      <tr class="sec"><td colspan="{span}">{_h(title)}</td></tr>\n'
        for c in items:
            cid = c.get("id")
            detail = f'<td class="detail">{_h(c.get("detail", ""))}</td>'
            if with_delta:
                entry = delta.get(cid, {})
                before = entry.get("before")
                before_cell = _status_pill(before) if before else '<span class="pill new">NEW</span>'
                body += (
                    f'      <tr><td class="cid">{_h(cid)}</td><td>{_h(c.get("title"))}</td>'
                    f'<td>{before_cell}</td><td>{_status_pill(c.get("status", ""))}</td>'
                    f'<td>{_change_pill(entry.get("change", ""))}</td>{detail}</tr>\n'
                )
            else:
                body += (
                    f'      <tr><td class="cid">{_h(cid)}</td><td>{_h(c.get("title"))}</td>'
                    f'<td>{_status_pill(c.get("status", ""))}</td>{detail}</tr>\n'
                )
    return f'<table class="grid full">\n  <thead>{head}</thead>\n  <tbody>\n{body}  </tbody>\n</table>'


def _render(ts: str, host: dict, summary: dict, controls: list[dict],
            baseline_data: dict | None = None) -> str:
    now = datetime.now(timezone.utc).strftime("%B %d, %Y · %H:%M UTC")

    delta = None
    delta_summary = None
    if baseline_data is not None:
        delta = _compute_delta(baseline_data.get("controls", []), controls)
        delta_summary = _delta_summary(delta)

    score = int(summary.get("score", 0))
    comp = int(summary.get("compliance_score", summary.get("score", 0)))
    verdict, vcls = _verdict(score)
    p = int(summary.get("pass", 0))
    w = int(summary.get("warn", 0))
    f = int(summary.get("fail", 0))
    m = int(summary.get("manual", 0))
    s = int(summary.get("skip", 0))
    total = int(summary.get("total", p + w + f + m + s))

    host_name = _h(host.get("name", "unknown"))
    fail_clause = (f"<strong>{f}</strong> failed (auto-fixable)" if f
                   else "<strong>0</strong> failed")
    manual_clause = (f", and <strong>{m}</strong> need manual review" if m else "")
    exec_summary = (
        f"Audited <strong>{total}</strong> CIS-aligned controls on {host_name} "
        f"({_human_ts(ts)}). <strong>{p}</strong> passed, {fail_clause}{manual_clause}. "
        f"Overall hardened score <strong>{score}%</strong>."
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>LSS Audit Report — {host_name}</title>
<style>
  :root {{
    --bg:#ffffff; --ink:#161c26; --ink2:#5b6675; --ink3:#8a94a3;
    --line:#e7ebf1; --surface:#f5f7fa; --accent:#0b6e6e;
    --good:#0c8a5a; --good-bg:#e4f7ee; --warn:#9a6b00; --warn-bg:#fff3d6;
    --bad:#c02a3e; --bad-bg:#fde3e7; --manual:#9a5a00; --manual-bg:#fff1da; --blue:#2a5fcc;
  }}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Inter,sans-serif;
    font-size:14px; line-height:1.55; color:var(--ink); background:var(--bg);
    max-width:920px; margin:0 auto; padding:48px 32px; }}
  .eyebrow {{ font-size:11px; text-transform:uppercase; letter-spacing:.14em;
    color:var(--accent); font-weight:700; margin-bottom:6px; }}
  .header {{ display:flex; justify-content:space-between; align-items:flex-start;
    border-bottom:1px solid var(--line); padding-bottom:22px; margin-bottom:28px; }}
  .header h1 {{ font-size:25px; letter-spacing:-.02em; font-weight:700; }}
  .header .meta {{ text-align:right; font-size:12px; color:var(--ink2); line-height:1.7; }}
  .verdict {{ display:flex; align-items:center; gap:24px; padding:22px 26px; border-radius:14px;
    border:1px solid var(--line); border-left:6px solid var(--ink2); margin-bottom:14px; }}
  .verdict.good {{ border-left-color:var(--good); background:var(--good-bg); }}
  .verdict.warn {{ border-left-color:var(--warn); background:var(--warn-bg); }}
  .verdict.bad {{ border-left-color:var(--bad); background:var(--bad-bg); }}
  .verdict .score {{ font-size:46px; font-weight:800; letter-spacing:-.03em; line-height:1; }}
  .verdict.good .score {{ color:var(--good); }} .verdict.warn .score {{ color:var(--warn); }}
  .verdict.bad .score {{ color:var(--bad); }}
  .verdict .word {{ font-size:13px; text-transform:uppercase; letter-spacing:.1em; font-weight:700;
    margin-top:6px; color:var(--ink2); }}
  .verdict .track {{ height:9px; border-radius:6px; background:rgba(0,0,0,.08); overflow:hidden; margin:8px 0 4px; }}
  .verdict .fill {{ height:100%; border-radius:6px; }}
  .verdict.good .fill {{ background:var(--good); }} .verdict.warn .fill {{ background:var(--warn); }}
  .verdict.bad .fill {{ background:var(--bad); }}
  .verdict .sub {{ font-size:12px; color:var(--ink2); }}
  .summary {{ font-size:15px; color:var(--ink); margin:18px 2px 30px; line-height:1.6; }}
  .stat-row {{ display:grid; grid-template-columns:repeat(5,1fr); gap:10px; margin-bottom:34px; }}
  .stat {{ text-align:center; padding:14px 8px; border-radius:10px; background:var(--surface); }}
  .stat .n {{ font-size:24px; font-weight:700; }}
  .stat .l {{ font-size:10px; text-transform:uppercase; letter-spacing:.08em; color:var(--ink2); margin-top:3px; }}
  .stat.ok .n {{ color:var(--good); }} .stat.warn .n {{ color:var(--warn); }}
  .stat.bad .n {{ color:var(--bad); }} .stat.manual .n {{ color:var(--manual); }} .stat.skip .n {{ color:var(--ink3); }}
  .section-label {{ font-size:12px; text-transform:uppercase; letter-spacing:.09em; color:var(--ink);
    font-weight:700; margin:34px 0 12px; padding-bottom:8px; border-bottom:2px solid var(--line); }}
  .lead {{ color:var(--ink2); margin-bottom:14px; max-width:680px; }}
  .ok-note {{ color:var(--good); font-weight:600; }}
  code {{ font-family:'JetBrains Mono','SF Mono',Menlo,monospace; font-size:12px;
    background:var(--surface); padding:1px 6px; border-radius:5px; }}
  pre.cmd {{ font-family:'JetBrains Mono','SF Mono',Menlo,monospace; font-size:13px; color:#e6f1ef;
    background:#10211f; padding:12px 16px; border-radius:9px; margin-bottom:16px; }}
  table.grid {{ width:100%; border-collapse:collapse; font-size:13px; margin-bottom:8px; }}
  table.grid th {{ text-align:left; padding:9px 10px; font-size:10px; text-transform:uppercase;
    letter-spacing:.08em; color:var(--ink2); font-weight:600; border-bottom:2px solid var(--line); }}
  table.grid td {{ padding:9px 10px; border-bottom:1px solid var(--line); vertical-align:top; }}
  td.cid {{ font-family:'JetBrains Mono',Menlo,monospace; font-size:12px; color:var(--ink2); white-space:nowrap; }}
  td.detail, td.rem {{ color:var(--ink2); font-size:12.5px; }}
  tr.sec td {{ background:var(--surface); font-weight:700; font-size:11px; text-transform:uppercase;
    letter-spacing:.07em; color:var(--accent); padding:8px 10px; border-bottom:1px solid var(--line); }}
  .pill {{ display:inline-block; padding:2px 9px; border-radius:5px; font-size:10px; font-weight:700; letter-spacing:.04em; }}
  .pill.pass {{ background:var(--good-bg); color:var(--good); }}
  .pill.warn {{ background:var(--warn-bg); color:var(--warn); }}
  .pill.fail {{ background:var(--bad-bg); color:var(--bad); }}
  .pill.manual {{ background:var(--manual-bg); color:var(--manual); }}
  .pill.skip {{ background:var(--surface); color:var(--ink3); }}
  .pill.new {{ background:#e7eefe; color:var(--blue); }}
  .pill.change-fixed {{ background:var(--good-bg); color:var(--good); }}
  .pill.change-improved {{ background:var(--warn-bg); color:var(--warn); }}
  .pill.change-regressed {{ background:var(--bad-bg); color:var(--bad); }}
  .pill.change-still {{ background:var(--surface); color:var(--ink2); }}
  .pill.change-new {{ background:#e7eefe; color:var(--blue); }}
  .cov {{ margin-bottom:14px; }}
  .cov-row {{ display:grid; grid-template-columns:200px 1fr 56px; align-items:center; gap:14px; padding:5px 0; }}
  .cov-name {{ font-size:13px; color:var(--ink); }}
  .cov-track {{ height:9px; border-radius:6px; background:var(--surface); overflow:hidden; }}
  .cov-fill {{ height:100%; border-radius:6px; }}
  .cov-fill.good {{ background:var(--good); }} .cov-fill.warn {{ background:var(--warn); }} .cov-fill.bad {{ background:var(--bad); }}
  .cov-n {{ text-align:right; font-size:12px; color:var(--ink2); font-family:'JetBrains Mono',Menlo,monospace; }}
  .delta-row {{ display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin-bottom:8px; }}
  .delta-row .stat.fixed .n {{ color:var(--good); }} .delta-row .stat.improved .n {{ color:var(--warn); }}
  .delta-row .stat.regressed .n {{ color:var(--bad); }} .delta-row .stat.still .n {{ color:var(--warn); }}
  .delta-row .stat.unchanged .n {{ color:var(--ink2); }}
  .footer {{ border-top:1px solid var(--line); padding-top:16px; margin-top:44px; font-size:11.5px; color:var(--ink3); }}
  @media print {{ body {{ padding:24px; }} .verdict,.stat,tr,.cov-row {{ break-inside:avoid; }} tr.sec {{ break-after:avoid; }} }}
</style>
</head>
<body>

<div class="header">
  <div>
    <div class="eyebrow">CIS Hardening Audit</div>
    <h1>{host_name}</h1>
  </div>
  <div class="meta">
    {_human_ts(ts)}<br/>
    Linux Security Suite v{_h(__version__)}<br/>
    Kernel {_h(host.get('kernel', 'unknown'))}
  </div>
</div>

<div class="verdict {vcls}">
  <div><div class="score">{score}%</div><div class="word">{_h(verdict)}</div></div>
  <div style="flex:1">
    <div class="track"><div class="fill" style="width:{score}%"></div></div>
    <div class="sub">Hardened score &nbsp;·&nbsp; {comp}% full compliance (incl. manual-review items)</div>
  </div>
</div>

<p class="summary">{exec_summary}</p>

<div class="stat-row">
  <div class="stat ok"><div class="n">{p}</div><div class="l">Pass</div></div>
  <div class="stat warn"><div class="n">{w}</div><div class="l">Warn</div></div>
  <div class="stat bad"><div class="n">{f}</div><div class="l">Fail</div></div>
  <div class="stat manual"><div class="n">{m}</div><div class="l">Manual</div></div>
  <div class="stat skip"><div class="n">{s}</div><div class="l">N/A</div></div>
</div>

{_delta_block_html(delta_summary, baseline_data)}

{_priority_html(controls)}

{_manual_html(controls)}

{_coverage_html(controls)}

<div class="section-label">Full results</div>
{_full_table_html(controls, delta)}

<div class="footer">
  Generated {now} by The Linux Security Suite v{_h(__version__)} · read-only audit · no data leaves this host
</div>

</body>
</html>"""
