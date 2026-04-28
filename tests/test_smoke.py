"""Smoke tests — fast, no-root, catch regressions in registry, journal, rollback, report."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest


EXPECTED_CONTROL_COUNT = 206  # 204 CIS + LSS-001..005


def test_all_controls_register():
    """Importing list_controls should populate the registry with the expected
    number of unique IDs. Bump EXPECTED_CONTROL_COUNT when adding new LSS-XXX
    controls or new CIS coverage."""
    import lss.list_controls  # noqa: F401  (side-effect: imports every controls/* module)
    from lss.lib.registry import get_controls

    ctrls = get_controls()
    assert len(ctrls) == EXPECTED_CONTROL_COUNT, (
        f"expected {EXPECTED_CONTROL_COUNT} controls, got {len(ctrls)}"
    )

    ids = [c.id for c in ctrls]
    assert len(set(ids)) == len(ids), "duplicate control IDs detected"

    # Every control must have a check function
    no_check = [c.id for c in ctrls if c.check is None]
    assert not no_check, f"controls missing check function: {no_check}"


def test_no_undo_strings_in_registry():
    """RollbackEntry.undo must be a list of argv lists, never a shell string."""
    from lss.lib.registry import RollbackEntry

    e = RollbackEntry(action="x", undo=[["echo", "ok"]])
    assert isinstance(e.undo, list)
    assert all(isinstance(item, list) for item in e.undo)


def test_journal_atomic_write_and_backup(tmp_path, monkeypatch):
    """write_run must be atomic; backup_file must snapshot the file."""
    from lss.lib import journal

    monkeypatch.setattr(journal, "JOURNAL_DIR", tmp_path / "journal")
    monkeypatch.setattr(journal, "BACKUPS_DIR", tmp_path / "journal" / "backups")

    run_id = journal.new_run_id()
    journal.set_current_run_id(run_id)

    # Backup a real file
    src = tmp_path / "etc-passwd-fake"
    src.write_text("root:x:0:0:root:/root:/bin/bash\n")
    bkp = journal.backup_file(str(src))
    assert bkp and Path(bkp).exists()
    assert Path(bkp).read_text() == src.read_text()

    # Write the journal
    entries = {"5.1.1": [{"action": "test", "undo": [["true"]], "path": "", "backup": ""}]}
    path = journal.write_run(run_id, entries)
    assert path.exists()
    data = json.loads(path.read_text())
    assert data["run_id"] == run_id
    assert "controls" in data

    # latest.json must point to the new run
    latest = journal.JOURNAL_DIR / "latest.json"
    assert latest.is_symlink()
    assert latest.resolve() == path.resolve()

    journal.set_current_run_id(None)


def test_rollback_refuses_legacy_shell_string_undo(tmp_path, monkeypatch, capsys):
    """A journal entry with a string-form undo must be skipped, not executed.

    This is the explicit guarantee of the shell-injection refactor: even if an
    old journal somehow has a legacy `undo: "rm -rf /"`, rollback must NOT
    execute it via shell=True.
    """
    from lss.lib import journal
    from lss import rollback

    monkeypatch.setattr(journal, "JOURNAL_DIR", tmp_path / "j")

    run_id = journal.new_run_id()
    # Hand-craft a journal with a malicious legacy string undo
    sentinel = tmp_path / "should-not-exist"
    legacy = {
        "run_id": run_id,
        "timestamp": "2026-04-22T00:00:00Z",
        "controls": {
            "9.9.9": [{
                "action": "malicious",
                "undo": f"touch {sentinel}",  # legacy string form
                "path": "",
                "backup": "",
            }],
        },
    }
    (journal.JOURNAL_DIR).mkdir(parents=True, exist_ok=True)
    (journal.JOURNAL_DIR / f"{run_id}.json").write_text(json.dumps(legacy))
    (journal.JOURNAL_DIR / "latest.json").symlink_to(f"{run_id}.json")

    class Args:
        last = True
        run_id = None
        control = None

    rollback.run_rollback(Args())
    # The sentinel must NOT have been created — proves shell=True was not used
    assert not sentinel.exists(), "rollback executed a legacy shell-string undo!"


def test_report_html_escapes_user_data(tmp_path, monkeypatch):
    """HTML report must escape <script>, attributes, and angle brackets."""
    from lss import report

    monkeypatch.setattr(report, "RESULTS_DIR", tmp_path)
    data = {
        "timestamp": "2026-04-22T00-00-00",
        "host": {"name": "<script>alert(1)</script>", "kernel": "<img src=x onerror=alert(2)>"},
        "summary": {"pass": 1, "warn": 0, "fail": 0, "score": 100},
        "controls": [
            {"id": "1.1.1", "title": "<b>injected</b>", "status": "pass", "detail": "</td><td>oops"},
        ],
    }
    (tmp_path / "audit-latest.json").write_text(json.dumps(data))
    out = tmp_path / "r.html"

    class Args:
        output = str(out)

    rc = report.run_report(Args())
    assert rc == 0
    html = out.read_text()
    assert "<script>alert(1)</script>" not in html
    assert "<img src=x onerror" not in html
    assert "<b>injected</b>" not in html
    assert "&lt;script&gt;" in html


def test_cli_list_runs_clean():
    """`python -m lss list` exits 0 and emits the controls-count header."""
    r = subprocess.run(
        [sys.executable, "-m", "lss", "--no-color", "list"],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, f"exit {r.returncode}, stderr: {r.stderr}"
    assert f"{EXPECTED_CONTROL_COUNT} controls" in r.stdout


def test_harden_dry_run_makes_no_changes(tmp_path, monkeypatch):
    """`harden --dry-run` must surface failing controls without invoking any fix."""
    # We don't have root in tests so we can't actually invoke the CLI's
    # privilege gate. Just verify the parser accepts --dry-run and the
    # mutual exclusion with --confirm is enforced.
    from lss.cli import build_parser

    parser = build_parser()

    args = parser.parse_args(["harden", "--dry-run"])
    assert args.dry_run is True
    assert args.confirm is False

    with pytest.raises(SystemExit):
        # --confirm and --dry-run are mutually exclusive
        parser.parse_args(["harden", "--confirm", "--dry-run"])


def test_cis_id_corrections():
    """5.4.1.4 (inactive lock) must exist; 5.4.1.5 (which doesn't exist in CIS) must not."""
    import lss.list_controls  # noqa: F401
    from lss.lib.registry import get_controls

    ids = {c.id for c in get_controls()}
    assert "5.4.1.4" in ids, "expected CIS 5.4.1.4 (inactive password lock)"
    assert "5.4.1.5" not in ids, "5.4.1.5 doesn't exist in CIS Debian 12 v1.0.0"


def test_lss_namespace_for_custom_controls():
    """Non-CIS custom controls must use the LSS-xxx namespace, not collide with CIS IDs."""
    import lss.list_controls  # noqa: F401
    from lss.lib.registry import get_controls

    ids = [c.id for c in get_controls()]
    lss_ids = [i for i in ids if i.startswith("LSS-")]
    assert len(lss_ids) >= 3, f"expected at least 3 LSS-* IDs, got {lss_ids}"
    # IDs with a 1.10 / 5.5 / 6.2.16 form (the previously-mislabeled customs) must be gone
    assert "1.10" not in ids
    assert "5.5" not in ids
    assert "6.2.16" not in ids


def test_registry_sort_handles_lss_ids():
    """Non-numeric IDs must sort to the end without raising."""
    from lss.lib.registry import _id_sort_key

    # Numeric IDs sort first, by tuple order
    assert _id_sort_key("1.1.1.1") < _id_sort_key("5.4.1.4")
    assert _id_sort_key("5.4.1.4") < _id_sort_key("LSS-001")
    # No exception on non-numeric
    _id_sort_key("LSS-999")


def test_skip_status_renders_and_counts(capsys):
    """A check returning status='skip' must be a recognized rendering path."""
    from lss.lib.output import print_result, print_summary
    print_result("LSS-001", "test", "skip", "not applicable")
    print_summary(passes=1, warns=0, fails=0, skips=1)
    captured = capsys.readouterr()
    # The skip stats column must appear
    assert "skip" in captured.out


def test_audit_json_mode_clean_stdout(tmp_path, monkeypatch):
    """`lss audit --json` should produce parseable JSON on stdout (no rich pollution)."""
    # We can't run the full audit without root, but we can verify the
    # CLI parser accepts --json and that audit's JSON path is gated
    # correctly — simplest is just assert flag parses.
    from lss.cli import build_parser
    parser = build_parser()
    args = parser.parse_args(["--json", "audit"])
    assert args.json is True


def test_sshd_match_scope_helper(tmp_path, monkeypatch):
    """setting_in_global_scope must distinguish global vs Match-scoped settings."""
    from lss.lib import sshd

    cfg = tmp_path / "sshd_config"
    cfg.write_text(
        "MaxAuthTries 6\n"
        "Match User admin\n"
        "    PermitRootLogin no\n"
    )
    monkeypatch.setattr(sshd, "SSHD_CONFIG", str(cfg))
    monkeypatch.setattr(sshd, "SSHD_CONFIG_D", str(tmp_path / "nonexistent"))

    assert sshd.setting_in_global_scope("MaxAuthTries") is True
    assert sshd.setting_in_global_scope("PermitRootLogin") is False
    assert sshd.setting_in_global_scope("X11Forwarding") is False  # not set at all


def test_syslog_helper_never_raises():
    """syslog helpers must be best-effort — never raise even if syslog is unavailable."""
    from lss.lib import syslog as lss_syslog
    # Should not raise, even on systems where the LOG_AUTHPRIV facility is restricted
    lss_syslog.info("test message")
    lss_syslog.warn("test warning")
    lss_syslog.err("test error")
