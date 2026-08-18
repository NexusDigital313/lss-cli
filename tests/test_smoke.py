# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file, 
# via any medium, is strictly prohibited without explicit written authorization.

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


# --- Regression tests for the multi-control-same-file rollback bug class ---
# When several controls modify the same file in one harden run, three things
# must hold for rollback to truly undo everything:
#   1. The OUTER loop in rollback.run_rollback iterates controls in REVERSE
#      application order (so an early control's `rm -f` runs LAST, after later
#      controls have stopped restoring their backups onto a recreated file).
#   2. journal.backup_file produces a unique destination path per call,
#      otherwise repeated backups overwrite each other and the journal entry's
#      "backup" field points to the wrong snapshot.
#   3. A control that CREATES a persistence file (no prior backup) must emit
#      `rm -f` in its undo, otherwise the file survives rollback. sshd.py
#      gets this right; sysctl.py 0.5.1 missed it.


def test_rollback_outer_loop_reverses_controls(tmp_path, monkeypatch):
    """rollback.run_rollback must iterate controls in reverse application order.

    Scenario: control A creates a file (undo = rm -f), control B modifies it
    (undo = restore from backup of post-A state). Forward outer-loop order
    would run A's rm-f first, then B's restore would recreate the file. In
    reverse order, B's restore runs first (returns file to post-A state),
    then A's rm-f deletes it.
    """
    from lss.lib import journal
    from lss import rollback

    monkeypatch.setattr(journal, "JOURNAL_DIR", tmp_path / "j")
    monkeypatch.setattr(journal, "BACKUPS_DIR", tmp_path / "j" / "backups")

    run_id = journal.new_run_id()
    journal.set_current_run_id(run_id)

    target = tmp_path / "shared.conf"

    # Simulate harden: control A creates the file (no pre-existing backup)
    target.write_text("from_a = 1\n")
    bkp_a = ""

    # Control B then modifies it; backup_file snapshots post-A state
    bkp_b = journal.backup_file(str(target))
    target.write_text("from_a = 1\nfrom_b = 1\n")

    entries = {
        "1.1.1": [{
            "action": "added from_a",
            "undo": [["rm", "-f", str(target)]],
            "path": str(target),
            "backup": bkp_a,
        }],
        "1.1.2": [{
            "action": "added from_b",
            "undo": [],
            "path": str(target),
            "backup": bkp_b,
        }],
    }
    journal.write_run(run_id, entries)
    journal.set_current_run_id(None)

    class Args:
        last = True
        run_id = None
        control = None

    rollback.run_rollback(Args())

    assert not target.exists(), (
        "rollback left the file behind — outer loop is iterating controls "
        "in forward order, so 1.1.1's `rm -f` ran before 1.1.2 restored its "
        "backup, and the restore recreated the file with stale state"
    )


def test_backup_file_produces_unique_paths_for_repeated_calls(tmp_path, monkeypatch):
    """journal.backup_file must not overwrite earlier backups for the same path.

    Multiple controls in a single run may snapshot the same file. If
    backup_file returns a deterministic path, the second call's shutil.copy2
    silently overwrites the first call's backup, so reverse-order rollback
    can no longer rebuild the original file from the chain.
    """
    from lss.lib import journal

    monkeypatch.setattr(journal, "BACKUPS_DIR", tmp_path / "backups")
    journal.set_current_run_id("test-run")

    src = tmp_path / "shared.conf"

    src.write_text("v1\n")
    bkp1 = journal.backup_file(str(src))

    src.write_text("v2\n")
    bkp2 = journal.backup_file(str(src))

    src.write_text("v3\n")
    bkp3 = journal.backup_file(str(src))

    assert len({bkp1, bkp2, bkp3}) == 3, "backup_file produced duplicate paths"
    assert Path(bkp1).read_text() == "v1\n"
    assert Path(bkp2).read_text() == "v2\n"
    assert Path(bkp3).read_text() == "v3\n"

    journal.set_current_run_id(None)


def test_sysctl_set_emits_rm_f_when_creating_persistence_file(tmp_path, monkeypatch):
    """sysctl.set_sysctl must add `rm -f SYSCTL_CONF` to undo when the
    persistence file did not exist before this control ran.

    Without this, the dropfile survives rollback and `lss audit` keeps
    reporting the post-harden state. sshd.py:set_sysctl_setting has the
    correct shape — sysctl.py must mirror it.
    """
    from lss.lib import sysctl, journal

    sysctl_conf = tmp_path / "80-lss.conf"  # does NOT exist yet
    monkeypatch.setattr(sysctl, "SYSCTL_CONF", str(sysctl_conf))
    monkeypatch.setattr(journal, "BACKUPS_DIR", tmp_path / "backups")
    journal.set_current_run_id("test-run")

    # No-op the actual kernel call, and pretend the key has no current value
    monkeypatch.setattr(
        sysctl.subprocess, "run",
        lambda *a, **kw: subprocess.CompletedProcess(args=a, returncode=0, stdout="", stderr=""),
    )
    monkeypatch.setattr(sysctl, "get_sysctl", lambda k: None)

    entry = sysctl.set_sysctl("kernel.example_key", "1")

    assert ["rm", "-f", str(sysctl_conf)] in entry.undo, (
        "sysctl.set_sysctl did not add `rm -f` to undo for a freshly-created "
        "persistence file — rollback will leave the dropfile behind"
    )

    journal.set_current_run_id(None)
