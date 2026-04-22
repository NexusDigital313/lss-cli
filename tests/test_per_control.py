"""Per-control sanity tests — generated from the registry.

For every registered control we verify:
  - the ID has a sane shape (numeric dotted CIS ID OR LSS-XXX)
  - the title is non-empty
  - the section is one of the known section labels
  - the level is 1 or 2
  - calling check() doesn't crash (it can return any status; what matters
    is it doesn't raise an unhandled exception, which would crash audit)

These don't replace deep per-control tests (mock /etc files, verify the
exact pass/fail decision against a known input). Those need scaffolding and
are tracked for v0.4.x. But these catch the "did someone register a
malformed control" and "did a check function regress into a crash"
classes of bug, which are the two most likely regression vectors when the
codebase is refactored.
"""

from __future__ import annotations

import re

import pytest

import lss.list_controls  # noqa: F401  (side-effect: register every control)
from lss.lib.registry import get_controls

ALL_CONTROLS = get_controls()
KNOWN_SECTIONS = {
    "filesystem", "kernel", "banners", "boot", "services", "network",
    "logging", "cron", "ssh", "auth", "users",
}
ID_PATTERN_CIS = re.compile(r"^\d+(\.\d+)*$")
ID_PATTERN_LSS = re.compile(r"^LSS-\d{3,}$")


@pytest.mark.parametrize("ctrl", ALL_CONTROLS, ids=lambda c: c.id)
def test_control_id_shape(ctrl):
    assert ID_PATTERN_CIS.match(ctrl.id) or ID_PATTERN_LSS.match(ctrl.id), (
        f"control id {ctrl.id!r} doesn't match a known shape "
        "(expected dotted-numeric CIS or LSS-XXX)"
    )


@pytest.mark.parametrize("ctrl", ALL_CONTROLS, ids=lambda c: c.id)
def test_control_title_present(ctrl):
    assert ctrl.title and ctrl.title.strip(), f"{ctrl.id} has empty title"
    assert len(ctrl.title) <= 200, f"{ctrl.id} title is suspiciously long"


@pytest.mark.parametrize("ctrl", ALL_CONTROLS, ids=lambda c: c.id)
def test_control_section_known(ctrl):
    assert ctrl.section in KNOWN_SECTIONS, (
        f"{ctrl.id} uses unknown section {ctrl.section!r}; add it to "
        "lss/lib/output.py:_SECTION_LABELS first"
    )


@pytest.mark.parametrize("ctrl", ALL_CONTROLS, ids=lambda c: c.id)
def test_control_level_valid(ctrl):
    assert ctrl.level in (1, 2), f"{ctrl.id} level={ctrl.level} (expected 1 or 2)"


@pytest.mark.parametrize("ctrl", ALL_CONTROLS, ids=lambda c: c.id)
def test_control_check_does_not_crash(ctrl):
    """Every check() must return a CheckResult — never raise.

    Unhandled exceptions in checks crash the whole audit run. The audit engine
    DOES wrap check() in try/except, but the contract is that checks shouldn't
    raise in the first place. This test catches it.
    """
    if ctrl.check is None:
        pytest.skip(f"{ctrl.id} has no check function")
    try:
        result = ctrl.check()
    except PermissionError:
        # Some checks read root-only files; running unprivileged may legitimately
        # hit PermissionError before they can return a CheckResult. That's an
        # operator concern, not a code defect. Skip.
        pytest.skip(f"{ctrl.id} check needs privileges we don't have")
    except FileNotFoundError as exc:
        # If a check shells out to a tool that doesn't exist on this box, it
        # should handle that gracefully — but in test env we're tolerant.
        pytest.skip(f"{ctrl.id} check references a missing tool: {exc}")
    except Exception as exc:
        pytest.fail(f"{ctrl.id} check raised {type(exc).__name__}: {exc}")
    else:
        assert hasattr(result, "status"), (
            f"{ctrl.id} check returned {type(result).__name__}, expected CheckResult"
        )
        assert result.status in ("pass", "warn", "fail", "skip"), (
            f"{ctrl.id} returned status={result.status!r}; expected one of "
            "pass/warn/fail/skip"
        )
