# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file, 
# via any medium, is strictly prohibited without explicit written authorization.

"""Control registry — defines what a CIS control is and collects them."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


@dataclass
class RollbackEntry:
    """One reversible action recorded during hardening.

    Undo is a list of argv lists, each executed with shell=False. Empty list
    means rollback relies entirely on `backup` to restore `path`. Both may be
    set: `backup` is restored first, then each `undo` argv runs in order.
    """
    action: str
    undo: list[list[str]] = field(default_factory=list)
    path: str = ""
    backup: str = ""


@dataclass
class CheckResult:
    """Result of running a single control check.

    Status values:
      pass    — control is satisfied
      warn    — soft non-compliance the operator should review
      fail    — non-compliant; `lss harden` will attempt to fix it
      manual  — non-compliant AND auto-fix is intentionally not provided
                (operator action required: see detail). Used for controls
                where automated remediation is unsafe (PAM stack edits) or
                requires explicit opt-in (audit log volume). Reported as a
                separate bucket from fail so the operator can distinguish
                "broken" from "needs me to take a step."
      skip    — control not applicable on this system
    """
    status: str
    detail: str = ""   # short explanation shown in parentheses


@dataclass
class Control:
    """A single CIS Benchmark control."""
    id: str                                         # e.g. "1.1.1"
    title: str                                      # e.g. "Ensure mounting of cramfs is disabled"
    section: str                                    # e.g. "filesystem", "network", "ssh"
    level: int = 1                                  # CIS level 1 or 2
    check: Callable[[], CheckResult] | None = None  # read-only audit function
    fix: Callable[[], list[RollbackEntry]] | None = None  # remediation function


# Global control registry
_controls: list[Control] = []


def _id_sort_key(control_id: str):
    """Sort numeric CIS IDs (e.g. "5.4.1.1") naturally, with non-numeric IDs
    (e.g. "LSS-001") grouped at the end and sorted lexicographically."""
    parts = control_id.split(".")
    try:
        return (0, [int(p) for p in parts])
    except ValueError:
        return (1, [control_id])


def register(control: Control):
    """Add a control to the global registry."""
    _controls.append(control)
    # Keep sorted by ID for consistent output
    _controls.sort(key=lambda c: _id_sort_key(c.id))


def get_controls(section: str | None = None, ids: list[str] | None = None) -> list[Control]:
    """Return controls, optionally filtered by section or specific IDs."""
    result = _controls
    if section:
        result = [c for c in result if c.section == section]
    if ids:
        id_set = set(ids)
        result = [c for c in result if c.id in id_set]
    return result


def get_control(control_id: str) -> Control | None:
    """Look up a single control by ID."""
    for c in _controls:
        if c.id == control_id:
            return c
    return None
