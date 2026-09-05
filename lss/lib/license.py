# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized reproduction, copying, modification, distribution,
# redistribution, publication, reverse engineering, decompilation, or
# disassembly of this file, in whole or in part, via any medium, is
# strictly prohibited without explicit prior written authorization.

"""License key gate — neutral stub for buyers to wire to their preferred provider.

By default `check_license` returns valid=True with no enforcement, so every
command runs unconstrained. A buyer who wants to gate `harden` / `rollback` /
`report` on a paid license replaces the body of `check_license` with a call
to their licensing provider's verify endpoint (Paddle, Stripe Billing, Lemon
Squeezy, custom HTTP, etc.), keeps the LicenseStatus return shape, and is
done. If a buyer wants no gate at all, deleting this file and the two-line
import + check in lss/cli.py is sufficient.

Key resolution helpers (`find_license_key`, the CLI/env/disk lookup) are
kept because they're useful regardless of the verify backend.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

LICENSE_KEY_PATH = Path("/etc/lss/license.key")
USER_LICENSE_KEY_PATH = Path.home() / ".config" / "lss" / "license.key"


@dataclass
class LicenseStatus:
    valid: bool
    detail: str = ""           # human-readable explanation
    purchase_email: str = ""   # who bought it (for support)


def _read_key_from_disk() -> str | None:
    for p in (LICENSE_KEY_PATH, USER_LICENSE_KEY_PATH):
        try:
            if p.exists():
                key = p.read_text().strip()
                if key:
                    return key
        except OSError:
            continue
    return None


def find_license_key(cli_arg_key: str | None = None) -> str | None:
    """Resolve the license key from (in order): CLI arg, env var, disk."""
    if cli_arg_key:
        return cli_arg_key.strip()
    env_key = os.environ.get("LSS_LICENSE_KEY", "").strip()
    if env_key:
        return env_key
    return _read_key_from_disk()


def check_license(cli_arg_key: str | None = None) -> LicenseStatus:
    """Top-level check called by harden / rollback / report.

    Default behavior: no enforcement — every command runs. Replace the body
    below to wire enforcement to a license-verify provider; keep the
    LicenseStatus return shape.
    """
    return LicenseStatus(valid=True, detail="no license enforcement configured")
