"""License key gate — verifies the operator has a valid LSS license before
running mutating commands (harden / rollback / report).

Currently in BOOTSTRAP mode: until the Gumroad product URLs and license
verification endpoint are wired in, the gate is permissive but visible —
it prints a one-time evaluation notice and lets the command proceed.

When you're ready to enforce:
  1. Set LSS_LICENSE_API_URL to the Gumroad license-verify endpoint
     (https://api.gumroad.com/v2/licenses/verify).
  2. Set GUMROAD_PRODUCT_IDS to map tier → product permalink slug.
  3. Set BOOTSTRAP_MODE = False below (or via the LSS_ENFORCE_LICENSE env var).

Customers will then need either:
  - A license key passed via --license-key XXXX
  - The LSS_LICENSE_KEY env var set
  - A key stored at ~/.config/lss/license.key (root-owned, mode 0600)
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration — flip BOOTSTRAP_MODE = False once Gumroad listing is live.
# ---------------------------------------------------------------------------
BOOTSTRAP_MODE: bool = True

# Gumroad license verify API. Same endpoint for all tiers; the response
# tells us which product the key belongs to.
LSS_LICENSE_API_URL = "https://api.gumroad.com/v2/licenses/verify"

# Map of human tier name → Gumroad product permalink slug.
# REPLACE these placeholders once you have real Gumroad product URLs.
GUMROAD_PRODUCT_IDS: dict[str, str] = {
    "Solo":       "REPLACE-WITH-SOLO-SLUG",
    "Pro":        "REPLACE-WITH-PRO-SLUG",
    "Enterprise": "REPLACE-WITH-ENTERPRISE-SLUG",
}

LICENSE_KEY_PATH = Path("/etc/lss/license.key")
USER_LICENSE_KEY_PATH = Path.home() / ".config" / "lss" / "license.key"
EVAL_NOTICE_FLAG = Path("/var/lib/lss/.eval-notice-shown")


@dataclass
class LicenseStatus:
    valid: bool
    tier: str = ""           # "Solo" | "Pro" | "Enterprise" | "evaluation"
    detail: str = ""         # human-readable explanation
    purchase_email: str = "" # who bought it (for support)


def _is_enforcement_on() -> bool:
    """Are we actually checking license keys, or in bootstrap?"""
    if os.environ.get("LSS_ENFORCE_LICENSE", "").lower() in ("1", "true", "yes"):
        return True
    return not BOOTSTRAP_MODE


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


def verify_with_gumroad(license_key: str, product_slug: str) -> LicenseStatus:
    """Hit Gumroad's license verify endpoint. Returns LicenseStatus."""
    body = urllib.parse.urlencode({
        "product_permalink": product_slug,
        "license_key": license_key,
        "increment_uses_count": "false",
    }).encode()
    req = urllib.request.Request(
        LSS_LICENSE_API_URL,
        data=body,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return LicenseStatus(valid=False, detail=f"license verify HTTP {exc.code}")
    except urllib.error.URLError as exc:
        return LicenseStatus(valid=False, detail=f"license verify network error: {exc.reason}")
    except (TimeoutError, json.JSONDecodeError) as exc:
        return LicenseStatus(valid=False, detail=f"license verify failure: {exc}")

    if not data.get("success"):
        return LicenseStatus(valid=False, detail=data.get("message", "invalid license key"))

    purchase = data.get("purchase", {}) or {}
    if purchase.get("refunded"):
        return LicenseStatus(valid=False, detail="license refunded")
    if purchase.get("disputed"):
        return LicenseStatus(valid=False, detail="license under dispute")
    if purchase.get("chargebacked"):
        return LicenseStatus(valid=False, detail="license charged back")

    return LicenseStatus(
        valid=True,
        tier=_tier_from_product_slug(product_slug),
        detail="license valid",
        purchase_email=purchase.get("email", ""),
    )


def _tier_from_product_slug(slug: str) -> str:
    for tier, configured_slug in GUMROAD_PRODUCT_IDS.items():
        if configured_slug == slug:
            return tier
    return "Unknown"


def _show_eval_notice_once() -> None:
    """Print a friendly evaluation notice the first time per host."""
    try:
        EVAL_NOTICE_FLAG.parent.mkdir(parents=True, exist_ok=True)
        if EVAL_NOTICE_FLAG.exists():
            return
        EVAL_NOTICE_FLAG.write_text("shown\n")
    except OSError:
        # If we can't persist the flag (e.g. running unprivileged), just
        # show the notice every time. Better than silent.
        pass

    from lss.lib.output import warn
    warn("Running in evaluation mode (no license key configured).")
    warn("Purchase a commercial license at https://linuxsecuritysuite.com")
    warn("Or pass --license-key XXXX once you have one.")


def check_license(cli_arg_key: str | None = None) -> LicenseStatus:
    """Top-level check called by harden / rollback / report.

    In bootstrap mode: always returns valid=True with tier='evaluation' and
    shows a one-time notice. Once you flip BOOTSTRAP_MODE off, this becomes
    the real enforcement point.
    """
    if not _is_enforcement_on():
        _show_eval_notice_once()
        return LicenseStatus(valid=True, tier="evaluation", detail="bootstrap mode")

    key = find_license_key(cli_arg_key)
    if not key:
        return LicenseStatus(
            valid=False,
            detail="no license key configured. Pass --license-key, set "
                   "LSS_LICENSE_KEY, or place the key at /etc/lss/license.key",
        )

    # Try each tier's product slug until one validates
    last_detail = "license key not recognized for any product tier"
    for tier, slug in GUMROAD_PRODUCT_IDS.items():
        if not slug or slug.startswith("REPLACE"):
            continue
        result = verify_with_gumroad(key, slug)
        if result.valid:
            return result
        last_detail = result.detail

    return LicenseStatus(valid=False, detail=last_detail)
