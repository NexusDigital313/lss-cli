# Copyright (c) 2026 Jacob Douglas Parmenter. All Rights Reserved.
# Proprietary and Confidential.
#
# Unauthorized copying, modification, distribution, or use of this file,
# via any medium, is strictly prohibited without explicit written authorization.

"""License gate — validates a Lemon Squeezy license key for the paid commands.

The free tier (`audit`, `report`, `list`) never touches this. `harden` and
`rollback` call `check_license()`; when enforcement is on (the default) they
require a valid, activated key.

Design goals:
  * One network call on the first mutating command, then cached — the binary
    keeps working offline (matches the "no telemetry, works offline" promise).
  * Key resolution from CLI flag, env, or disk; activation persisted to
    /etc/lss/license.json (machine-wide) or ~/.config/lss/ when not root.
  * Honest, light-touch gate — this is source-available software; the goal is a
    clean activation flow for paying customers, not unbreakable DRM.

Enforcement is ON by default. Set LSS_ENFORCE_LICENSE=0 to disable (self-hosting
/ development). A valid key always satisfies the gate regardless of that flag.
"""

from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

# Lemon Squeezy license API (unauthenticated — the key itself is the credential)
LS_API = "https://api.lemonsqueezy.com/v1/licenses"
HTTP_TIMEOUT = 10  # seconds

LICENSE_KEY_PATH = Path("/etc/lss/license.key")
USER_LICENSE_KEY_PATH = Path.home() / ".config" / "lss" / "license.key"
CACHE_PATH = Path("/etc/lss/license.json")
USER_CACHE_PATH = Path.home() / ".config" / "lss" / "license.json"

# How long a cached validation is trusted before we try to re-validate online.
REVALIDATE_AFTER = 14 * 86400          # 14 days: re-check when online
# How long we keep honoring a cached validation if the network is unreachable.
OFFLINE_GRACE = 90 * 86400             # 90 days fully offline before we re-require online


@dataclass
class LicenseStatus:
    valid: bool
    detail: str = ""              # human-readable explanation
    purchase_email: str = ""      # who bought it (for support)
    product: str = ""             # product/tier name from the store
    key_masked: str = ""          # last 4 chars, for display
    source: str = ""              # how it was satisfied: online | cache | env-disabled | offline


# --------------------------------------------------------------------------- #
# Enforcement toggle + key resolution
# --------------------------------------------------------------------------- #
def enforcement_enabled() -> bool:
    """Enforcement is on unless explicitly disabled via LSS_ENFORCE_LICENSE."""
    v = os.environ.get("LSS_ENFORCE_LICENSE", "1").strip().lower()
    return v not in ("0", "false", "off", "no")


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


def _mask(key: str) -> str:
    key = (key or "").strip()
    return f"…{key[-4:]}" if len(key) >= 4 else "…"


# --------------------------------------------------------------------------- #
# Local cache (the activation record)
# --------------------------------------------------------------------------- #
def _cache_path_for_write() -> Path:
    """Prefer the machine-wide path; fall back to the user config dir."""
    for p in (CACHE_PATH, USER_CACHE_PATH):
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            return p
        except OSError:
            continue
    return USER_CACHE_PATH


def _load_cache() -> dict | None:
    for p in (CACHE_PATH, USER_CACHE_PATH):
        try:
            if p.exists():
                return json.loads(p.read_text())
        except (OSError, ValueError):
            continue
    return None


def _save_cache(data: dict) -> None:
    p = _cache_path_for_write()
    try:
        p.write_text(json.dumps(data, indent=2))
        os.chmod(p, 0o600)
    except OSError:
        pass  # caching is best-effort; a failed write just means we re-validate next time


def _clear_cache() -> None:
    for p in (CACHE_PATH, USER_CACHE_PATH):
        try:
            p.unlink()
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# Lemon Squeezy API
# --------------------------------------------------------------------------- #
def _ls_post(action: str, params: dict) -> dict:
    """POST to a Lemon Squeezy license endpoint; returns parsed JSON.

    Raises urllib.error.URLError / socket.timeout on network failure so the
    caller can fall back to the cache.
    """
    body = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(
        f"{LS_API}/{action}",
        data=body,
        headers={"Accept": "application/json",
                 "Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        # nosec B310 — URL is the fixed https Lemon Squeezy API constant (LS_API),
        # never user-controlled, so no file:/custom-scheme risk.
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:  # nosec B310
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        # Lemon Squeezy returns 4xx with a JSON error body for a bad/invalid key
        # (e.g. {"valid": false, "error": "license_key not found"}). Surface that
        # as a real rejection rather than letting it bubble up as "offline".
        try:
            return json.loads(exc.read().decode())
        except (ValueError, OSError):
            raise  # non-JSON HTTP error → genuine server problem, treat as network failure


def _meta_email(payload: dict) -> str:
    return (payload.get("meta") or {}).get("customer_email", "") or ""


def _meta_product(payload: dict) -> str:
    return (payload.get("meta") or {}).get("product_name", "") or ""


# --------------------------------------------------------------------------- #
# Public operations (used by the `lss license` subcommand)
# --------------------------------------------------------------------------- #
def activate(key: str, instance_name: str | None = None) -> LicenseStatus:
    """Activate a license key on this host and cache the result."""
    key = (key or "").strip()
    if not key:
        return LicenseStatus(False, "no license key provided")
    instance_name = instance_name or socket.gethostname() or "lss-host"
    try:
        payload = _ls_post("activate", {"license_key": key, "instance_name": instance_name})
    except (urllib.error.URLError, socket.timeout, OSError) as exc:
        return LicenseStatus(False, f"could not reach the license server: {exc}")

    if not payload.get("activated"):
        return LicenseStatus(False, payload.get("error") or "activation failed", key_masked=_mask(key))

    instance = payload.get("instance") or {}
    cache = {
        "key": key,
        "instance_id": instance.get("id", ""),
        "status": (payload.get("license_key") or {}).get("status", "active"),
        "email": _meta_email(payload),
        "product": _meta_product(payload),
        "validated_at": int(time.time()),
    }
    _save_cache(cache)
    return LicenseStatus(True, "license activated", cache["email"], cache["product"],
                         _mask(key), source="online")


def deactivate() -> LicenseStatus:
    """Release this host's activation (frees a seat) and clear the cache."""
    cache = _load_cache()
    if not cache:
        return LicenseStatus(False, "no active license on this host")
    key, instance_id = cache.get("key", ""), cache.get("instance_id", "")
    try:
        if key and instance_id:
            _ls_post("deactivate", {"license_key": key, "instance_id": instance_id})
    except (urllib.error.URLError, socket.timeout, OSError):
        pass  # best-effort; we still clear locally
    _clear_cache()
    return LicenseStatus(True, "license deactivated on this host")


def _validate_online(key: str, instance_id: str | None) -> LicenseStatus:
    params = {"license_key": key}
    if instance_id:
        params["instance_id"] = instance_id
    try:
        payload = _ls_post("validate", params)
    except (urllib.error.URLError, socket.timeout, OSError) as exc:
        return LicenseStatus(False, f"offline: {exc}", source="offline")
    if not payload.get("valid"):
        return LicenseStatus(False, payload.get("error") or "license is not valid",
                             key_masked=_mask(key))
    return LicenseStatus(True, "license valid", _meta_email(payload), _meta_product(payload),
                         _mask(key), source="online")


# --------------------------------------------------------------------------- #
# The gate — called by harden / rollback via cli.py
# --------------------------------------------------------------------------- #
def check_license(cli_arg_key: str | None = None) -> LicenseStatus:
    """Entitlement check for the paid commands (harden / rollback).

    Order: enforcement off → allow; fresh cache → allow offline; key present →
    validate online (refresh cache); stale cache within offline grace → allow;
    otherwise deny with actionable guidance.
    """
    if not enforcement_enabled():
        return LicenseStatus(True, "enforcement disabled (LSS_ENFORCE_LICENSE=0)",
                             source="env-disabled")

    cache = _load_cache()
    now = int(time.time())
    key = find_license_key(cli_arg_key)

    # 1. Recent, valid cache → trust it, stay offline.
    if cache and cache.get("status") == "active":
        age = now - int(cache.get("validated_at", 0))
        if age < REVALIDATE_AFTER:
            return LicenseStatus(True, "license valid (cached)", cache.get("email", ""),
                                 cache.get("product", ""), _mask(cache.get("key", "")),
                                 source="cache")

    # 2. We have a key (explicit or from cache) → re-validate online.
    use_key = key or (cache.get("key") if cache else None)
    if use_key:
        instance_id = cache.get("instance_id") if cache else None
        st = _validate_online(use_key, instance_id)
        if st.valid:
            _save_cache({
                "key": use_key,
                "instance_id": instance_id or "",
                "status": "active",
                "email": st.purchase_email,
                "product": st.product,
                "validated_at": now,
            })
            return st
        # Online explicitly rejected (not merely offline) → hard deny.
        if st.source != "offline":
            return LicenseStatus(False, f"license rejected: {st.detail}", key_masked=_mask(use_key))
        # 3. Offline: honor a still-fresh-enough cache within the grace window.
        if cache and (now - int(cache.get("validated_at", 0))) < OFFLINE_GRACE:
            return LicenseStatus(True, "license valid (cached, offline)", cache.get("email", ""),
                                 cache.get("product", ""), _mask(use_key), source="cache")
        return LicenseStatus(False, "could not reach the license server and no recent "
                                    "validation is cached — connect once to (re)validate")

    # 4. No key anywhere.
    return LicenseStatus(False, "no license key found")


def status() -> LicenseStatus:
    """Human-facing status for `lss license status` (re-validates if possible)."""
    if not enforcement_enabled():
        return LicenseStatus(True, "enforcement disabled (LSS_ENFORCE_LICENSE=0)",
                             source="env-disabled")
    return check_license()
