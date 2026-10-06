"""Tests for the Lemon Squeezy license gate (lss/lib/license.py).

All network calls go through license._ls_post, which we monkeypatch — no real
HTTP. Cache + key paths are redirected into tmp_path so nothing touches /etc.
"""

import time
import urllib.error

import pytest

from lss.lib import license as L


@pytest.fixture(autouse=True)
def isolate(tmp_path, monkeypatch):
    """Redirect all on-disk paths into tmp and start from a clean env."""
    monkeypatch.setattr(L, "CACHE_PATH", tmp_path / "etc" / "license.json")
    monkeypatch.setattr(L, "USER_CACHE_PATH", tmp_path / "user" / "license.json")
    monkeypatch.setattr(L, "LICENSE_KEY_PATH", tmp_path / "etc" / "license.key")
    monkeypatch.setattr(L, "USER_LICENSE_KEY_PATH", tmp_path / "user" / "license.key")
    for var in ("LSS_ENFORCE_LICENSE", "LSS_LICENSE_KEY"):
        monkeypatch.delenv(var, raising=False)
    yield


def _no_network(*a, **k):
    raise AssertionError("network must not be called in this path")


# --- enforcement toggle ---------------------------------------------------
def test_enforcement_on_by_default():
    assert L.enforcement_enabled() is True


@pytest.mark.parametrize("val", ["0", "false", "off", "no", "FALSE", "Off"])
def test_enforcement_disabled(monkeypatch, val):
    monkeypatch.setenv("LSS_ENFORCE_LICENSE", val)
    assert L.enforcement_enabled() is False


def test_enforcement_other_values_stay_on(monkeypatch):
    monkeypatch.setenv("LSS_ENFORCE_LICENSE", "1")
    assert L.enforcement_enabled() is True


# --- key resolution -------------------------------------------------------
def test_find_key_precedence(monkeypatch):
    L.LICENSE_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    L.LICENSE_KEY_PATH.write_text("disk-key\n")
    monkeypatch.setenv("LSS_LICENSE_KEY", "env-key")
    assert L.find_license_key("cli-key") == "cli-key"          # CLI wins
    assert L.find_license_key(None) == "env-key"               # then env
    monkeypatch.delenv("LSS_LICENSE_KEY")
    assert L.find_license_key(None) == "disk-key"              # then disk


# --- the gate -------------------------------------------------------------
def test_no_key_denied(monkeypatch):
    monkeypatch.setattr(L, "_ls_post", _no_network)  # no key -> never hits network
    st = L.check_license(None)
    assert st.valid is False
    assert "no license key" in st.detail


def test_enforcement_off_allows(monkeypatch):
    monkeypatch.setenv("LSS_ENFORCE_LICENSE", "0")
    monkeypatch.setattr(L, "_ls_post", _no_network)
    st = L.check_license(None)
    assert st.valid and st.source == "env-disabled"


def test_fresh_cache_allows_offline(monkeypatch):
    L._save_cache({"key": "K-ABCD", "instance_id": "i1", "status": "active",
                   "email": "a@b.co", "product": "Personal", "validated_at": int(time.time())})
    monkeypatch.setattr(L, "_ls_post", _no_network)   # fresh cache must NOT call network
    st = L.check_license(None)
    assert st.valid and st.source == "cache" and st.purchase_email == "a@b.co"


def test_online_validate_success_caches(monkeypatch):
    calls = {}

    def fake(action, params):
        calls["action"] = action
        return {"valid": True, "meta": {"customer_email": "buyer@x.io", "product_name": "Commercial"}}

    monkeypatch.setenv("LSS_LICENSE_KEY", "K-LIVE-9999")
    monkeypatch.setattr(L, "_ls_post", fake)
    st = L.check_license(None)
    assert st.valid and st.source == "online" and calls["action"] == "validate"
    # cache was written so the next call is offline-fast
    cached = L._load_cache()
    assert cached["key"] == "K-LIVE-9999" and cached["status"] == "active"


def test_online_reject_denies(monkeypatch):
    monkeypatch.setenv("LSS_LICENSE_KEY", "K-BAD")
    monkeypatch.setattr(L, "_ls_post", lambda a, p: {"valid": False, "error": "license_key not found"})
    st = L.check_license(None)
    assert st.valid is False and "rejected" in st.detail


def test_offline_within_grace_allows(monkeypatch):
    old = int(time.time()) - (L.REVALIDATE_AFTER + 10)   # stale enough to try online
    L._save_cache({"key": "K", "instance_id": "i", "status": "active",
                   "email": "", "product": "Personal", "validated_at": old})

    def offline(a, p):
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(L, "_ls_post", offline)
    st = L.check_license(None)
    assert st.valid and st.source == "cache"   # honored within OFFLINE_GRACE


def test_offline_past_grace_denies(monkeypatch):
    import urllib.error
    old = int(time.time()) - (L.OFFLINE_GRACE + 10)
    L._save_cache({"key": "K", "instance_id": "i", "status": "active",
                   "email": "", "product": "Personal", "validated_at": old})
    monkeypatch.setattr(L, "_ls_post", lambda a, p: (_ for _ in ()).throw(urllib.error.URLError("down")))
    st = L.check_license(None)
    assert st.valid is False


# --- activate / deactivate ------------------------------------------------
def test_activate_writes_cache(monkeypatch):
    def fake(action, params):
        assert action == "activate"
        return {"activated": True, "instance": {"id": "inst-123"},
                "license_key": {"status": "active"},
                "meta": {"customer_email": "c@d.io", "product_name": "Personal"}}

    monkeypatch.setattr(L, "_ls_post", fake)
    st = L.activate("K-NEW")
    assert st.valid and st.purchase_email == "c@d.io"
    cached = L._load_cache()
    assert cached["instance_id"] == "inst-123" and cached["key"] == "K-NEW"


def test_activate_rejected(monkeypatch):
    monkeypatch.setattr(L, "_ls_post", lambda a, p: {"activated": False, "error": "activation_limit reached"})
    st = L.activate("K-OVER")
    assert st.valid is False and "activation_limit" in st.detail


def test_deactivate_clears_cache(monkeypatch):
    L._save_cache({"key": "K", "instance_id": "i", "status": "active",
                   "email": "", "product": "", "validated_at": int(time.time())})
    monkeypatch.setattr(L, "_ls_post", lambda a, p: {"deactivated": True})
    st = L.deactivate()
    assert st.valid and L._load_cache() is None
