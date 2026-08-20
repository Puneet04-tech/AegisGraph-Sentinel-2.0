"""Regression tests for Streamlit authenticated stats/health cache keys."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path


def _load_fingerprint_helper():
    """Load _auth_cache_fingerprint without executing the Streamlit app module."""
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    source = app_path.read_text(encoding="utf-8")
    start = source.index("def _auth_cache_fingerprint")
    end = source.index("\n\n", start)
    ns: dict = {"hashlib": hashlib}
    exec(source[start:end], ns)
    return ns["_auth_cache_fingerprint"]


def test_auth_cache_fingerprint_is_stable_and_non_reversible():
    fingerprint = _load_fingerprint_helper()
    key = "super-secret-api-key"
    first = fingerprint(key)
    second = fingerprint(key)
    assert first == second
    assert key not in first
    assert first == hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


def test_auth_cache_fingerprint_differs_across_sessions():
    fingerprint = _load_fingerprint_helper()
    assert fingerprint("tenant-a-key") != fingerprint("tenant-b-key")


def test_auth_cache_fingerprint_anonymous_when_missing():
    fingerprint = _load_fingerprint_helper()
    assert fingerprint(None) == "anonymous"
    assert fingerprint("") == "anonymous"


def test_fetch_snapshot_signatures_include_auth_fingerprint():
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    source = app_path.read_text(encoding="utf-8")
    assert "def _fetch_health_snapshot(api_url: str, auth_fingerprint: str)" in source
    assert "def _fetch_stats_snapshot(api_url: str, auth_fingerprint: str)" in source
    assert "_fetch_health_snapshot(API_URL, _auth_cache_fingerprint(" in source
    assert "_fetch_stats_snapshot(API_URL, _auth_cache_fingerprint(" in source
