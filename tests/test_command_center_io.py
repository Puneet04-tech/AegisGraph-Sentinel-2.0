"""Regression test for non-blocking Command Center dashboard I/O."""

from pathlib import Path


def test_command_center_uses_cached_snapshots_and_background_post():
    source = Path("app.py").read_text(encoding="utf-8")
    normalized_source = " ".join(source.split())

    assert "_fetch_health_snapshot(API_URL)" in source
    assert "_fetch_stats_snapshot(API_URL)" in source
    assert 'requests.get(f"{API_URL}/health", timeout=3)' not in source
    assert 'requests.get(f"{API_URL}/stats", timeout=3)' not in source
    assert 'requests.get(f"{API_URL}/health", timeout=2)' not in source
    assert "COMMAND_CENTER_IO_EXECUTOR.submit( _build_live_event, API_URL, txn )" in normalized_source
    assert "time.sleep(2)" not in source
