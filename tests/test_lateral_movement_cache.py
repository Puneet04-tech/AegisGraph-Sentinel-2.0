"""Regression coverage for Redis-mode lateral movement cache eviction."""

from pathlib import Path


def test_redis_mode_graph_cache_has_explicit_eviction():
    source = Path("src/features/lateral_movement.py").read_text(encoding="utf-8")

    assert "OrderedDict()" in source
    assert "self._graph_cache.clear()" in source
    assert "self._graph_cache_max_size = 1024" in source
    assert "self._graph_cache.move_to_end(account_id)" in source
    assert "self._graph_cache.popitem(last=False)" in source
