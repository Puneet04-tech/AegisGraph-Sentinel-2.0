"""Unit tests for the thread-safe LRU cache.

Covers ``src.lru_cache.LRUCache``: mapping semantics, LRU ordering,
capacity eviction, snapshot views, and comparison/copy behaviour.
"""

from __future__ import annotations

import pytest

from src.lru_cache import LRUCache


# ---------------------------------------------------------------------------
# Basic mapping behaviour
# ---------------------------------------------------------------------------


class TestMapping:
    def test_set_get_contains(self):
        cache = LRUCache(maxsize=10)

        cache["a"] = 1

        assert cache["a"] == 1
        assert "a" in cache
        assert "b" not in cache
        assert len(cache) == 1

    def test_override_value(self):
        cache = LRUCache(maxsize=10)
        cache["a"] = 1
        cache["a"] = 2

        assert cache["a"] == 2
        assert len(cache) == 1

    def test_missing_key_raises_key_error(self):
        cache = LRUCache(maxsize=10)
        with pytest.raises(KeyError):
            cache["missing"]

    def test_delitem(self):
        cache = LRUCache(maxsize=10)
        cache["a"] = 1
        del cache["a"]

        assert "a" not in cache
        assert len(cache) == 0

    def test_iteration_follows_insertion_order(self):
        cache = LRUCache(maxsize=10)
        cache["a"] = 1
        cache["b"] = 2
        cache["c"] = 3

        assert list(cache) == ["a", "b", "c"]

    def test_reversed_iteration(self):
        cache = LRUCache(maxsize=10)
        cache["a"] = 1
        cache["b"] = 2

        assert list(reversed(cache)) == ["b", "a"]

    def test_clear(self):
        cache = LRUCache(maxsize=10)
        cache["a"] = 1
        cache["b"] = 2

        cache.clear()

        assert len(cache) == 0


# ---------------------------------------------------------------------------
# LRU semantics
# ---------------------------------------------------------------------------


class TestLRU:
    def test_read_moves_key_to_most_recent(self):
        cache = LRUCache(maxsize=3)
        cache["a"] = 1
        cache["b"] = 2
        cache["c"] = 3

        assert cache["a"] == 1  # touch 'a'
        assert list(cache.keys()) == ["b", "c", "a"]

    def test_write_moves_existing_key_to_most_recent(self):
        cache = LRUCache(maxsize=3)
        cache["a"] = 1
        cache["b"] = 2
        cache["a"] = 10

        assert list(cache.keys()) == ["b", "a"]

    def test_eviction_removes_oldest(self):
        cache = LRUCache(maxsize=3)
        cache["a"] = 1
        cache["b"] = 2
        cache["c"] = 3
        cache["d"] = 4

        assert "a" not in cache
        assert list(cache.keys()) == ["b", "c", "d"]

    def test_eviction_skips_recently_accessed(self):
        cache = LRUCache(maxsize=3)
        cache["a"] = 1
        cache["b"] = 2
        cache["c"] = 3
        _ = cache["a"]  # touch 'a'
        cache["d"] = 4

        assert "b" not in cache  # oldest untouched key evicted
        assert "a" in cache


# ---------------------------------------------------------------------------
# Access / update helpers
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_get_returns_value(self):
        cache = LRUCache(maxsize=3)
        cache["a"] = 1
        assert cache.get("a") == 1

    def test_get_missing_returns_default(self):
        cache = LRUCache(maxsize=3)
        assert cache.get("missing") is None
        assert cache.get("missing", 42) == 42

    def test_get_missing_does_not_insert(self):
        cache = LRUCache(maxsize=3)
        cache.get("missing", 42)
        assert "missing" not in cache

    def test_pop_existing(self):
        cache = LRUCache(maxsize=3)
        cache["a"] = 1

        assert cache.pop("a") == 1
        assert "a" not in cache

    def test_pop_missing_default(self):
        cache = LRUCache(maxsize=3)
        assert cache.pop("missing", 7) == 7

    def test_pop_missing_raises(self):
        cache = LRUCache(maxsize=3)
        with pytest.raises(KeyError):
            cache.pop("missing")

    def test_popitem_last_and_first(self):
        cache = LRUCache(maxsize=3)
        cache["a"] = 1
        cache["b"] = 2

        assert cache.popitem(last=True) == ("b", 2)
        assert cache.popitem(last=False) == ("a", 1)

    def test_setdefault_existing(self):
        cache = LRUCache(maxsize=3)
        cache["a"] = 1

        assert cache.setdefault("a", 99) == 1
        assert cache["a"] == 1

    def test_setdefault_missing(self):
        cache = LRUCache(maxsize=3)

        assert cache.setdefault("a", 42) == 42
        assert cache["a"] == 42

    def test_move_to_end(self):
        cache = LRUCache(maxsize=3)
        cache["a"] = 1
        cache["b"] = 2
        cache["c"] = 3

        cache.move_to_end("a")
        assert list(cache.keys()) == ["b", "c", "a"]

        cache.move_to_end("c", last=False)
        assert list(cache.keys()) == ["c", "b", "a"]

    def test_update_from_dict(self):
        cache = LRUCache(maxsize=5)
        cache.update({"a": 1, "b": 2})
        assert dict(cache.items()) == {"a": 1, "b": 2}

    def test_update_from_pair_iterable(self):
        cache = LRUCache(maxsize=5)
        cache.update([("a", 1), ("b", 2)])
        assert dict(cache.items()) == {"a": 1, "b": 2}

    def test_update_from_kwargs(self):
        cache = LRUCache(maxsize=5)
        cache.update(a=1, b=2)
        assert dict(cache.items()) == {"a": 1, "b": 2}

    def test_update_too_many_args_raises(self):
        cache = LRUCache(maxsize=5)
        with pytest.raises(TypeError):
            cache.update({"a": 1}, {"b": 2})


# ---------------------------------------------------------------------------
# Snapshot views, copy, equality
# ---------------------------------------------------------------------------


class TestViewsAndEquality:
    def test_snapshot_views_are_tuples(self):
        cache = LRUCache(maxsize=5)
        cache["a"] = 1
        cache["b"] = 2

        assert cache.keys() == ("a", "b")
        assert cache.values() == (1, 2)
        assert cache.items() == (("a", 1), ("b", 2))
        assert isinstance(cache.keys(), tuple)

    def test_copy_is_independent(self):
        cache = LRUCache(maxsize=5)
        cache["a"] = 1

        dup = cache.copy()

        assert dup == cache
        assert dup.maxsize == cache.maxsize
        dup["b"] = 2
        assert "b" not in cache

    def test_equality_with_dicts_and_caches(self):
        cache = LRUCache(maxsize=5)
        cache["a"] = 1

        assert cache == {"a": 1}
        assert cache == LRUCache(maxsize=5, **{"a": 1})
        assert (cache != {"a": 2}) is True

    def test_repr_includes_items(self):
        cache = LRUCache(maxsize=3)
        cache["a"] = 1

        assert "LRUCache" in repr(cache)
        assert "maxsize=3" in repr(cache)
        assert "a" in repr(cache)
        assert "1" in repr(cache)
