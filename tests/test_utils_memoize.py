"""Tests for the memoize decorator and TTLCache."""

import pytest

import src.utils.memoize as memoize_module
from src.utils.memoize import TTLCache, cache_info, clear_cache, memoize


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def test_memoize_caches_result():
    calls = []

    @memoize()
    def compute(x):
        calls.append(x)
        return x * 2

    assert compute(3) == 6
    assert compute(3) == 6
    assert calls == [3]


def test_memoize_distinguishes_arguments():
    calls = []

    @memoize()
    def compute(x):
        calls.append(x)
        return x + 1

    assert compute(1) == 2
    assert compute(2) == 3
    assert compute(1) == 2
    assert calls == [1, 2]


def test_memoize_kwargs_are_distinct():
    calls = []

    @memoize()
    def compute(a, b=10):
        calls.append((a, b))
        return a + b

    assert compute(1, b=2) == 3
    assert compute(1, b=2) == 3
    assert compute(1) == 11
    assert calls == [(1, 2), (1, 10)]


def test_memoize_ttl_expiry(monkeypatch):
    clock = FakeClock()
    monkeypatch.setattr(memoize_module, "_clock", clock)
    calls = []

    @memoize(ttl=5)
    def compute(x):
        calls.append(x)
        return x * 10

    assert compute(1) == 10
    clock.advance(3)
    assert compute(1) == 10
    assert calls == [1]
    clock.advance(5)
    assert compute(1) == 10
    assert calls == [1, 1]


def test_memoize_custom_key_func():
    calls = []

    @memoize(key_func=lambda *args, **kwargs: args[0])
    def compute(a, b):
        calls.append((a, b))
        return a + b

    assert compute(1, 100) == 101
    assert compute(1, 200) == 101
    assert calls == [(1, 100)]


def test_memoize_lru_eviction():
    calls = []

    @memoize(maxsize=2)
    def compute(x):
        calls.append(x)
        return x

    compute(1)
    compute(2)
    compute(1)
    compute(3)
    assert calls == [1, 2, 3]
    compute(2)
    assert calls == [1, 2, 3, 2]
    compute(1)
    assert calls == [1, 2, 3, 2, 1]


def test_memoize_unhashable_args():
    calls = []

    @memoize()
    def compute(items):
        calls.append(items)
        return sum(items)

    assert compute([1, 2]) == 3
    assert compute([1, 2]) == 3
    assert calls == [[1, 2]]


def test_memoize_invalid_maxsize():
    with pytest.raises(ValueError):
        memoize(maxsize=0)


def test_clear_cache_resets():
    calls = []

    @memoize()
    def compute(x):
        calls.append(x)
        return x

    compute(1)
    compute(1)
    assert calls == [1]
    clear_cache(compute)
    compute(1)
    assert calls == [1, 1]


def test_clear_cache_resets_counters():
    @memoize()
    def compute(x):
        return x

    compute(1)
    compute(1)
    assert cache_info(compute)["hits"] == 1
    clear_cache(compute)
    assert cache_info(compute) == {
        "hits": 0,
        "misses": 0,
        "size": 0,
        "maxsize": 128,
    }


def test_clear_cache_non_memoized_raises():
    def plain(x):
        return x

    with pytest.raises(ValueError):
        clear_cache(plain)


def test_cache_info_counts():
    @memoize()
    def compute(x):
        return x * 2

    assert cache_info(compute)["hits"] == 0
    compute(1)
    compute(1)
    compute(2)
    info = cache_info(compute)
    assert info["hits"] == 1
    assert info["misses"] == 2
    assert info["size"] == 2
    assert info["maxsize"] == 128


def test_cache_info_non_memoized_zeros():
    def plain(x):
        return x

    assert cache_info(plain) == {"hits": 0, "misses": 0, "size": 0, "maxsize": 0}


def test_wrapped_cache_dict_like():
    @memoize()
    def compute(x):
        return x

    compute(1)
    cache = compute.__wrapped_cache__
    assert isinstance(cache, TTLCache)
    assert len(cache) == 1
    assert cache.get(((1,), ())) == 1


def test_ttlcache_basic_and_expiry():
    clock = FakeClock()
    cache = TTLCache(ttl=5, maxsize=8, clock=clock)
    cache.set("k", "v")
    assert cache.get("k") == "v"
    assert "k" in cache
    assert len(cache) == 1
    clock.advance(6)
    assert cache.get("k") is None
    assert "k" not in cache
    assert len(cache) == 0


def test_ttlcache_no_ttl_never_expires():
    cache = TTLCache(ttl=None, maxsize=8, clock=FakeClock())
    cache.set("k", "v")
    assert cache.get("k") == "v"


def test_ttlcache_clear():
    cache = TTLCache(ttl=None, maxsize=8)
    cache.set("a", 1)
    cache.set("b", 2)
    cache.clear()
    assert len(cache) == 0
    assert cache.get("a") is None


def test_ttlcache_maxsize_eviction():
    cache = TTLCache(ttl=None, maxsize=2)
    cache.set("a", 1)
    cache.set("b", 2)
    cache.set("c", 3)
    assert len(cache) == 2
    assert cache.get("a") is None
    assert cache.get("c") == 3
