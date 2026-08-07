"""Memoization decorator and TTL cache for expensive computations."""

import time
from collections import OrderedDict
from functools import wraps

_clock = time.monotonic


def _make_key(args, kwargs, key_func):
    if key_func is not None:
        return key_func(*args, **kwargs)
    key = (args, tuple(kwargs.items()))
    try:
        hash(key)
    except TypeError:
        key = repr(key)
    return key


class TTLCache:
    """OrderedDict-backed cache with TTL expiry and LRU eviction."""

    def __init__(self, ttl=None, maxsize=128, clock=None):
        self.ttl = ttl
        self.maxsize = maxsize
        self._clock = clock if clock is not None else time.monotonic
        self._data = OrderedDict()

    def _now(self):
        return self._clock()

    def _expire(self, now=None):
        if self.ttl is None:
            return
        if now is None:
            now = self._now()
        expired = [
            k for k, (_, stored_at) in self._data.items()
            if now - stored_at >= self.ttl
        ]
        for k in expired:
            del self._data[k]

    def get(self, key):
        now = self._now()
        self._expire(now)
        if key not in self._data:
            return None
        self._data.move_to_end(key)
        return self._data[key][0]

    def set(self, key, value):
        now = self._now()
        self._expire(now)
        self._data[key] = (value, now)
        self._data.move_to_end(key)
        while len(self._data) > self.maxsize:
            self._data.popitem(last=False)

    def __contains__(self, key):
        self._expire()
        return key in self._data

    def __len__(self):
        self._expire()
        return len(self._data)

    def clear(self):
        self._data.clear()


def memoize(ttl=None, *, key_func=None, maxsize=128):
    """Cache results by arguments.

    ttl: seconds before an entry expires (None = never).
    key_func: optional callable(*args, **kwargs) returning a hashable key.
    maxsize: maximum cached entries, LRU-evicted.
    """
    if maxsize <= 0:
        raise ValueError("maxsize must be positive")

    def decorator(fn):
        cache = TTLCache(ttl=ttl, maxsize=maxsize, clock=lambda: _clock())
        stats = {"hits": 0, "misses": 0}

        @wraps(fn)
        def wrapper(*args, **kwargs):
            key = _make_key(args, kwargs, key_func)
            if key in cache:
                stats["hits"] += 1
                return cache.get(key)
            stats["misses"] += 1
            value = fn(*args, **kwargs)
            cache.set(key, value)
            return value

        wrapper.__wrapped_cache__ = cache
        wrapper.__cache_stats__ = stats
        return wrapper

    return decorator


def clear_cache(fn):
    """Empty the cache and reset counters for a memoized function."""
    if not hasattr(fn, "__wrapped_cache__"):
        raise ValueError(f"{getattr(fn, '__name__', fn)} is not memoized")
    fn.__wrapped_cache__.clear()
    fn.__cache_stats__["hits"] = 0
    fn.__cache_stats__["misses"] = 0


def cache_info(fn):
    """Return hit/miss counters and sizing for a function.

    Non-memoized functions report all zeros.
    """
    if not hasattr(fn, "__wrapped_cache__"):
        return {"hits": 0, "misses": 0, "size": 0, "maxsize": 0}
    return {
        "hits": fn.__cache_stats__["hits"],
        "misses": fn.__cache_stats__["misses"],
        "size": len(fn.__wrapped_cache__),
        "maxsize": fn.__wrapped_cache__.maxsize,
    }
