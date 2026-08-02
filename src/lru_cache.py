"""
Thread-safe LRU cache backed by ``OrderedDict``.

A single shared implementation used wherever a bounded, eviction-capable
mapping is needed (auth state, API request caches), so the locking behaviour
does not diverge between call sites.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Any


class LRUCache(OrderedDict):
    """Thread-safe LRU cache with configurable max size."""

    def __init__(self, maxsize: int = 10000, *args, **kwds):
        self.maxsize = maxsize
        self._lock = threading.RLock()
        super().__init__(*args, **kwds)


    def __getitem__(self, key: str):
        with self._lock:
            value = super().__getitem__(key)
            super().move_to_end(key)
            return value

    def __setitem__(self, key: str, value: Any):
        with self._lock:
            if key in self:
                super().move_to_end(key)
            super().__setitem__(key, value)
            if super().__len__() > self.maxsize:
                oldest = next(iter(super().keys()))
                super().__delitem__(oldest)

    def __delitem__(self, key: str):
        with self._lock:
            super().__delitem__(key)

    def __contains__(self, key: str) -> bool:
        with self._lock:
            return super().__contains__(key)

    def __len__(self) -> int:
        with self._lock:
            return super().__len__()

    def __iter__(self):
        with self._lock:
            return iter(tuple(super().keys()))

    def __reversed__(self):
        with self._lock:
            return iter(tuple(super().__reversed__()))

    def keys(self) -> tuple[str, ...]:
        """Return an immutable snapshot tuple of cache keys (thread-safe)."""
        with self._lock:
            return tuple(super().keys())

    def values(self) -> tuple[Any, ...]:
        """Return an immutable snapshot tuple of cache values (thread-safe)."""
        with self._lock:
            return tuple(super().values())

    def items(self) -> tuple[tuple[str, Any], ...]:
        """Return an immutable snapshot tuple of (key, value) pairs (thread-safe)."""
        with self._lock:
            return tuple(super().items())

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            try:
                return self[key]
            except KeyError:
                return default

    def pop(self, key: str, *args) -> Any:
        with self._lock:
            try:
                value = super().__getitem__(key)
                super().__delitem__(key)
                return value
            except KeyError:
                if args:
                    return args[0]
                raise

    def popitem(self, last: bool = True) -> tuple[Any, Any]:
        with self._lock:
            return super().popitem(last=last)

    def setdefault(self, key: str, default: Any = None) -> Any:
        with self._lock:
            if key in self:
                return self[key]
            self[key] = default
            return default

    def update(self, *args, **kwds) -> None:
        """Update cache keys and values atomically while preserving LRU eviction."""
        # Item-by-item insertion via self[k] = v is required (instead of super().update)
        # to ensure that every inserted key updates LRU order and triggers capacity eviction.
        with self._lock:
            if args:
                if len(args) > 1:
                    raise TypeError(f"update expected at most 1 argument, got {len(args)}")
                other = args[0]
                if isinstance(other, dict):
                    for k, v in other.items():
                        self[k] = v
                elif hasattr(other, "keys"):
                    for k in other.keys():
                        self[k] = other[k]
                else:
                    for k, v in other:
                        self[k] = v
            for k, v in kwds.items():
                self[k] = v

    def clear(self) -> None:
        with self._lock:
            super().clear()

    def move_to_end(self, key: str, last: bool = True) -> None:
        with self._lock:
            super().move_to_end(key, last=last)

    def copy(self) -> LRUCache:
        with self._lock:
            return LRUCache(self.maxsize, list(super().items()))

    def __eq__(self, other: Any) -> bool:
        with self._lock:
            self_items = tuple(super().items())
        if isinstance(other, LRUCache):
            return self_items == tuple(other.items())
        if isinstance(other, (dict, OrderedDict)):
            return self_items == tuple(other.items())
        if hasattr(other, "items"):
            return self_items == tuple(other.items())
        return False

    def __ne__(self, other: Any) -> bool:
        return not (self == other)

    def __repr__(self) -> str:
        with self._lock:
            return f"{self.__class__.__name__}({list(super().items())}, maxsize={self.maxsize})"




