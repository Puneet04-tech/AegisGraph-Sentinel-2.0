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
        super().__init__(*args, **kwds)
        self._lock = threading.RLock()

    def __getitem__(self, key: str):
        with self._lock:
            value = super().__getitem__(key)
            self.move_to_end(key)
            return value

    def __setitem__(self, key: str, value: Any):
        with self._lock:
            if key in self:
                self.move_to_end(key)
            super().__setitem__(key, value)
            if len(self) > self.maxsize:
                oldest = next(iter(self))
                del self[oldest]

    def __delitem__(self, key: str):
        with self._lock:
            super().__delitem__(key)

    def __contains__(self, key: str) -> bool:
        with self._lock:
            return super().__contains__(key)

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            try:
                return self[key]
            except KeyError:
                return default

    def pop(self, key: str, *args) -> Any:
        with self._lock:
            try:
                value = dict.__getitem__(self, key)
                OrderedDict.__delitem__(self, key)
                return value
            except KeyError:
                if args:
                    return args[0]
                raise

    def clear(self) -> None:
        with self._lock:
            super().clear()
