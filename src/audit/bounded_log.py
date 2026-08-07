"""Bounded in-memory audit log with globally unique event ids.

Seventeen store and service modules each carried a copy-pasted
``self._audit_log: List[...] = []`` that appended forever and was only ever
emptied by a full reset, so audit memory grew monotonically for the lifetime of
the process across every one of those subsystems at once.

The same copied code derived event ids from the list's current length
(``f"audit-{len(self._audit_log) + 1}"``). That is only a valid counter while
nothing is ever removed: after a reset -- or once a retention bound starts
evicting -- new events reuse ids that already identify different historical
events, which undermines the audit trail exactly where uniqueness matters most.

This module supplies both halves of the fix: a bounded, thread-safe log, and a
process-wide monotonic id source that does not depend on how many entries are
currently retained.
"""

from __future__ import annotations

import itertools
import os
import threading
from collections import deque
from typing import Any, Deque, Iterable, List, Optional

# Deep enough that an operator investigating a recent incident still finds the
# relevant history, shallow enough that seventeen of these cannot exhaust a
# process. Override with AEGIS_AUDIT_LOG_CAPACITY.
DEFAULT_AUDIT_CAPACITY = 10_000

_ENV_CAPACITY = "AEGIS_AUDIT_LOG_CAPACITY"

# One counter for the whole process, so ids stay unique across every log
# instance and across clears.
_id_counter = itertools.count(1)
_id_lock = threading.Lock()


def default_capacity() -> int:
    """Resolve the configured retention bound, falling back to the default.

    A malformed or non-positive override falls back rather than raising, since
    an unparseable environment variable must not stop the process from starting.
    """
    raw = os.getenv(_ENV_CAPACITY)
    if raw is None:
        return DEFAULT_AUDIT_CAPACITY
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_AUDIT_CAPACITY
    return value if value > 0 else DEFAULT_AUDIT_CAPACITY


def next_event_id(prefix: str = "audit") -> str:
    """Return a process-unique, monotonically increasing audit event id.

    Replaces ``f"{prefix}-{len(log) + 1}"``, which collided after any clear.
    """
    with _id_lock:
        return f"{prefix}-{next(_id_counter)}"


def reset_event_ids() -> None:
    """Restart the id sequence. Intended for tests only."""
    global _id_counter
    with _id_lock:
        _id_counter = itertools.count(1)


class BoundedAuditLog:
    """Thread-safe append-only audit buffer with oldest-first eviction.

    Behaves like the list it replaces for every read the callers perform --
    ``tail(limit)`` returns the same slice ``self._audit_log[-limit:]`` did,
    in the same order -- but memory use is constant regardless of uptime.

    Args:
        capacity: Maximum entries retained. Defaults to the configured value.
    """

    def __init__(self, capacity: Optional[int] = None) -> None:
        resolved = default_capacity() if capacity is None else capacity
        if resolved <= 0:
            # A zero or negative bound would silently discard everything, which
            # is never what a caller means by "audit log".
            resolved = default_capacity()
        self._capacity = resolved
        self._entries: Deque[Any] = deque(maxlen=resolved)
        self._lock = threading.RLock()
        self._dropped = 0

    @property
    def capacity(self) -> int:
        """Maximum number of entries retained."""
        return self._capacity

    @property
    def dropped(self) -> int:
        """How many entries eviction has discarded.

        Surfaced so silent eviction is observable rather than invisible: an
        operator seeing a non-zero value knows history has been truncated.
        """
        with self._lock:
            return self._dropped

    def append(self, entry: Any) -> None:
        """Record an entry, evicting the oldest once capacity is reached."""
        with self._lock:
            if len(self._entries) == self._capacity:
                self._dropped += 1
            self._entries.append(entry)

    def extend(self, entries: Iterable[Any]) -> None:
        """Record several entries in order."""
        for entry in entries:
            self.append(entry)

    def tail(self, limit: int = 100) -> List[Any]:
        """Return the most recent *limit* entries, oldest first.

        Matches the ``[-limit:]`` slicing semantics of the list this replaces,
        including a non-positive limit yielding an empty list.
        """
        with self._lock:
            if limit <= 0:
                return []
            if limit >= len(self._entries):
                return list(self._entries)
            return list(self._entries)[-limit:]

    def all(self) -> List[Any]:
        """Return every retained entry, oldest first."""
        with self._lock:
            return list(self._entries)

    def clear(self) -> None:
        """Drop every retained entry and reset the eviction counter."""
        with self._lock:
            self._entries.clear()
            self._dropped = 0

    def stats(self) -> dict:
        """Return retention statistics for inclusion in a store's metrics."""
        with self._lock:
            return {
                "retained": len(self._entries),
                "capacity": self._capacity,
                "dropped": self._dropped,
            }

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def __iter__(self):
        # Iterates a snapshot so a concurrent append cannot invalidate it.
        return iter(self.all())

    def __reversed__(self):
        """Iterate newest first.

        Defined explicitly because the sequence-protocol fallback would route
        through ``__getitem__``, which snapshots the whole buffer per index and
        would make a single reverse scan quadratic.
        """
        return reversed(self.all())

    def __bool__(self) -> bool:
        with self._lock:
            return bool(self._entries)

    def __getitem__(self, index):
        """Index or slice the retained entries.

        Present so the migrated modules keep working if any caller was relying
        on list indexing, including the ``[-limit:]`` idiom.
        """
        with self._lock:
            return list(self._entries)[index]
