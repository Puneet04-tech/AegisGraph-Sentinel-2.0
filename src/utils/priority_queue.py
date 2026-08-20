"""Priority queue for triaging cases and events by severity.

Smaller priority values are processed first; items pushed with equal
priority are returned in FIFO order.
"""

import heapq
from typing import Callable, Iterator, List, Sequence, Tuple, TypeVar

T = TypeVar("T")


class PriorityQueue:
    """Min-heap priority queue with FIFO tie-breaking.

    Internal entries are ``(priority, sequence, item)`` tuples so that
    equal priorities compare only on the monotonic sequence counter.
    """

    def __init__(self) -> None:
        self._heap: List[Tuple[int, int, T]] = []
        self._sequence = 0

    def push(self, item: T, priority: int = 0) -> None:
        heapq.heappush(self._heap, (priority, self._sequence, item))
        self._sequence += 1

    def pop(self) -> T:
        if not self._heap:
            raise IndexError("pop from empty PriorityQueue")
        _, _, item = heapq.heappop(self._heap)
        return item

    def peek(self) -> T:
        if not self._heap:
            raise IndexError("peek from empty PriorityQueue")
        return self._heap[0][2]

    def is_empty(self) -> bool:
        return not self._heap

    def clear(self) -> None:
        self._heap.clear()

    def size(self) -> int:
        return len(self._heap)

    def __len__(self) -> int:
        return len(self._heap)

    def __iter__(self) -> Iterator[Tuple[int, int, T]]:
        return iter(self._heap)


def priority_sort(items: Sequence[T], key: Callable[[T], int]) -> List[T]:
    """Return ``items`` sorted by priority ascending, stable for ties."""
    return sorted(items, key=key)


class BoundedPriorityQueue(PriorityQueue):
    """PriorityQueue that rejects pushes once ``max_size`` is reached.

    Pushing past the bound raises ``IndexError``; items are never
    evicted automatically.
    """

    def __init__(self, max_size: int) -> None:
        if max_size < 0:
            raise ValueError("max_size must be non-negative")
        super().__init__()
        self._max_size = max_size

    def push(self, item: T, priority: int = 0) -> None:
        if self.size() >= self._max_size:
            raise IndexError("BoundedPriorityQueue is full")
        super().push(item, priority)
