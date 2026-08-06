"""Unit tests for the priority queue module."""

import pytest

from src.utils.priority_queue import BoundedPriorityQueue, PriorityQueue, priority_sort


class TestPriorityQueueBasic:
    def test_fifo_within_same_priority(self):
        pq = PriorityQueue()
        for item in (1, 2, 3):
            pq.push(item, priority=0)
        assert [pq.pop(), pq.pop(), pq.pop()] == [1, 2, 3]

    def test_lower_priority_number_popped_first(self):
        pq = PriorityQueue()
        pq.push("low", priority=10)
        pq.push("high", priority=1)
        pq.push("medium", priority=5)
        assert pq.pop() == "high"
        assert pq.pop() == "medium"
        assert pq.pop() == "low"

    def test_peek_does_not_remove(self):
        pq = PriorityQueue()
        pq.push("urgent", priority=1)
        pq.push("later", priority=2)
        assert pq.peek() == "urgent"
        assert pq.peek() == "urgent"
        assert pq.size() == 2
        assert pq.pop() == "urgent"
        assert pq.size() == 1

    def test_pop_on_empty_raises_index_error(self):
        pq = PriorityQueue()
        with pytest.raises(IndexError):
            pq.pop()

    def test_peek_on_empty_raises_index_error(self):
        pq = PriorityQueue()
        with pytest.raises(IndexError):
            pq.peek()

    def test_is_empty_len_size(self):
        pq = PriorityQueue()
        assert pq.is_empty()
        assert len(pq) == 0
        assert pq.size() == 0
        pq.push("a")
        assert not pq.is_empty()
        assert len(pq) == 1
        assert pq.size() == 1

    def test_clear_resets_queue(self):
        pq = PriorityQueue()
        pq.push("a", priority=1)
        pq.push("b", priority=2)
        pq.clear()
        assert pq.is_empty()
        assert len(pq) == 0
        pq.push("c", priority=0)
        assert pq.pop() == "c"


class TestPriorityQueueOrdering:
    def test_interleaved_mixed_priorities(self):
        pq = PriorityQueue()
        pq.push("a", priority=3)
        pq.push("b", priority=1)
        pq.push("c", priority=2)
        pq.push("d", priority=1)
        pq.push("e", priority=0)
        assert [pq.pop() for _ in range(5)] == ["e", "b", "d", "c", "a"]

    def test_fifo_tie_break_across_interleaving(self):
        pq = PriorityQueue()
        pq.push("first", priority=2)
        pq.push("second", priority=1)
        pq.push("third", priority=2)
        pq.push("fourth", priority=1)
        assert pq.pop() == "second"
        assert pq.pop() == "fourth"
        assert pq.pop() == "first"
        assert pq.pop() == "third"

    def test_negative_priorities_allowed(self):
        pq = PriorityQueue()
        pq.push("normal", priority=0)
        pq.push("critical", priority=-10)
        assert pq.pop() == "critical"
        assert pq.pop() == "normal"

    def test_many_items_round_trip_preserves_priority_order(self):
        import random

        random.seed(42)
        items = [(random.randint(-5, 5), i) for i in range(500)]
        pq = PriorityQueue()
        for priority, item in items:
            pq.push(item, priority=priority)
        popped = [pq.pop() for _ in range(len(items))]
        expected = [item for _, item in sorted(items, key=lambda pair: (pair[0], pair[1]))]
        assert popped == expected
        assert pq.is_empty()


class TestPrioritySort:
    def test_sorts_by_priority_ascending(self):
        cases = [
            {"id": "case-1", "severity": 7},
            {"id": "case-2", "severity": 2},
            {"id": "case-3", "severity": 5},
        ]
        sorted_cases = priority_sort(cases, key=lambda c: c["severity"])
        assert [c["id"] for c in sorted_cases] == ["case-2", "case-3", "case-1"]

    def test_stable_for_equal_priorities(self):
        cases = [
            {"id": "a", "severity": 3},
            {"id": "b", "severity": 3},
            {"id": "c", "severity": 3},
        ]
        sorted_cases = priority_sort(cases, key=lambda c: c["severity"])
        assert [c["id"] for c in sorted_cases] == ["a", "b", "c"]

    def test_empty_items(self):
        assert priority_sort([], key=lambda x: x) == []


class TestBoundedPriorityQueue:
    def test_full_push_raises_index_error(self):
        bq = BoundedPriorityQueue(max_size=2)
        bq.push("a")
        bq.push("b")
        with pytest.raises(IndexError):
            bq.push("c")

    def test_size_respected(self):
        bq = BoundedPriorityQueue(max_size=3)
        for i in range(3):
            bq.push(i)
        assert len(bq) == 3
        assert bq.size() == 3
        with pytest.raises(IndexError):
            bq.push(99)

    def test_works_normally_under_limit(self):
        bq = BoundedPriorityQueue(max_size=4)
        bq.push("low", priority=2)
        bq.push("high", priority=1)
        assert bq.size() == 2
        assert bq.pop() == "high"
        assert bq.pop() == "low"

    def test_zero_max_size_rejects_everything(self):
        bq = BoundedPriorityQueue(max_size=0)
        with pytest.raises(IndexError):
            bq.push("anything")

    def test_frees_space_after_pop(self):
        bq = BoundedPriorityQueue(max_size=2)
        bq.push("a")
        bq.push("b")
        bq.pop()
        bq.push("c")
        assert bq.size() == 2
        assert bq.pop() == "b"
        assert bq.pop() == "c"

    def test_rejects_negative_max_size(self):
        with pytest.raises(ValueError):
            BoundedPriorityQueue(max_size=-1)

    def test_priority_ordering_still_applies(self):
        bq = BoundedPriorityQueue(max_size=3)
        bq.push("p3", priority=3)
        bq.push("p1", priority=1)
        bq.push("p2", priority=2)
        assert [bq.pop() for _ in range(3)] == ["p1", "p2", "p3"]
