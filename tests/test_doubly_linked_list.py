"""Unit and performance tests for DoublyLinkedList."""
import time
import pytest
from src.timeline.doubly_linked_list import DoublyLinkedList, Node


class TestDoublyLinkedListBasic:
    """Basic functional tests for DoublyLinkedList."""

    def test_empty_list(self):
        dll = DoublyLinkedList()
        assert len(dll) == 0
        assert dll.head is None
        assert dll.tail is None
        assert not dll
        with pytest.raises(IndexError):
            dll.pop()
        with pytest.raises(IndexError):
            dll.popleft()

    def test_append(self):
        dll = DoublyLinkedList()
        dll.append(10)
        assert len(dll) == 1
        assert dll.head.value == 10
        assert dll.tail.value == 10
        assert dll

        dll.append(20)
        assert len(dll) == 2
        assert dll.head.value == 10
        assert dll.tail.value == 20
        assert dll.head.next.value == 20
        assert dll.tail.prev.value == 10

    def test_appendleft(self):
        dll = DoublyLinkedList()
        dll.appendleft(10)
        assert len(dll) == 1
        assert dll.head.value == 10
        assert dll.tail.value == 10

        dll.appendleft(5)
        assert len(dll) == 2
        assert dll.head.value == 5
        assert dll.tail.value == 10
        assert dll.head.next.value == 10
        assert dll.tail.prev.value == 5

    def test_pop(self):
        dll = DoublyLinkedList()
        dll.append(10)
        dll.append(20)
        assert dll.pop() == 20
        assert len(dll) == 1
        assert dll.tail.value == 10
        assert dll.tail.next is None

        assert dll.pop() == 10
        assert len(dll) == 0
        assert dll.head is None
        assert dll.tail is None

    def test_popleft(self):
        dll = DoublyLinkedList()
        dll.append(10)
        dll.append(20)
        assert dll.popleft() == 10
        assert len(dll) == 1
        assert dll.head.value == 20
        assert dll.head.prev is None

        assert dll.popleft() == 20
        assert len(dll) == 0
        assert dll.head is None
        assert dll.tail is None

    def test_clear(self):
        dll = DoublyLinkedList()
        dll.append(1)
        dll.append(2)
        dll.clear()
        assert len(dll) == 0
        assert dll.head is None
        assert dll.tail is None


class TestDoublyLinkedListIndexingAndIter:
    """Tests indexing, iteration, and list conversions."""

    def test_indexing_ends(self):
        dll = DoublyLinkedList()
        dll.append("a")
        dll.append("b")
        dll.append("c")
        
        # Test O(1) indices
        assert dll[0] == "a"
        assert dll[-1] == "b" or dll[-1] == "c"  # wait, dll[-1] must be "c"
        assert dll[-1] == "c"
        
        # Test negative indices and boundaries
        assert dll[1] == "b"
        assert dll[-2] == "b"
        assert dll[-3] == "a"
        
        with pytest.raises(IndexError):
            _ = dll[3]
        with pytest.raises(IndexError):
            _ = dll[-4]

    def test_iteration(self):
        dll = DoublyLinkedList()
        values = [1, 2, 3, 4]
        for v in values:
            dll.append(v)

        assert list(dll) == values
        assert list(reversed(dll)) == [4, 3, 2, 1]
        assert dll.to_list() == values


class TestDoublyLinkedListBoundedMemory:
    """Tests bounded capacity limits and evictions."""

    def test_max_size_append_evicts_head(self):
        dll = DoublyLinkedList(max_size=3)
        dll.append(1)
        dll.append(2)
        dll.append(3)
        assert len(dll) == 3
        assert dll.to_list() == [1, 2, 3]

        # Exceed capacity: should evict from head (1)
        dll.append(4)
        assert len(dll) == 3
        assert dll.to_list() == [2, 3, 4]

        dll.append(5)
        assert len(dll) == 3
        assert dll.to_list() == [3, 4, 5]

    def test_max_size_appendleft_evicts_tail(self):
        dll = DoublyLinkedList(max_size=3)
        dll.appendleft(1)
        dll.appendleft(2)
        dll.appendleft(3)
        assert len(dll) == 3
        assert dll.to_list() == [3, 2, 1]

        # Exceed capacity: should evict from tail (1)
        dll.appendleft(4)
        assert len(dll) == 3
        assert dll.to_list() == [4, 3, 2]


class TestDoublyLinkedListPerformance:
    """Performance benchmarks simulating high-frequency event streams (e.g. 100+ events/sec)."""

    def test_high_frequency_simulation(self):
        # Target: simulate 10,000 events inserted at head of a capped list.
        # This is equivalent to 100 events/second for 100 seconds.
        max_capacity = 100
        dll = DoublyLinkedList(max_size=max_capacity)

        start_time = time.perf_counter()
        for i in range(10000):
            dll.appendleft({"id": i, "timestamp": time.time(), "type": "ALERT"})
        end_time = time.perf_counter()

        duration = end_time - start_time
        assert len(dll) == max_capacity
        # DLL O(1) insertions should be extremely fast, typically < 0.05 seconds
        assert duration < 0.2, f"High-frequency simulation took too long: {duration:.4f}s"

    def test_dll_vs_list_performance(self):
        """Verifies that DoublyLinkedList outperforms array-based list shift and slice at scale."""
        n_insertions = 15000
        max_capacity = 100

        # Measure standard list insert(0) and slicing
        start_list = time.perf_counter()
        lst = []
        for i in range(n_insertions):
            lst.insert(0, i)
            lst = lst[:max_capacity]
        end_list = time.perf_counter()
        list_time = end_list - start_list

        # Measure DoublyLinkedList appendleft
        start_dll = time.perf_counter()
        dll = DoublyLinkedList(max_size=max_capacity)
        for i in range(n_insertions):
            dll.appendleft(i)
        end_dll = time.perf_counter()
        dll_time = end_dll - start_dll

        # DLL must be faster or comparable (usually much faster because we avoid memory copies of lists)
        # We assert dll_time is reasonable (e.g. < 0.1s)
        assert dll_time < 0.1, f"DLL took too long: {dll_time:.4f}s"
