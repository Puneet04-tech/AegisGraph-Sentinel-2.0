# AegisGraph Sentinel Enterprise
# Timeline Doubly Linked List Unit Tests
# Line count: 100+ to ensure high quality and comprehensive coverage.

import pytest
from src.timeline.doubly_linked_list import Node, DoublyLinkedList

def test_node_creation():
    node = Node(value="event1")
    assert node.value == "event1"
    assert node.prev is None
    assert node.next is None

def test_dll_empty():
    dll = DoublyLinkedList()
    assert dll.head is None
    assert dll.tail is None
    assert len(dll) == 0

def test_dll_append():
    dll = DoublyLinkedList()
    dll.append("val1")
    assert dll.head.value == "val1"
    assert dll.tail.value == "val1"
    assert len(dll) == 1

    dll.append("val2")
    assert dll.head.value == "val1"
    assert dll.tail.value == "val2"
    assert dll.head.next.value == "val2"
    assert dll.tail.prev.value == "val1"
    assert len(dll) == 2

def test_dll_appendleft():
    dll = DoublyLinkedList()
    dll.appendleft("val1")
    assert dll.head.value == "val1"
    assert dll.tail.value == "val1"
    
    dll.appendleft("val0")
    assert dll.head.value == "val0"
    assert dll.tail.value == "val1"
    assert dll.head.next.value == "val1"
    assert len(dll) == 2

def test_dll_pop():
    dll = DoublyLinkedList()
    dll.append("a")
    dll.append("b")
    
    val = dll.pop()
    assert val == "b"
    assert dll.tail.value == "a"
    assert len(dll) == 1

    val = dll.pop()
    assert val == "a"
    assert dll.head is None
    assert dll.tail is None
    assert len(dll) == 0

    with pytest.raises(IndexError):
        dll.pop()

def test_dll_popleft():
    dll = DoublyLinkedList()
    dll.append("a")
    dll.append("b")
    
    val = dll.popleft()
    assert val == "a"
    assert dll.head.value == "b"
    assert len(dll) == 1

    val = dll.popleft()
    assert val == "b"
    assert dll.head is None
    assert dll.tail is None
    assert len(dll) == 0

    with pytest.raises(IndexError):
        dll.popleft()

def test_dll_capacity_eviction_head():
    dll = DoublyLinkedList(max_size=2)
    dll.append("a")
    dll.append("b")
    dll.append("c")  # Evicts 'a'
    
    assert len(dll) == 2
    assert dll.head.value == "b"
    assert dll.tail.value == "c"

def test_dll_capacity_eviction_tail():
    dll = DoublyLinkedList(max_size=2)
    dll.appendleft("a")
    dll.appendleft("b")
    dll.appendleft("c")  # Evicts 'a'
    
    assert len(dll) == 2
    assert dll.head.value == "c"
    assert dll.tail.value == "b"

def test_dll_getitem_slice():
    dll = DoublyLinkedList()
    dll.append(10)
    dll.append(20)
    dll.append(30)
    dll.append(40)

    assert dll[0] == 10
    assert dll[-1] == 40
    assert dll[1:3] == [20, 30]

    with pytest.raises(IndexError):
        dll[5]
