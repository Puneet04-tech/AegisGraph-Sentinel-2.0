"""Custom Doubly Linked List module for managing timeline event state."""
from typing import Any, Optional, Iterator

class Node:
    """A Node in a Doubly Linked List."""
    __slots__ = ('value', 'prev', 'next')
    
    def __init__(self, value: Any, prev: Optional['Node'] = None, next: Optional['Node'] = None):
        self.value = value
        self.prev = prev
        self.next = next


class DoublyLinkedList:
    """A custom Doubly Linked List tailored for managing high-frequency event feeds.
    
    Supports:
      - O(1) appends and appendlefts.
      - O(1) pops and poplefts.
      - Auto-eviction based on `max_size` capacity limit.
      - O(1) lookup for index 0 and -1.
      - O(N) lookup for other indices.
      - Forward and backward iteration.
    """
    def __init__(self, max_size: Optional[int] = None):
        self.head: Optional[Node] = None
        self.tail: Optional[Node] = None
        self._size: int = 0
        self.max_size: Optional[int] = max_size

    def __len__(self) -> int:
        return self._size

    def append(self, value: Any) -> Node:
        """Add value to the tail of the list. O(1) complexity."""
        node = Node(value, prev=self.tail, next=None)
        if self.tail:
            self.tail.next = node
            self.tail = node
        else:
            self.head = self.tail = node
        self._size += 1
        
        self._check_capacity_and_evict_from_head()
        return node

    def appendleft(self, value: Any) -> Node:
        """Add value to the head of the list. O(1) complexity."""
        node = Node(value, prev=None, next=self.head)
        if self.head:
            self.head.prev = node
            self.head = node
        else:
            self.head = self.tail = node
        self._size += 1
        
        self._check_capacity_and_evict_from_tail()
        return node

    def pop(self) -> Any:
        """Remove and return the value from the tail. O(1) complexity."""
        if not self.tail:
            raise IndexError("pop from empty list")
        node = self.tail
        self.tail = node.prev
        if self.tail:
            self.tail.next = None
        else:
            self.head = None
        self._size -= 1
        return node.value

    def popleft(self) -> Any:
        """Remove and return the value from the head. O(1) complexity."""
        if not self.head:
            raise IndexError("pop from empty list")
        node = self.head
        self.head = node.next
        if self.head:
            self.head.prev = None
        else:
            self.tail = None
        self._size -= 1
        return node.value

    def _check_capacity_and_evict_from_head(self) -> None:
        """Evicts from head if list size exceeds maximum capacity."""
        if self.max_size is not None and self._size > self.max_size:
            self.popleft()

    def _check_capacity_and_evict_from_tail(self) -> None:
        """Evicts from tail if list size exceeds maximum capacity."""
        if self.max_size is not None and self._size > self.max_size:
            self.pop()

    def __iter__(self) -> Iterator[Any]:
        """Forward traversal from head to tail."""
        current = self.head
        while current:
            yield current.value
            current = current.next

    def __reversed__(self) -> Iterator[Any]:
        """Backward traversal from tail to head."""
        current = self.tail
        while current:
            yield current.value
            current = current.prev

    def to_list(self) -> list:
        """Convert the linked list to a standard Python list."""
        return list(self)

    def clear(self) -> None:
        """Clear all nodes from the list."""
        self.head = None
        self.tail = None
        self._size = 0

    def __bool__(self) -> bool:
        """Boolean check based on whether the list is empty."""
        return self._size > 0

    def __getitem__(self, index: int) -> Any:
        """Get the item at index.
        
        Optimized for:
          - index `0` (head): O(1)
          - index `-1` or `size - 1` (tail): O(1)
          
        Other indices have O(N) complexity.
        """
        if not isinstance(index, int):
            raise TypeError("Index must be an integer")
        if index < 0:
            index += self._size
        if index < 0 or index >= self._size:
            raise IndexError("Index out of range")
        
        if index == 0:
            return self.head.value
        if index == self._size - 1:
            return self.tail.value
            
        current = self.head
        for _ in range(index):
            current = current.next
        return current.value
