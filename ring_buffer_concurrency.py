import collections
import threading
import time

class InMemoryRingBuffer:
    def __init__(self, capacity=1024):
        self.capacity = capacity
        self.buffer = collections.deque(maxlen=capacity)
        self._lock = threading.Lock()

    def enqueue(self, event_data):
        """Adds an event to the buffer without blocking if there is space."""
        with self._lock:
            if len(self.buffer) >= self.capacity:
                # Buffer is full (Backpressure strategy: drop old/ignore)
                return False
            self.buffer.append(event_data)
            return True

    def dequeue_batch(self, max_batch_size=32):
        """Reads a batch of events out of the buffer cleanly."""
        events = []
        with self._lock:
            available = len(self.buffer)
            if available == 0:
                return events
                
            batch_size = min(available, max_batch_size)
            for _ in range(batch_size):
                events.append(self.buffer.popleft())
        return events