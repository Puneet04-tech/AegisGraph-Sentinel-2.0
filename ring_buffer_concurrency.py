import collections
import threading
import time

class InMemoryRingBuffer:
    def __init__(self, capacity=1024):
        # Capacity must be a power of 2 for fast bitwise math
        self.capacity = capacity
        self.buffer = [None] * capacity
        self.write_sequence = 0
        self.read_sequence = 0
        self._lock = threading.Lock()

    def enqueue(self, event_data):
        """Adds an event to the buffer without blocking if there is space."""
        with self._lock:
            if self.write_sequence - self.read_sequence >= self.capacity:
                # Buffer is full (Backpressure strategy: drop old/ignore)
                return False
            
            # Put data into the circular slot
            index = self.write_sequence & (self.capacity - 1)
            self.buffer[index] = event_data
            self.write_sequence += 1
            return True

    def dequeue_batch(self, max_batch_size=32):
        """Reads a batch of events out of the buffer cleanly."""
        events = []
        with self._lock:
            available = self.write_sequence - self.read_sequence
            if available == 0:
                return events
                
            batch_size = min(available, max_batch_size)
            for _ in range(batch_size):
                index = self.read_sequence & (self.capacity - 1)
                events.append(self.buffer[index])
                self.buffer[index] = None  # Clear memory slot
                self.read_sequence += 1
        return events