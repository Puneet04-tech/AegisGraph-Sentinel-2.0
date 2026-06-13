import threading
import time
import pytest
from ring_buffer_concurrency import InMemoryRingBuffer

def test_ring_buffer_concurrency_stress():
    capacity = 5000
    buffer = InMemoryRingBuffer(capacity=capacity)
    
    num_threads = 100
    writes_per_thread = 50
    inserted_items = set()
    inserted_lock = threading.Lock()
    
    def worker(thread_idx):
        for i in range(writes_per_thread):
            item = f"t{thread_idx}_e{i}"
            # Attempt to enqueue until successful or wait briefly
            while not buffer.enqueue(item):
                time.sleep(0.001)
            with inserted_lock:
                inserted_items.add(item)
                
    threads = []
    for i in range(num_threads):
        t = threading.Thread(target=worker, args=(i,))
        threads.append(t)
        
    # Start all threads
    for t in threads:
        t.start()
        
    # Start a consumer thread that dequeues items concurrently
    dequeued_items = []
    dequeued_lock = threading.Lock()
    stop_consumer = False
    
    def consumer():
        while not stop_consumer or len(dequeued_items) < num_threads * writes_per_thread:
            batch = buffer.dequeue_batch(max_batch_size=20)
            if batch:
                with dequeued_lock:
                    dequeued_items.extend(batch)
            else:
                time.sleep(0.001)
                
    c_thread = threading.Thread(target=consumer)
    c_thread.start()
    
    # Wait for all producers to finish
    for t in threads:
        t.join()
        
    # Stop consumer and wait
    stop_consumer = True
    c_thread.join()
    
    # Dequeue any remaining items
    remaining = buffer.dequeue_batch(max_batch_size=1000)
    dequeued_items.extend(remaining)
    
    # Check that all written items were successfully dequeued without corruption or duplication
    assert len(dequeued_items) == num_threads * writes_per_thread
    assert set(dequeued_items) == inserted_items
