import threading
import time


class RateLimiter:
    """A thread-safe Token-Bucket rate limiter."""

    def __init__(self, capacity: float, refill_rate: float):
        """Initialize the rate limiter.

        Args:
            capacity: Maximum number of tokens in the bucket.
            refill_rate: Number of tokens added to the bucket per second.
        """
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate)
        self.tokens = float(capacity)
        self.last_refill = time.time()
        self.lock = threading.Lock()

    def consume(self, tokens: int = 1) -> bool:
        """Attempt to consume the specified number of tokens from the bucket.

        Args:
            tokens: The number of tokens to consume.

        Returns:
            True if tokens were consumed (request allowed), False otherwise.
        """
        with self.lock:
            now = time.time()
            # Calculate elapsed time and add refilled tokens
            elapsed = now - self.last_refill
            if elapsed > 0:
                self.tokens = min(
                    self.capacity, self.tokens + (elapsed * self.refill_rate)
                )
                self.last_refill = now

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True

            return False
