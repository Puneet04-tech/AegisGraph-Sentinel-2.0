"""
Fraud Decision Cache Security

Prevents cache-based fraud bypass attacks (issue #2586). Implements
secure caching strategies for fraud check decisions that prevent
attackers from reusing previously approved transaction IDs to bypass
real-time scoring.

Vulnerability: If fraud decisions are cached using client-supplied
transaction_id as the key, an attacker can replay a transaction_id
that previously received an APPROVE decision, bypassing HTGNN and
biometric analysis.
"""

import hashlib
import json
from typing import Any, Dict, Optional
from collections import OrderedDict
from threading import Lock
import time


class FraudDecisionCache:
    """
    Secure cache for fraud check decisions.

    Prevents replay attacks by:
    1. Tracking seen transaction IDs (reject duplicates)
    2. Including transaction data in cache key (not just ID)
    3. Enforcing per-transaction uniqueness

    The cache is in-memory (not shared across processes). For production
    distributed systems, migrate to Redis with transaction ID uniqueness
    enforced at the database level.
    """

    def __init__(self, max_entries: int = 10000, ttl_seconds: int = 86400):
        """
        Initialize the fraud decision cache.

        Args:
            max_entries: Maximum number of cached decisions
            ttl_seconds: Time-to-live for cache entries (1 day default)
        """
        self._decision_cache: OrderedDict[str, Dict[str, Any]] = OrderedDict()
        self._seen_txns: OrderedDict[str, float] = OrderedDict()  # txn_id -> timestamp
        self._lock = Lock()
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds

    def is_duplicate_transaction(self, transaction_id: str) -> bool:
        """
        Check if a transaction ID has been seen before.

        In a real payment system, transaction IDs must be globally unique
        and assigned by the issuing bank. Client-supplied IDs should never
        be reused. This check prevents cache-based replay attacks.

        Args:
            transaction_id: The transaction ID to check

        Returns:
            True if this ID has been seen before (duplicate), False otherwise
        """
        with self._lock:
            # Clean up expired entries
            self._cleanup_expired()

            if transaction_id in self._seen_txns:
                return True

            # Mark as seen
            self._seen_txns[transaction_id] = time.time()

            # Prevent unbounded growth
            if len(self._seen_txns) > self.max_entries:
                self._seen_txns.popitem(last=False)

            return False

    def get_cached_decision(
        self,
        transaction: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve a cached fraud decision for a transaction.

        Cache key includes transaction data (amount, source, target) to prevent
        reusing decisions for different transactions with the same ID.

        Args:
            transaction: Transaction dictionary

        Returns:
            Cached decision dict, or None if not in cache

        Note: In production, cache key should include transaction hash to
        ensure decisions aren't reused across different transaction data.
        """
        with self._lock:
            # Clean up expired entries
            self._cleanup_expired()

            cache_key = self._make_cache_key(transaction)
            if cache_key in self._decision_cache:
                cached = self._decision_cache[cache_key]
                # Move to end (LRU behavior)
                self._decision_cache.move_to_end(cache_key)
                return cached["decision"]

            return None

    def cache_decision(
        self,
        transaction: Dict[str, Any],
        decision: Dict[str, Any],
    ) -> None:
        """
        Cache a fraud check decision.

        Args:
            transaction: Transaction dictionary
            decision: Fraud decision result dict
        """
        with self._lock:
            cache_key = self._make_cache_key(transaction)

            # Store decision with timestamp
            self._decision_cache[cache_key] = {
                "decision": decision,
                "timestamp": time.time(),
            }

            # Prevent unbounded growth
            if len(self._decision_cache) > self.max_entries:
                self._decision_cache.popitem(last=False)

    def _make_cache_key(self, transaction: Dict[str, Any]) -> str:
        """
        Create a cache key including transaction data.

        Includes source, target, and amount to prevent decisions from being
        reused for different transactions with the same ID.

        Args:
            transaction: Transaction dictionary

        Returns:
            Cache key string
        """
        # Include transaction data in cache key (not just ID)
        key_data = {
            "txn_id": transaction.get("transaction_id"),
            "source": transaction.get("source_account"),
            "target": transaction.get("target_account"),
            "amount": transaction.get("amount"),
        }

        # Create hash of transaction data
        key_json = json.dumps(key_data, sort_keys=True)
        key_hash = hashlib.sha256(key_json.encode()).hexdigest()

        return f"fraud_decision:{key_hash}"

    def _cleanup_expired(self) -> None:
        """Remove expired entries from cache."""
        current_time = time.time()
        expired_keys = [
            key
            for key, data in self._decision_cache.items()
            if current_time - data["timestamp"] > self.ttl_seconds
        ]

        for key in expired_keys:
            del self._decision_cache[key]

        # Clean up seen transactions
        expired_txns = [
            txn_id
            for txn_id, timestamp in self._seen_txns.items()
            if current_time - timestamp > self.ttl_seconds
        ]

        for txn_id in expired_txns:
            del self._seen_txns[txn_id]

    def clear(self) -> None:
        """Clear all cached data."""
        with self._lock:
            self._decision_cache.clear()
            self._seen_txns.clear()

    def get_stats(self) -> Dict[str, int]:
        """Get cache statistics."""
        with self._lock:
            return {
                "cached_decisions": len(self._decision_cache),
                "seen_transactions": len(self._seen_txns),
            }


# Global cache instance
_fraud_cache: Optional[FraudDecisionCache] = None


def get_fraud_cache() -> FraudDecisionCache:
    """Get or create the global fraud decision cache."""
    global _fraud_cache
    if _fraud_cache is None:
        _fraud_cache = FraudDecisionCache()
    return _fraud_cache
