"""Feature hashing encoder for categorical values without a dictionary.

Maps arbitrary categorical strings to a fixed-size feature vector using a
deterministic hash. The signed trick reduces the impact of hash collisions
(the expected number of collisions across ``n_features`` buckets is low and
the alternating sign lets colliding features partially cancel).
"""

import hashlib
from typing import Dict, List, Union


class HashingEncoder:
    """Deterministic hashing encoder mapping strings to sparse indices."""

    def __init__(self, n_features: int = 100, seed: int = 0) -> None:
        if n_features <= 0:
            raise ValueError("n_features must be positive")
        self.n_features = n_features
        self.seed = seed

    def _digest(self, value: str) -> int:
        payload = f"{self.seed}|{value}".encode("utf-8")
        return int.from_bytes(hashlib.md5(payload).digest(), "big")

    def transform(self, value: str) -> Dict[str, int]:
        """Return {"index": int, "sign": int} for the given categorical value."""
        if value is None:
            value = ""
        if not isinstance(value, str):
            value = str(value)
        digest = self._digest(value)
        index = digest % self.n_features
        sign = 1 if (digest >> 32) % 2 == 0 else -1
        return {"index": index, "sign": sign}

    def vectorize(self, value: str) -> List[int]:
        """Return a full vector of length ``n_features`` with the sign at index."""
        vector = [0] * self.n_features
        mapped = self.transform(value)
        vector[mapped["index"]] = mapped["sign"]
        return vector

    def encode(self, value: str) -> int:
        """Return just the sparse index for simple use cases."""
        return self.transform(value)["index"]


def ngram_tokens(text: str, n: int = 2) -> List[str]:
    """Return character n-grams (lowercased) for ``text``."""
    if not text:
        return []
    if n <= 0:
        raise ValueError("n must be positive")
    normalized = text.lower().strip()
    if len(normalized) < n:
        return []
    return [normalized[i : i + n] for i in range(len(normalized) - n + 1)]


def encode_sentence(text: str, n_features: int = 100, n: int = 2) -> List[int]:
    """Return the summed signed one-hot vectors over all n-grams of ``text``."""
    encoder = HashingEncoder(n_features=n_features)
    vector = [0] * n_features
    for token in ngram_tokens(text, n=n):
        mapped = encoder.transform(token)
        vector[mapped["index"]] += mapped["sign"]
    return vector
