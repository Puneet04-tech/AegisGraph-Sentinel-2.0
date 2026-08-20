"""Hashing and checksum utilities.

Stable, deterministic hashing helpers used for feature keys, caching and
consistent sharding across worker processes.
"""

import hashlib
import json
from typing import Any


def sha256_hex(data):
    """Return the lowercase SHA-256 hex digest for str or bytes input.

    Strings are encoded as UTF-8 before hashing.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def md5_hex(data):
    """Return the MD5 hex digest for str or bytes input.

    NOT cryptographic: MD5 is broken and must not be used for security.
    It is provided for checksums and compatibility with legacy systems only.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.md5(data).hexdigest()


def deterministic_hash(*parts, length=12):
    """Combine arbitrary parts into a stable hex digest truncated to length.

    Each part is rendered with repr so floats (0.1 vs 0.10000000000000001) and
    mixed types hash deterministically regardless of platform float formatting.
    """
    rendered = "|".join(repr(part) for part in parts)
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()[:length]


def stable_json_hash(obj):
    """Return a SHA-256 hex digest of a JSON-serializable object.

    Keys are sorted during serialization so semantically equal dicts with
    different key order produce the same digest.
    """
    payload = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def fnv1a(value):
    """Return the 32-bit FNV-1a hash of value as an int.

    Non-str/bytes inputs are rendered with repr for deterministic results.
    """
    if isinstance(value, str):
        data = value.encode("utf-8")
    elif isinstance(value, bytes):
        data = value
    else:
        data = repr(value).encode("utf-8")
    h = 0x811C9DC5
    for byte in data:
        h ^= byte
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def hash_range(value, buckets):
    """Map a value to a stable bucket index in [0, buckets) for sharding."""
    if buckets <= 0:
        raise ValueError(f"buckets must be positive, got {buckets}")
    return fnv1a(value) % buckets
