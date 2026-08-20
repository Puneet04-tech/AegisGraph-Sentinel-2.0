"""Tamper-evident SHA256 hash chaining for audit records."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, is_dataclass
from typing import Any, Iterable, Mapping, Optional


def _payload(event_payload: Any) -> str:
    """Serialize an event payload to a deterministic JSON string for hashing."""
    if is_dataclass(event_payload):
        event_payload = asdict(event_payload)
    return json.dumps(event_payload, sort_keys=True, separators=(",", ":"), default=str)


def compute_hash(previous_hash: str, event_payload: Any) -> str:
    """Compute the SHA256 hash for an audit event in the tamper-evident chain.

    Args:
        previous_hash: The hash of the preceding record, or empty string for the first record.
        event_payload: The event data to include in the hash computation.

    Returns:
        A lowercase hex-encoded SHA256 hash of the concatenation of previous_hash and
        the JSON-serialized event payload.
    """
    return hashlib.sha256((previous_hash + _payload(event_payload)).encode("utf-8")).hexdigest()


def verify_chain(
    records: Iterable[Mapping[str, Any]],
    initial_hash_anchor: Optional[str] = None,
) -> bool:
    """Verify the tamper-evident hash chain of audit records.

    Args:
        records: An iterable of audit record mappings, each containing 'event',
            'previous_hash', and 'current_hash' keys.
        initial_hash_anchor: Optional hash anchor of evicted/preceding records.

    Returns:
        True if the chain is intact (every record's hash matches the computed hash
        and previous_hash values form a continuous chain); False if any record
        has been tampered with or the chain is broken.
    """
    previous_hash = initial_hash_anchor
    for record in records:
        event = record["event"]
        record_previous = record.get("previous_hash")
        if previous_hash is not None and record_previous != previous_hash:
            return False
        current_hash = compute_hash(record_previous or "", event)
        if record.get("current_hash") != current_hash:
            return False
        previous_hash = current_hash
    return True
