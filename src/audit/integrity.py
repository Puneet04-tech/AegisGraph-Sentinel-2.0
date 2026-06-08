"""Tamper-evident SHA256 hash chaining for audit records."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, is_dataclass
from typing import Any, Iterable, Mapping


def _payload(event_payload: Any) -> str:
    if is_dataclass(event_payload):
        event_payload = asdict(event_payload)
    return json.dumps(event_payload, sort_keys=True, separators=(",", ":"), default=str)


def compute_hash(previous_hash: str, event_payload: Any) -> str:
    return hashlib.sha256((previous_hash + _payload(event_payload)).encode("utf-8")).hexdigest()


def verify_chain(records: Iterable[Mapping[str, Any]]) -> bool:
    previous_hash = None
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
