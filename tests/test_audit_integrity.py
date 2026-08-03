"""Dedicated unit tests for src/audit/integrity.py.

The SHA256 hash-chaining helpers protect audit records from undetected
tampering.  These tests pin deterministic hashing, dataclass payload
serialization and the full chain-verification state machine.
"""

import pytest

from src.audit.audit_event import AuditEvent
from src.audit.integrity import compute_hash, verify_chain


def make_event(event_id: str, event_type: str = "login") -> AuditEvent:
    return AuditEvent(
        event_id=event_id,
        timestamp="2025-01-01T00:00:00Z",
        event_type=event_type,
        severity="info",
        source="api",
        correlation_id="corr-1",
    )


def test_compute_hash_is_deterministic():
    assert compute_hash("", {"a": 1}) == compute_hash("", {"a": 1})


def test_compute_hash_differs_across_events():
    assert compute_hash("", {"a": 1}) != compute_hash("", {"a": 2})


def test_compute_hash_chains_records():
    h1 = compute_hash("", {"a": 1})
    h2 = compute_hash(h1, {"a": 2})
    assert h2 != h1
    assert h2 == compute_hash(h1, {"a": 2})


def test_compute_hash_handles_dataclass_payload():
    event = make_event("e1")
    assert compute_hash("", event) == compute_hash("", event)


def test_verify_chain_valid_chain():
    ev1, ev2 = make_event("e1"), make_event("e2")
    r1 = {"event": ev1, "previous_hash": "", "current_hash": compute_hash("", ev1)}
    r2 = {"event": ev2, "previous_hash": r1["current_hash"], "current_hash": compute_hash(r1["current_hash"], ev2)}
    assert verify_chain([r1, r2]) is True
    assert verify_chain([r1]) is True


def test_verify_chain_detects_tampered_event():
    ev1 = make_event("e1")
    tampered = make_event("e1", event_type="blocked")
    r1 = {"event": tampered, "previous_hash": "", "current_hash": compute_hash("", ev1)}
    assert verify_chain([r1]) is False


def test_verify_chain_detects_broken_previous_hash():
    ev1, ev2 = make_event("e1"), make_event("e2")
    r1 = {"event": ev1, "previous_hash": "", "current_hash": compute_hash("", ev1)}
    r2 = {"event": ev2, "previous_hash": "tampered", "current_hash": compute_hash(r1["current_hash"], ev2)}
    assert verify_chain([r1, r2]) is False
