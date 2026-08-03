"""Dedicated unit tests for src/audit/audit_store.py.

``AuditStore`` is a rolling, tamper-evident in-memory audit buffer.  These
tests pin the hash-chain linkage, correlation/type lookups, rolling-buffer
eviction and chain integrity.
"""

import pytest

from src.audit.audit_store import AuditStore
from src.audit.audit_event import AuditEvent
from src.audit.integrity import verify_chain


def make_event(event_id: str, event_type: str, correlation_id: str = "corr-1") -> AuditEvent:
    return AuditEvent(
        event_id=event_id,
        timestamp="2025-01-01T00:00:00Z",
        event_type=event_type,
        severity="info",
        source="api",
        correlation_id=correlation_id,
    )


def test_append_chains_hashes():
    store = AuditStore()
    first = store.append(make_event("e1", "login"))
    second = store.append(make_event("e2", "logout"))
    assert first["previous_hash"] == ""
    assert second["previous_hash"] == first["current_hash"]
    assert first["current_hash"] != second["current_hash"]


def test_get_events_returns_in_order():
    store = AuditStore()
    store.append(make_event("e1", "login"))
    store.append(make_event("e2", "logout"))
    assert [r["event"].event_id for r in store.get_events()] == ["e1", "e2"]


def test_get_by_correlation_id_filters():
    store = AuditStore()
    store.append(make_event("e1", "login", "corr-1"))
    store.append(make_event("e2", "login", "corr-2"))
    assert [r["event"].event_id for r in store.get_by_correlation_id("corr-1")] == ["e1"]


def test_get_by_event_type_filters():
    store = AuditStore()
    store.append(make_event("e1", "login"))
    store.append(make_event("e2", "block"))
    assert [r["event"].event_id for r in store.get_by_event_type("block")] == ["e2"]


def test_rolling_buffer_evicts_oldest():
    store = AuditStore(max_size=2)
    store.append(make_event("e1", "login"))
    store.append(make_event("e2", "login"))
    store.append(make_event("e3", "login"))
    events = store.get_events()
    assert [r["event"].event_id for r in events] == ["e2", "e3"]


def test_chain_remains_verifiable():
    store = AuditStore(max_size=5)
    for i in range(5):
        store.append(make_event(f"e{i}", "login"))
    assert verify_chain(store.get_events()) is True
