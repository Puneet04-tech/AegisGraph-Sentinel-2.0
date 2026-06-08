"""Focused tests for the in-memory audit framework."""

from __future__ import annotations

import asyncio
import uuid

from src.audit import (
    AuditEvent,
    AuditLogger,
    AuditStore,
    generate_correlation_id,
    verify_chain,
)
from src.runtime import LifecycleManager, RuntimeState
from src.runtime import lifecycle_manager as lifecycle_module


def test_audit_event_creation():
    event = AuditEvent(
        event_id="evt-1",
        timestamp="2026-06-07T00:00:00Z",
        event_type="runtime_startup_started",
        severity="info",
        source="test",
        correlation_id="corr-1",
        metadata={"ok": True},
    )

    assert event.event_id == "evt-1"
    assert event.event_type == "runtime_startup_started"
    assert event.metadata == {"ok": True}


def test_correlation_id_generation():
    correlation_id = generate_correlation_id()

    assert str(uuid.UUID(correlation_id)) == correlation_id


def test_audit_store_retention():
    store = AuditStore(max_size=2)
    logger = AuditLogger(store)

    logger.log_audit_event("first")
    logger.log_audit_event("second")
    logger.log_audit_event("third")

    events = store.get_events()
    assert [record["event"].event_type for record in events] == ["second", "third"]
    assert verify_chain(events) is True


def test_lookup_by_event_type():
    store = AuditStore()
    logger = AuditLogger(store)

    logger.log_audit_event("runtime_startup_complete")
    logger.log_audit_event("runtime_shutdown_complete")
    logger.log_audit_event("runtime_startup_complete")

    matches = store.get_by_event_type("runtime_startup_complete")
    assert len(matches) == 2


def test_lookup_by_correlation_id():
    store = AuditStore()
    logger = AuditLogger(store)

    logger.log_audit_event("a", correlation_id="corr-1")
    logger.log_audit_event("b", correlation_id="corr-2")
    logger.log_audit_event("c", correlation_id="corr-1")

    matches = store.get_by_correlation_id("corr-1")
    assert [record["event"].event_type for record in matches] == ["a", "c"]


def test_hash_chain_generation_and_verification():
    store = AuditStore()
    logger = AuditLogger(store)

    first = logger.log_audit_event("first")
    second = logger.log_audit_event("second")

    assert first["previous_hash"] == ""
    assert second["previous_hash"] == first["current_hash"]
    assert verify_chain(store.get_events()) is True


def test_chain_verification_detects_tampering():
    store = AuditStore()
    logger = AuditLogger(store)

    logger.log_audit_event("first", metadata={"value": 1})
    logger.log_audit_event("second")
    store.get_events()[0]["event"].metadata["value"] = 2

    assert verify_chain(store.get_events()) is False


def test_runtime_audit_event_creation(monkeypatch):
    store = AuditStore()
    logger = AuditLogger(store)
    monkeypatch.setattr(lifecycle_module, "log_audit_event", logger.log_audit_event)

    async def _run():
        lifecycle = LifecycleManager(RuntimeState())
        lifecycle.register_startup("step", lambda: None)
        lifecycle.register_shutdown("step", lambda: None)

        await lifecycle.startup()
        await lifecycle.shutdown()

    asyncio.run(_run())

    event_types = [record["event"].event_type for record in store.get_events()]
    assert "runtime_startup_started" in event_types
    assert "runtime_startup_complete" in event_types
    assert "runtime_shutdown_started" in event_types
    assert "runtime_shutdown_complete" in event_types
    assert verify_chain(store.get_events()) is True
