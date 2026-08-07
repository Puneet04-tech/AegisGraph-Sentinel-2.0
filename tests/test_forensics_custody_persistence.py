"""Custody-chain persistence tests for the forensics service.

Regression guard for issue #2865: ``ForensicsService.record_custody()`` built a
``ChainOfCustody`` record and returned it without ever writing it to the store,
so custody transfers vanished as soon as the process exited and could never be
audited afterwards.
"""

from src.forensics.models import Evidence, Investigation
from src.forensics.service import ForensicsService
from src.forensics.store import ForensicsStore


def _service():
    return ForensicsService(store=ForensicsStore())


def test_record_custody_persists_to_store():
    service = _service()

    record = service.record_custody("ev-1", "analyst.alice", "ACQUIRED")

    stored = service._store.get_custody(record.custody_id)
    assert stored is not None
    assert stored.custody_id == record.custody_id
    assert stored.evidence_id == "ev-1"
    assert stored.custodian == "analyst.alice"
    assert stored.action == "ACQUIRED"


def test_custody_trail_is_retrievable_for_evidence():
    service = _service()

    service.record_custody("ev-2", "analyst.alice", "ACQUIRED")
    service.record_custody("ev-2", "evidence.locker", "TRANSFERRED")
    service.record_custody("ev-2", "lead.investigator", "RELEASED")

    trail = service._store.get_custody_for_evidence("ev-2")

    assert [c.action for c in trail] == ["ACQUIRED", "TRANSFERRED", "RELEASED"]
    assert [c.custodian for c in trail] == [
        "analyst.alice",
        "evidence.locker",
        "lead.investigator",
    ]


def test_custody_trail_is_isolated_per_evidence():
    service = _service()

    service.record_custody("ev-a", "alice", "ACQUIRED")
    service.record_custody("ev-b", "bob", "ACQUIRED")

    assert len(service._store.get_custody_for_evidence("ev-a")) == 1
    assert service._store.get_custody_for_evidence("ev-b")[0].custodian == "bob"
    assert len(service._store.get_custody_for_evidence("ev-missing")) == 0


def test_custody_chain_ties_back_to_investigation_evidence():
    service = _service()
    inv = service.create_investigation("Case 3", "Full custody chain")
    ev = service.add_evidence(inv.investigation_id, "file", {"path": "/tmp/a"})

    service.record_custody(ev.evidence_id, "analyst.alice", "ACQUIRED")

    assert isinstance(inv, Investigation)
    assert isinstance(ev, Evidence)
    assert len(service._store.get_custody_for_evidence(ev.evidence_id)) == 1
