"""Unit tests for the blockchain evidence ledger subsystem.

Covers ``src.blockchain_evidence``: models, ``BlockchainEvidenceStore``,
``EvidenceLedger`` (hashing, merkle roots, mining, integrity), and
``CustodyTracker`` (custody chaining, legal holds).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.blockchain_evidence.custody_tracker import CustodyTracker
from src.blockchain_evidence.evidence_ledger import EvidenceLedger
from src.blockchain_evidence.models import (
    AuditTrail,
    BlockchainBlock,
    ChainOfCustody,
    CustodyAction,
    EvidenceRecord,
    EvidenceType,
    LegalHold,
    VerificationResult,
    VerificationStatus,
)
from src.blockchain_evidence.store import BlockchainEvidenceStore


@pytest.fixture
def store() -> BlockchainEvidenceStore:
    return BlockchainEvidenceStore()


@pytest.fixture
def ledger(store) -> EvidenceLedger:
    return EvidenceLedger(store=store)


@pytest.fixture
def tracker(store) -> CustodyTracker:
    return CustodyTracker(store=store)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TestModels:
    def test_evidence_record_defaults(self):
        record = EvidenceRecord(
            case_id="case-1",
            evidence_type=EvidenceType.TRANSACTION,
            description="desc",
            hash="abc",
            collector_id="user-1",
        )

        assert record.evidence_id
        assert record.collected_at is not None
        assert record.integrity_verified is False
        assert record.previous_hash is None

    def test_blockchain_block_defaults(self):
        block = BlockchainBlock(
            block_number=0,
            previous_hash="0" * 64,
            merkle_root="abc",
        )

        assert block.nonce == 0
        assert block.hash is None
        assert block.evidence_hashes == []

    def test_legal_hold_default_status(self):
        hold = LegalHold(case_id="c", reason="r", imposed_by="u")
        assert hold.status == "ACTIVE"

    def test_enum_values(self):
        assert EvidenceType.TRANSACTION.value == "TRANSACTION"
        assert CustodyAction.TRANSFERRED.value == "TRANSFERRED"
        assert VerificationStatus.VERIFIED.value == "VERIFIED"


# ---------------------------------------------------------------------------
# BlockchainEvidenceStore
# ---------------------------------------------------------------------------


class TestStore:
    def test_evidence_crud(self, store):
        record = EvidenceRecord(
            case_id="case-1", evidence_type=EvidenceType.DOCUMENT,
            description="d", hash="h", collector_id="u",
        )
        other = EvidenceRecord(
            case_id="case-2", evidence_type=EvidenceType.LOG,
            description="d", hash="h2", collector_id="u",
        )

        store.store_evidence(record)
        store.store_evidence(other)

        assert store.get_evidence(record.evidence_id) is record
        assert store.get_evidence("missing") is None
        assert store.get_case_evidence("case-1") == [record]

    def test_custody_chain_sorted(self, store):
        a = ChainOfCustody(
            evidence_id="e1", action=CustodyAction.COLLECTED, custodian_id="u1",
            custodian_name="A", location="x", purpose="collect",
            hash="h1", timestamp=datetime.now(timezone.utc),
        )
        b = ChainOfCustody(
            evidence_id="e1", action=CustodyAction.TRANSFERRED, custodian_id="u2",
            custodian_name="B", location="y", purpose="transfer",
            hash="h2", timestamp=a.timestamp.replace(year=a.timestamp.year + 1),
        )
        store.store_custody(b)
        store.store_custody(a)

        assert store.get_custody(a.custody_id) is a
        assert store.get_evidence_custody_chain("e1") == [a, b]
        assert store.get_evidence_custody_chain("missing") == []

    def test_blocks_and_latest(self, store):
        block0 = BlockchainBlock(block_number=0, previous_hash="0" * 64, merkle_root="r0")
        block1 = BlockchainBlock(block_number=1, previous_hash="p", merkle_root="r1")

        store.store_block(block0)
        store.store_block(block1)

        assert store.get_block(0) is block0
        assert store.get_block(2) is None
        assert store.get_latest_block() is block1

    def test_latest_block_empty(self, store):
        assert store.get_latest_block() is None

    def test_blockchain_stats(self, store):
        block0 = BlockchainBlock(block_number=0, previous_hash="0" * 64, merkle_root="r0")
        store.store_block(block0)

        stats = store.get_blockchain_stats()
        assert stats["total_blocks"] == 1
        assert stats["latest_block_hash"] == block0.hash

    def test_verifications(self, store):
        v = VerificationResult(evidence_id="e1", status=VerificationStatus.VERIFIED)
        store.store_verification(v)

        assert store.get_verification(v.verification_id) is v
        assert store.get_evidence_verification("e1") is v
        assert store.get_evidence_verification("missing") is None

    def test_audit_trail_sorted(self, store):
        a = AuditTrail(evidence_id="e1", action="A", user_id="u", timestamp=datetime.now(timezone.utc))
        b = AuditTrail(evidence_id="e1", action="B", user_id="u", timestamp=a.timestamp.replace(year=a.timestamp.year + 1))
        store.store_audit_entry(b)
        store.store_audit_entry(a)

        assert store.get_evidence_audit_trail("e1") == [a, b]
        assert store.get_evidence_audit_trail("missing") == []

    def test_legal_holds(self, store):
        h1 = LegalHold(case_id="c1", evidence_ids=["e1"], reason="r", imposed_by="u")
        h2 = LegalHold(case_id="c2", evidence_ids=["e2"], reason="r", imposed_by="u", status="RELEASED")
        store.store_legal_hold(h1)
        store.store_legal_hold(h2)

        assert store.get_legal_hold(h1.hold_id) is h1
        assert store.get_active_holds() == [h1]
        assert store.get_evidence_holds("e1") == [h1]

    def test_stats(self, store):
        record = EvidenceRecord(
            case_id="c", evidence_type=EvidenceType.DOCUMENT,
            description="d", hash="h", collector_id="u",
        )
        store.store_evidence(record)

        stats = store.get_stats()
        assert stats["evidence_stored"] == 1
        assert stats["active_holds"] == 0


# ---------------------------------------------------------------------------
# EvidenceLedger
# ---------------------------------------------------------------------------


class TestEvidenceLedger:
    def test_collect_evidence_creates_block_zero(self, store, ledger):
        evidence = ledger.collect_evidence(
            case_id="case-1",
            evidence_type=EvidenceType.TRANSACTION,
            description="suspicious transfer",
            data={"amount": 5000},
            collector_id="collector-1",
        )

        assert evidence.previous_hash == "0" * 64
        assert evidence.block_number == 0
        assert evidence.transaction_hash is not None
        assert evidence.hash == ledger._compute_hash({"amount": 5000})

        block0 = store.get_block(0)
        assert block0 is not None
        assert evidence.hash in block0.evidence_hashes
        assert len(store.get_evidence_audit_trail(evidence.evidence_id)) == 1

    def test_collect_appends_to_existing_block(self, store, ledger):
        first = ledger.collect_evidence(
            case_id="c", evidence_type=EvidenceType.LOG, description="d",
            data="log1", collector_id="u",
        )
        second = ledger.collect_evidence(
            case_id="c", evidence_type=EvidenceType.LOG, description="d",
            data="log2", collector_id="u",
        )

        block0 = store.get_block(0)
        assert len(block0.evidence_hashes) == 2
        # Appended evidence inherits the previous block's hash.
        assert second.previous_hash == block0.hash
        # Appended evidence keeps the linked hash but no block number.
        assert second.block_number is None
        assert first.block_number == 0

    def test_new_block_after_ten_hashes(self, store, ledger):
        for i in range(11):
            ledger.collect_evidence(
                case_id="c", evidence_type=EvidenceType.LOG, description="d",
                data=f"log-{i}", collector_id="u",
            )

        block0 = store.get_block(0)
        block1 = store.get_block(1)
        assert len(block0.evidence_hashes) == 10
        assert block1 is not None
        assert len(block1.evidence_hashes) == 1

    def test_compute_hash_consistency(self, ledger):
        assert ledger._compute_hash("data") == ledger._compute_hash("data")
        assert ledger._compute_hash(b"data") == ledger._compute_hash("data")
        assert ledger._compute_hash("a") != ledger._compute_hash("b")

    def test_merkle_root_empty(self, ledger):
        assert ledger._compute_merkle_root([]) == "0" * 64

    def test_merkle_root_single(self, ledger):
        h = "abc"
        assert ledger._compute_merkle_root([h]) == h

    def test_merkle_root_even_and_odd(self, ledger):
        h1, h2, h3 = "a", "b", "c"
        even = ledger._compute_merkle_root([h1, h2])
        odd = ledger._compute_merkle_root([h1, h2, h3])

        assert even != odd
        assert len(even) == 64
        assert len(odd) == 64

    def test_mine_block_meets_difficulty(self, ledger):
        block = BlockchainBlock(
            block_number=0,
            previous_hash="0" * 64,
            merkle_root="root",
        )

        result = ledger._mine_block(block, difficulty=2)

        assert result.startswith("00")
        assert result == ledger._compute_hash(
            f"{block.block_number}{block.timestamp.isoformat()}{block.previous_hash}{block.merkle_root}{block.nonce}"
        )

    def test_verify_integrity_missing_evidence(self, ledger):
        result = ledger.verify_evidence_integrity("missing")
        assert result["error"] == "Evidence not found"

    def test_verify_integrity_first_block_valid(self, store, ledger):
        evidence = ledger.collect_evidence(
            case_id="c", evidence_type=EvidenceType.TRANSACTION, description="d",
            data="x", collector_id="u",
        )

        result = ledger.verify_evidence_integrity(evidence.evidence_id)
        assert result["chain_integrity"] is True

    def test_verify_chain_detects_tampering(self, store, ledger):
        evidence = ledger.collect_evidence(
            case_id="c", evidence_type=EvidenceType.TRANSACTION, description="d",
            data="x", collector_id="u",
        )
        store.get_block(0).hash = "tampered"

        assert ledger._verify_chain(evidence) is False

    def test_get_case_evidence(self, store, ledger):
        ledger.collect_evidence(
            case_id="case-a", evidence_type=EvidenceType.TRANSACTION, description="d",
            data="x", collector_id="u",
        )
        ledger.collect_evidence(
            case_id="case-a", evidence_type=EvidenceType.LOG, description="d",
            data="y", collector_id="u",
        )
        ledger.collect_evidence(
            case_id="case-b", evidence_type=EvidenceType.DOCUMENT, description="d",
            data="z", collector_id="u",
        )

        assert len(ledger.get_case_evidence("case-a")) == 2
        assert len(ledger.get_case_evidence("case-b")) == 1


# ---------------------------------------------------------------------------
# CustodyTracker
# ---------------------------------------------------------------------------


class TestCustodyTracker:
    def test_transfer_custody_chains_hashes(self, store, tracker):
        first = tracker.transfer_custody("e1", "u-a", "u-b", "Bob", "Room 1", "review")

        assert first.action == CustodyAction.TRANSFERRED
        assert first.previous_custody_hash == "0" * 64
        assert first.hash == tracker._compute_custody_hash(first)

        second = tracker.transfer_custody("e1", "u-b", "u-c", "Carol", "Vault", "transfer")

        assert second.previous_custody_hash == first.hash
        assert len(store.get_evidence_custody_chain("e1")) == 2

    def test_record_access(self, tracker):
        access = tracker.record_access("e1", "u-1", "Alice", "investigation")

        assert access.action == CustodyAction.ACCESSED
        assert access.location == "System"
        assert access.custodian_id == "u-1"

    def test_record_modification_tracks_original_hash(self, tracker):
        tracker.transfer_custody("e1", "u-a", "u-b", "Bob", "Room", "review")
        modification = tracker.record_modification("e1", "u-2", "Dave", "updated metadata")

        assert modification.action == CustodyAction.MODIFIED
        assert "original_hash" in modification.metadata

    def test_current_custodian_and_history(self, store, tracker):
        tracker.transfer_custody("e1", "u-a", "u-b", "Bob", "R1", "review")
        tracker.transfer_custody("e1", "u-b", "u-c", "Carol", "R2", "transfer")

        assert tracker.get_current_custodian("e1").custodian_id == "u-c"
        assert len(tracker.get_custodian_history("u-c")) == 1
        assert len(tracker.get_custody_chain("e1")) == 2

    def test_place_and_release_legal_hold(self, store, tracker):
        hold = tracker.place_legal_hold("case-1", ["e1", "e2"], "litigation", "attorney-1")

        assert hold.status == "ACTIVE"
        assert tracker.is_evidence_on_hold("e1") is True
        assert tracker.get_active_holds() == [hold]
        assert len(store.get_evidence_audit_trail("e1")) == 1

        tracker.release_legal_hold(hold.hold_id, "attorney-2")

        assert hold.status == "RELEASED"
        assert hold.released_at is not None
        assert tracker.is_evidence_on_hold("e1") is False

    def test_release_missing_hold_raises(self, tracker):
        with pytest.raises(ValueError):
            tracker.release_legal_hold("missing", "user")
