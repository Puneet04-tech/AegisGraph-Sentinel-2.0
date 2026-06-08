"""
Tests for BlockchainNode.add_transaction() input validation.

Covers the fix introduced in Issue #796: invalid transactions were
previously accepted into the pending pool without any field or value
checks, allowing corrupt or malicious records to enter the chain.
"""

import pytest
from fastapi import HTTPException

from src.features.blockchain_evidence import BlockchainNode


VALID_TRANSACTION = {
    "evidence_id": "ev-001",
    "transaction_hash": "abc123deadbeef",
    "risk_score": 0.85,
    "decision": "BLOCK",
    "confidence": 0.92,
}


@pytest.fixture
def node():
    return BlockchainNode(node_id="test-node-1", organization="TestOrg")


class TestAddTransactionValidation:
    """Unit tests for the _validate_transaction guard in add_transaction()."""

    def test_valid_transaction_is_accepted(self, node):
        tx_hash = node.add_transaction(dict(VALID_TRANSACTION))
        assert isinstance(tx_hash, str) and len(tx_hash) == 64
        assert len(node.pending_transactions) == 1

    def test_missing_evidence_id_raises_422(self, node):
        txn = {k: v for k, v in VALID_TRANSACTION.items() if k != "evidence_id"}
        with pytest.raises(HTTPException) as exc_info:
            node.add_transaction(txn)
        assert exc_info.value.status_code == 422
        assert "evidence_id" in exc_info.value.detail

    def test_missing_transaction_hash_raises_422(self, node):
        txn = {k: v for k, v in VALID_TRANSACTION.items() if k != "transaction_hash"}
        with pytest.raises(HTTPException) as exc_info:
            node.add_transaction(txn)
        assert exc_info.value.status_code == 422
        assert "transaction_hash" in exc_info.value.detail

    def test_missing_risk_score_raises_422(self, node):
        txn = {k: v for k, v in VALID_TRANSACTION.items() if k != "risk_score"}
        with pytest.raises(HTTPException) as exc_info:
            node.add_transaction(txn)
        assert exc_info.value.status_code == 422

    def test_missing_decision_raises_422(self, node):
        txn = {k: v for k, v in VALID_TRANSACTION.items() if k != "decision"}
        with pytest.raises(HTTPException) as exc_info:
            node.add_transaction(txn)
        assert exc_info.value.status_code == 422

    def test_missing_confidence_raises_422(self, node):
        txn = {k: v for k, v in VALID_TRANSACTION.items() if k != "confidence"}
        with pytest.raises(HTTPException) as exc_info:
            node.add_transaction(txn)
        assert exc_info.value.status_code == 422

    def test_risk_score_above_one_raises_422(self, node):
        txn = {**VALID_TRANSACTION, "risk_score": 1.1}
        with pytest.raises(HTTPException) as exc_info:
            node.add_transaction(txn)
        assert exc_info.value.status_code == 422
        assert "risk_score" in exc_info.value.detail

    def test_risk_score_below_zero_raises_422(self, node):
        txn = {**VALID_TRANSACTION, "risk_score": -0.1}
        with pytest.raises(HTTPException) as exc_info:
            node.add_transaction(txn)
        assert exc_info.value.status_code == 422

    def test_confidence_above_one_raises_422(self, node):
        txn = {**VALID_TRANSACTION, "confidence": 1.5}
        with pytest.raises(HTTPException) as exc_info:
            node.add_transaction(txn)
        assert exc_info.value.status_code == 422
        assert "confidence" in exc_info.value.detail

    def test_invalid_decision_value_raises_422(self, node):
        txn = {**VALID_TRANSACTION, "decision": "APPROVE"}
        with pytest.raises(HTTPException) as exc_info:
            node.add_transaction(txn)
        assert exc_info.value.status_code == 422
        assert "decision" in exc_info.value.detail

    def test_empty_evidence_id_raises_422(self, node):
        txn = {**VALID_TRANSACTION, "evidence_id": "   "}
        with pytest.raises(HTTPException) as exc_info:
            node.add_transaction(txn)
        assert exc_info.value.status_code == 422

    def test_empty_transaction_hash_raises_422(self, node):
        txn = {**VALID_TRANSACTION, "transaction_hash": ""}
        with pytest.raises(HTTPException) as exc_info:
            node.add_transaction(txn)
        assert exc_info.value.status_code == 422

    def test_allow_decision_is_accepted(self, node):
        txn = {**VALID_TRANSACTION, "decision": "ALLOW", "risk_score": 0.1}
        tx_hash = node.add_transaction(txn)
        assert isinstance(tx_hash, str)

    def test_review_decision_is_accepted(self, node):
        txn = {**VALID_TRANSACTION, "decision": "REVIEW", "risk_score": 0.65}
        tx_hash = node.add_transaction(txn)
        assert isinstance(tx_hash, str)

    def test_risk_score_boundary_zero_is_valid(self, node):
        txn = {**VALID_TRANSACTION, "risk_score": 0.0, "decision": "ALLOW"}
        tx_hash = node.add_transaction(txn)
        assert isinstance(tx_hash, str)

    def test_risk_score_boundary_one_is_valid(self, node):
        txn = {**VALID_TRANSACTION, "risk_score": 1.0, "decision": "BLOCK"}
        tx_hash = node.add_transaction(txn)
        assert isinstance(tx_hash, str)

    def test_invalid_transaction_not_added_to_pending_pool(self, node):
        txn = {**VALID_TRANSACTION, "risk_score": 99.0}
        with pytest.raises(HTTPException):
            node.add_transaction(txn)
        assert len(node.pending_transactions) == 0

    def test_multiple_valid_transactions_accepted(self, node):
        for i in range(5):
            txn = {**VALID_TRANSACTION, "evidence_id": f"ev-{i:03d}"}
            node.add_transaction(txn)
        assert len(node.pending_transactions) == 5
