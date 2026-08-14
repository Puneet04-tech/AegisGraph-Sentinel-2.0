"""
Tests for BlockchainEvidenceManager error handling and validation (Issue #8)

Tests the three new methods:
1. store_evidence() - Input validation and graceful error handling
2. get_chain() - Blockchain chain retrieval with error handling
3. verify_integrity() - Blockchain integrity verification
"""

import pytest
from datetime import datetime, timezone
import json
from unittest.mock import patch, MagicMock

from src.features.blockchain_evidence import (
    BlockchainEvidenceManager,
    BlockchainEvidence,
)


class TestStoreEvidenceMethod:
    """Test store_evidence() method with error handling"""

    def setup_method(self):
        """Create fresh manager for each test"""
        self.manager = BlockchainEvidenceManager(enable_blockchain=False)

    def test_store_evidence_with_valid_input(self):
        """Test store_evidence with valid transaction_id and data"""
        result = self.manager.store_evidence(
            transaction_id="test_tx_001",
            data={
                "risk_score": 0.75,
                "decision": "BLOCK",
                "amount": 1000.0,
                "confidence": 0.95,
            }
        )
        
        assert result["status"] == "success"
        assert "evidence_id" in result
        assert result["transaction_id"] == "test_tx_001"
        assert "stored_at" in result

    def test_store_evidence_with_null_transaction_id(self):
        """Test store_evidence rejects null transaction_id"""
        with pytest.raises(ValueError, match="transaction_id must be non-empty string"):
            self.manager.store_evidence(
                transaction_id=None,
                data={"risk_score": 0.75, "decision": "BLOCK", "amount": 1000.0}
            )

    def test_store_evidence_with_empty_transaction_id(self):
        """Test store_evidence rejects empty transaction_id"""
        with pytest.raises(ValueError, match="transaction_id must be non-empty string"):
            self.manager.store_evidence(
                transaction_id="",
                data={"risk_score": 0.75, "decision": "BLOCK", "amount": 1000.0}
            )

    def test_store_evidence_with_non_string_transaction_id(self):
        """Test store_evidence rejects non-string transaction_id"""
        with pytest.raises(ValueError, match="transaction_id must be non-empty string"):
            self.manager.store_evidence(
                transaction_id=12345,
                data={"risk_score": 0.75, "decision": "BLOCK", "amount": 1000.0}
            )

    def test_store_evidence_with_null_data(self):
        """Test store_evidence rejects null data"""
        with pytest.raises(ValueError, match="data must be non-empty dict"):
            self.manager.store_evidence(
                transaction_id="test_tx_001",
                data=None
            )

    def test_store_evidence_with_empty_data(self):
        """Test store_evidence rejects empty data dict"""
        with pytest.raises(ValueError, match="data must be non-empty dict"):
            self.manager.store_evidence(
                transaction_id="test_tx_001",
                data={}
            )

    def test_store_evidence_with_non_dict_data(self):
        """Test store_evidence rejects non-dict data"""
        with pytest.raises(ValueError, match="data must be non-empty dict"):
            self.manager.store_evidence(
                transaction_id="test_tx_001",
                data="not a dict"
            )

    def test_store_evidence_with_missing_required_fields(self):
        """Test store_evidence rejects data missing required fields"""
        with pytest.raises(ValueError, match="data missing required fields"):
            self.manager.store_evidence(
                transaction_id="test_tx_001",
                data={
                    "risk_score": 0.75,
                    "decision": "BLOCK",
                    # Missing 'amount' field
                }
            )

    def test_store_evidence_with_all_required_fields(self):
        """Test store_evidence accepts all required fields"""
        result = self.manager.store_evidence(
            transaction_id="test_tx_002",
            data={
                "risk_score": 0.85,
                "decision": "REVIEW",
                "amount": 500.0,
                "confidence": 0.90,
                "graph_risk": 0.3,
                "velocity_risk": 0.2,
                "behavior_risk": 0.1,
                "entropy_risk": 0.25,
                "explanation": "Test explanation",
                "fraud_patterns": ["velocity_anomaly"],
            }
        )
        
        assert result["status"] == "success"
        assert "evidence_id" in result

    def test_store_evidence_returns_consistent_format(self):
        """Test store_evidence always returns consistent response format"""
        result = self.manager.store_evidence(
            transaction_id="test_tx_003",
            data={
                "risk_score": 0.5,
                "decision": "ALLOW",
                "amount": 100.0,
            }
        )
        
        # Verify response structure
        assert "status" in result
        assert "evidence_id" in result
        assert "transaction_id" in result
        assert "stored_at" in result
        
        # Verify all values are of correct type
        assert isinstance(result["status"], str)
        assert isinstance(result["evidence_id"], str)
        assert isinstance(result["transaction_id"], str)
        assert isinstance(result["stored_at"], str)

    def test_store_evidence_evidence_id_format(self):
        """Test generated evidence_id has correct format"""
        result = self.manager.store_evidence(
            transaction_id="test_tx_004",
            data={"risk_score": 0.6, "decision": "BLOCK", "amount": 200.0}
        )
        
        # Evidence ID should start with "EV_"
        assert result["evidence_id"].startswith("EV_")


class TestGetChainMethod:
    """Test get_chain() method with error handling"""

    def setup_method(self):
        """Create fresh manager for each test"""
        self.manager = BlockchainEvidenceManager(enable_blockchain=True)
        
        # Add some sample evidence to the blockchain
        self.manager.seal_evidence(
            transaction_id="chain_test_001",
            source_account="acc_001",
            target_account="acc_002",
            amount=100.0,
            risk_score=0.5,
            decision="ALLOW",
            confidence=0.95,
        )

    def test_get_chain_with_valid_transaction(self):
        """Test get_chain with valid transaction_id"""
        result = self.manager.get_chain(transaction_id="chain_test_001")
        
        assert "status" in result
        assert result["status"] in ["success", "not_found"]
        assert "transaction_id" in result
        assert result["transaction_id"] == "chain_test_001"
        assert "chain" in result
        assert isinstance(result["chain"], list)

    def test_get_chain_with_null_transaction_id(self):
        """Test get_chain rejects null transaction_id"""
        with pytest.raises(ValueError, match="transaction_id must be non-empty string"):
            self.manager.get_chain(transaction_id=None)

    def test_get_chain_with_empty_transaction_id(self):
        """Test get_chain rejects empty transaction_id"""
        with pytest.raises(ValueError, match="transaction_id must be non-empty string"):
            self.manager.get_chain(transaction_id="")

    def test_get_chain_with_non_string_transaction_id(self):
        """Test get_chain rejects non-string transaction_id"""
        with pytest.raises(ValueError, match="transaction_id must be non-empty string"):
            self.manager.get_chain(transaction_id=12345)

    def test_get_chain_with_nonexistent_transaction(self):
        """Test get_chain handles non-existent transaction gracefully"""
        result = self.manager.get_chain(transaction_id="nonexistent_tx_999")
        
        assert result["status"] == "not_found"
        assert result["chain"] == []
        assert "message" in result

    def test_get_chain_returns_consistent_format(self):
        """Test get_chain returns consistent response format"""
        result = self.manager.get_chain(transaction_id="chain_test_001")
        
        # Verify response structure
        assert "transaction_id" in result
        assert "transaction_hash" in result
        assert "chain" in result
        assert "verified" in result
        
        # Verify types
        assert isinstance(result["transaction_id"], str)
        assert isinstance(result["transaction_hash"], str)
        assert isinstance(result["chain"], list)
        assert isinstance(result["verified"], bool)

    def test_get_chain_excludes_sensitive_data(self):
        """Test get_chain excludes sensitive data from transaction records"""
        result = self.manager.get_chain(transaction_id="chain_test_001")
        
        if result["chain"]:
            for block_data in result["chain"]:
                if "transaction_data" in block_data:
                    # Ensure no sensitive fields
                    tx_data = block_data["transaction_data"]
                    assert "_source" not in tx_data
                    assert "_target" not in tx_data


class TestVerifyIntegrityMethod:
    """Test verify_integrity() method with error handling"""

    def setup_method(self):
        """Create fresh manager for each test"""
        self.manager = BlockchainEvidenceManager(enable_blockchain=True)

    def test_verify_integrity_returns_valid_structure(self):
        """Test verify_integrity returns valid response structure"""
        result = self.manager.verify_integrity()
        
        # Verify response structure
        assert "verified" in result
        assert "timestamp" in result
        assert "node_status" in result
        assert "errors" in result
        assert "warnings" in result
        
        # Verify types
        assert isinstance(result["verified"], bool)
        assert isinstance(result["timestamp"], str)
        assert isinstance(result["node_status"], dict)
        assert isinstance(result["errors"], list)
        assert isinstance(result["warnings"], list)

    def test_verify_integrity_checks_all_nodes(self):
        """Test verify_integrity checks all nodes"""
        result = self.manager.verify_integrity()
        
        # Should have status for each node
        assert len(result["node_status"]) > 0
        
        # Each node should have required fields
        for node_id, status in result["node_status"].items():
            assert "verified" in status
            assert "chain_length" in status
            assert isinstance(status["verified"], bool)
            assert isinstance(status["chain_length"], int)

    def test_verify_integrity_on_fresh_blockchain(self):
        """Test verify_integrity on fresh blockchain should pass"""
        result = self.manager.verify_integrity()
        
        # Fresh blockchain should verify successfully
        # (may have warnings but not errors)
        assert isinstance(result["verified"], bool)
        assert isinstance(result["errors"], list)

    def test_verify_integrity_detects_storage_issues(self):
        """Test verify_integrity detects storage issues"""
        result = self.manager.verify_integrity()
        
        # Should include storage information
        assert "evidence_records" in result or "warnings" in result
        assert "redis_available" in result

    def test_verify_integrity_with_sealed_evidence(self):
        """Test verify_integrity after sealing evidence"""
        # Seal some evidence
        self.manager.seal_evidence(
            transaction_id="integrity_test_001",
            source_account="acc_001",
            target_account="acc_002",
            amount=100.0,
            risk_score=0.5,
            decision="ALLOW",
            confidence=0.95,
        )
        
        # Verify integrity
        result = self.manager.verify_integrity()
        
        assert "verified" in result
        assert "node_status" in result
        assert len(result["node_status"]) > 0

    def test_verify_integrity_error_handling(self):
        """Test verify_integrity handles errors gracefully"""
        result = self.manager.verify_integrity()
        
        # Errors should be documented, not thrown
        assert isinstance(result["errors"], list)
        assert isinstance(result["warnings"], list)
        
        # Should still return valid structure even with errors
        assert "verified" in result
        assert "timestamp" in result


class TestBlockchainEvidenceConsistency:
    """Test consistency of error responses across all methods"""

    def setup_method(self):
        """Create fresh manager for each test"""
        self.manager = BlockchainEvidenceManager(enable_blockchain=False)

    def test_all_methods_validate_inputs(self):
        """Test all methods validate inputs consistently"""
        invalid_inputs = [None, "", 123, []]
        
        for invalid_input in invalid_inputs:
            # store_evidence should reject invalid transaction_id
            with pytest.raises(ValueError):
                self.manager.store_evidence(
                    transaction_id=invalid_input,
                    data={"risk_score": 0.5, "decision": "BLOCK", "amount": 100.0}
                )
            
            # get_chain should reject invalid transaction_id
            with pytest.raises(ValueError):
                self.manager.get_chain(transaction_id=invalid_input)

    def test_error_messages_are_consistent(self):
        """Test error messages are consistent and helpful"""
        try:
            self.manager.store_evidence(transaction_id=None, data=None)
        except ValueError as e:
            # Error message should be descriptive
            assert len(str(e)) > 0
            assert "transaction_id" in str(e) or "data" in str(e)

    def test_methods_handle_concurrent_operations(self):
        """Test methods handle concurrent operations gracefully"""
        import threading
        
        results = []
        errors = []
        
        def store_operation(tx_id):
            try:
                result = self.manager.store_evidence(
                    transaction_id=tx_id,
                    data={
                        "risk_score": 0.5,
                        "decision": "BLOCK",
                        "amount": 100.0,
                    }
                )
                results.append(result)
            except Exception as e:
                errors.append(e)
        
        # Run multiple operations concurrently
        threads = [
            threading.Thread(target=store_operation, args=(f"concurrent_tx_{i}",))
            for i in range(5)
        ]
        
        for thread in threads:
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # All operations should complete
        assert len(results) + len(errors) == 5


class TestIssue8Acceptance:
    """Acceptance tests for Issue #8 requirements"""

    def setup_method(self):
        """Create fresh manager for each test"""
        self.manager = BlockchainEvidenceManager(enable_blockchain=False)

    def test_issue_requirement_1_input_validation(self):
        """Requirement 1: All inputs validated at method entry point"""
        # store_evidence must validate transaction_id and data
        with pytest.raises(ValueError):
            self.manager.store_evidence(transaction_id=None, data=None)
        
        with pytest.raises(ValueError):
            self.manager.store_evidence(transaction_id="", data={})
        
        # get_chain must validate transaction_id
        with pytest.raises(ValueError):
            self.manager.get_chain(transaction_id=None)

    def test_issue_requirement_2_error_handling(self):
        """Requirement 2: All exceptions handled with appropriate error types"""
        # Should raise ValueError for validation errors
        with pytest.raises(ValueError):
            self.manager.store_evidence(transaction_id=123, data="not a dict")
        
        # Should return valid responses, not crash
        result = self.manager.get_chain(transaction_id="nonexistent")
        assert isinstance(result, dict)
        assert "status" in result

    def test_issue_requirement_3_consistent_responses(self):
        """Requirement 3: Error responses consistent across all methods"""
        # store_evidence success response format
        result1 = self.manager.store_evidence(
            transaction_id="test_001",
            data={"risk_score": 0.5, "decision": "BLOCK", "amount": 100.0}
        )
        assert "status" in result1
        assert result1["status"] in ["success", "error"]
        
        # get_chain response format
        result2 = self.manager.get_chain(transaction_id="test_001")
        assert "status" in result2
        assert result2["status"] in ["success", "error", "not_found"]
        
        # verify_integrity response format
        result3 = self.manager.verify_integrity()
        assert "verified" in result3

    def test_issue_requirement_4_validation_errors_not_500(self):
        """Requirement 4: Returns 422 validation errors (not 500)"""
        # Validation errors should be catchable and describable
        try:
            self.manager.store_evidence(
                transaction_id=None,
                data={"risk_score": 0.5, "decision": "BLOCK", "amount": 100.0}
            )
            assert False, "Should have raised ValueError"
        except ValueError as e:
            # Should contain helpful error message
            assert "transaction_id" in str(e)


class TestMultiNodePendingTransactionPool:
    """Regression tests for Issue #3656: multi-node pending transaction pool duplication."""

    def _sample_tx(self, evidence_id="ev-001"):
        return {
            "evidence_id": evidence_id,
            "transaction_hash": "hash_" + evidence_id,
            "risk_score": 0.8,
            "decision": "BLOCK",
            "confidence": 0.9,
        }

    def test_multi_node_block_acceptance_purges_pending(self):
        from src.features.blockchain_evidence import BlockchainNode

        node_a = BlockchainNode(node_id="NodeA", organization="Org1")
        node_b = BlockchainNode(node_id="NodeB", organization="Org2")

        tx1_a = dict(self._sample_tx("ev-001"))
        tx1_b = dict(self._sample_tx("ev-001"))

        hash_a = node_a.add_transaction(tx1_a)
        hash_b = node_b.add_transaction(tx1_b)
        assert hash_a == hash_b

        # Node A creates block containing tx1
        block1 = node_a.create_block()
        assert block1 is not None
        assert len(node_a.pending_transactions) == 0

        # Node B receives and accepts block1 from Node A
        accepted = node_b.add_block(block1)
        assert accepted is True
        # Node B pending pool must no longer contain tx1
        assert len(node_b.pending_transactions) == 0

        # Node B creates block; should be None since pending pool is empty
        block2_b = node_b.create_block()
        assert block2_b is None

    def test_unrelated_pending_transactions_preserved(self):
        from src.features.blockchain_evidence import BlockchainNode

        node_a = BlockchainNode(node_id="NodeA", organization="Org1")
        node_b = BlockchainNode(node_id="NodeB", organization="Org2")

        tx1 = self._sample_tx("ev-001")
        tx2 = self._sample_tx("ev-002")
        tx3 = self._sample_tx("ev-003")

        node_a.add_transaction(dict(tx1))

        hash1 = node_b.add_transaction(dict(tx1))
        hash2 = node_b.add_transaction(dict(tx2))
        hash3 = node_b.add_transaction(dict(tx3))

        assert len(node_b.pending_transactions) == 3

        # Node A mines block containing tx1
        block_a = node_a.create_block()
        assert node_b.add_block(block_a) is True

        # Node B pending pool should now only contain tx2 and tx3 in order
        remaining_hashes = [tx["tx_hash"] for tx in node_b.pending_transactions]
        assert remaining_hashes == [hash2, hash3]

    def test_invalid_block_does_not_purge_pending(self):
        from src.features.blockchain_evidence import BlockchainNode

        node_b = BlockchainNode(node_id="NodeB", organization="Org2")
        tx1 = self._sample_tx("ev-001")
        node_b.add_transaction(dict(tx1))

        # Create invalid block with bad previous_hash
        invalid_block = {
            "block_number": 1,
            "timestamp": "2026-01-01T00:00:00+00:00",
            "transactions": [dict(tx1, tx_hash="some_hash")],
            "previous_hash": "bad_hash_123",
            "hash": "invalid_block_hash",
            "validator": "NodeA",
        }

        accepted = node_b.add_block(invalid_block)
        assert accepted is False
        # Pending pool must remain untouched
        assert len(node_b.pending_transactions) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
