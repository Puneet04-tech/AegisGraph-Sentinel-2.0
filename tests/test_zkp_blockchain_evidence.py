"""
Unit tests for Zero-Knowledge Proof (ZKP) SNARK-Based Fraud Attestation (Issue #3453).
"""

import pytest
from src.quantum_security.zkp_verifier import ZKPCircuit, ZKPVerifier
from src.features.blockchain_evidence import BlockchainEvidenceManager


def test_zkp_circuit_threshold_evaluation():
    circuit = ZKPCircuit(threshold=0.75)
    witness_pass = circuit.evaluate_witness(risk_score=0.85)
    assert witness_pass["satisfied"] is True
    assert "commitment_hash" in witness_pass

    witness_fail = circuit.evaluate_witness(risk_score=0.60)
    assert witness_fail["satisfied"] is False


def test_zkp_proof_generation_and_verification():
    verifier = ZKPVerifier(secret_key="test-secret-key-zkp")
    proof = verifier.generate_proof(risk_score=0.92, threshold=0.70, transaction_id="TXN-ZKP-101")

    assert proof["proof_type"] == "zk-SNARK-Attestation-v1"
    assert proof["is_above_threshold"] is True

    # Verify proof
    is_valid = verifier.verify_proof(proof)
    assert is_valid is True

    # Tamper with challenge
    tampered_proof = dict(proof)
    tampered_proof["challenge"] = "tampered_challenge_hash"
    assert verifier.verify_proof(tampered_proof) is False


def test_zkp_proof_rejects_tampered_response():
    verifier = ZKPVerifier(secret_key="test-secret-key-zkp")
    proof = verifier.generate_proof(risk_score=0.92, threshold=0.70, transaction_id="TXN-RESP-1")

    # Every field except the response is intact; the forged response must be
    # rejected instead of silently accepted.
    tampered_proof = dict(proof)
    tampered_proof["response"] = "0" * 64
    assert verifier.verify_proof(tampered_proof) is False

    truncated_proof = dict(proof)
    truncated_proof["response"] = proof["response"][:16]
    assert verifier.verify_proof(truncated_proof) is False


def test_zkp_proof_rejects_missing_response_and_salt():
    verifier = ZKPVerifier(secret_key="test-secret-key-zkp")
    proof = verifier.generate_proof(risk_score=0.92, threshold=0.70, transaction_id="TXN-RESP-2")

    missing_response = dict(proof)
    missing_response.pop("response")
    assert verifier.verify_proof(missing_response) is False

    missing_salt = dict(proof)
    missing_salt.pop("salt")
    assert verifier.verify_proof(missing_salt) is False


def test_blockchain_evidence_sealing_with_zkp():
    manager = BlockchainEvidenceManager(enable_blockchain=True)
    evidence = manager.seal_evidence(
        transaction_id="TXN-SEAL-ZKP-200",
        source_account="ACC-001",
        target_account="ACC-999",
        amount=150000.0,
        risk_score=0.95,
        decision="BLOCK",
        confidence=0.98,
        explanation="High-risk mule chain detected",
    )

    assert evidence is not None
    assert evidence.zkp_proof is not None
    assert evidence.zkp_proof["is_above_threshold"] is True
