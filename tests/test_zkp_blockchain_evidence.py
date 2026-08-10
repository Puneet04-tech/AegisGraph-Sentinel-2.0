"""
Unit tests for Zero-Knowledge Proof (ZKP) SNARK-Based Fraud Attestation (Issue #3453, #3504).
"""

import pytest
from src.quantum_security.zkp_verifier import ZKPCircuit, ZKPVerifier, get_zkp_verifier
from src.features.blockchain_evidence import BlockchainEvidenceManager

ZKP_SECRET = "test-shared-zkp-secret"


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


def test_blockchain_evidence_sealing_with_zkp(monkeypatch):
    monkeypatch.setenv("ZKP_SECRET_KEY", ZKP_SECRET)
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


def test_zkp_proof_round_trip_via_shared_verifier(monkeypatch):
    monkeypatch.setenv("ZKP_SECRET_KEY", ZKP_SECRET)
    manager = BlockchainEvidenceManager(enable_blockchain=True)
    evidence = manager.seal_evidence(
        transaction_id="TXN-SEAL-ZKP-201",
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
    # The shared accessor must use the same key as the seal path, so the sealed
    # proof verifies successfully.
    assert get_zkp_verifier().verify_proof(evidence.zkp_proof) is True


def test_zkp_verifier_fails_fast_without_secret_key(monkeypatch):
    monkeypatch.delenv("ZKP_SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError):
        ZKPVerifier()


def test_zkp_proof_rejected_when_key_differs():
    verifier_a = ZKPVerifier(secret_key="key-a")
    proof = verifier_a.generate_proof(
        risk_score=0.92, threshold=0.70, transaction_id="TXN-KEY-1"
    )

    verifier_b = ZKPVerifier(secret_key="key-b")
    assert verifier_b.verify_proof(proof) is False
