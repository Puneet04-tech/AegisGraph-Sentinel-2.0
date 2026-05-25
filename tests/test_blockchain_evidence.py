"""Tests for durable blockchain evidence recovery."""

from src.features.blockchain_evidence import BlockchainEvidenceManager


def _manager(tmp_path):
    return BlockchainEvidenceManager(
        journal_path=str(tmp_path / "evidence_journal.jsonl"),
        redis_url="redis://127.0.0.1:6399/0",
    )


def _seal(manager: BlockchainEvidenceManager):
    return manager.seal_evidence(
        transaction_id="txn_123",
        source_account="acct_src",
        target_account="acct_dst",
        amount=2500.0,
        risk_result={
            "risk_score": 0.93,
            "decision": "BLOCK",
            "confidence": 0.97,
            "breakdown": {
                "graph": 0.88,
                "velocity": 0.73,
                "behavior": 0.41,
                "entropy": 0.62,
            },
        },
        explanation="Synthetic fraud scenario for durable evidence testing.",
    )


def test_verify_evidence_recovers_from_journal_after_restart(tmp_path):
    first_manager = _manager(tmp_path)
    evidence = _seal(first_manager)

    restarted_manager = _manager(tmp_path)
    result = restarted_manager.verify_evidence(evidence.evidence_id, evidence.block_number)

    assert result["verified"] is True
    assert result["block_exists"] is True
    assert result["chain_integrity"] is True
    assert result["details"]["storage_backend"] == "journal"


def test_export_legal_proceedings_uses_durable_record_after_restart(tmp_path):
    first_manager = _manager(tmp_path)
    evidence = _seal(first_manager)

    restarted_manager = _manager(tmp_path)
    export = restarted_manager.export_for_legal_proceedings(
        evidence_id=evidence.evidence_id,
        case_number="CASE-149",
        requesting_authority="CBI",
        authorization_token="token-149",
    )

    assert export["authorized_by"] == "CBI"
    assert export["package"]["evidence"]["evidence_id"] == evidence.evidence_id
    assert export["package"]["chain_verification"]["verified"] is True
    assert export["chain_of_custody"][-1]["event"] == "legal_export_generated"
