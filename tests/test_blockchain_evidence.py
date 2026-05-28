"""Tests for durable blockchain evidence recovery."""

import json
import os
from pathlib import Path

from src.features import blockchain_evidence as be
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


def test_journal_refresh_seeks_from_previous_offset(tmp_path, monkeypatch):
    manager = _manager(tmp_path)
    evidence = _seal(manager)
    journal = manager._journal
    starting_pos = journal._last_file_pos

    external_record = {
        "evidence_id": "external_delta_record",
        "block_number": evidence.block_number + 1,
        "_journaled_at": "2026-01-01T00:00:00Z",
    }
    journal_path = Path(tmp_path / "evidence_journal.jsonl")
    with journal_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(external_record) + "\n")
    os.utime(journal_path, None)

    original_open = be.pathlib.Path.open
    seek_calls = []

    class SeekSpy:
        def __init__(self, wrapped):
            self._wrapped = wrapped

        def seek(self, offset, whence=0):
            seek_calls.append((offset, whence))
            return self._wrapped.seek(offset, whence)

        def __iter__(self):
            return iter(self._wrapped)

        def __getattr__(self, name):
            return getattr(self._wrapped, name)

        def __enter__(self):
            self._wrapped.__enter__()
            return self

        def __exit__(self, exc_type, exc, tb):
            return self._wrapped.__exit__(exc_type, exc, tb)

    def traced_open(self, mode="r", *args, **kwargs):
        handle = original_open(self, mode, *args, **kwargs)
        if self == journal_path and "r" in mode:
            return SeekSpy(handle)
        return handle

    monkeypatch.setattr(be.pathlib.Path, "open", traced_open, raising=False)
    journal._cache_mtime_ns = 0

    journal._ensure_index_loaded()

    assert seek_calls == [(starting_pos, 0)]
    assert journal.load_evidence("external_delta_record")["block_number"] == evidence.block_number + 1
    assert journal.count() == 2
