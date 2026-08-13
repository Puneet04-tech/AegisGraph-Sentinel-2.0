"""
Concurrent stress test suite for Async Honeypot Escrow Shadow Ledger State (Issue #3452).
"""

import asyncio
import pytest
from datetime import datetime, timedelta

from src.features.honeypot_escrow import HoneypotEscrowManager, HoneypotStatus


@pytest.mark.asyncio
async def test_concurrent_honeypot_activations():
    manager = HoneypotEscrowManager(activation_threshold=0.90)

    async def _activate_single(idx: int):
        return await manager.activate_honeypot_async(
            transaction_id=f"TXN-ASYNC-{idx}",
            source_account=f"SRC-{idx}",
            target_account=f"MULE-{idx}",
            amount=50000.0 + idx,
            currency="INR",
            risk_score=0.95,
            fraud_indicators=["mule_to_mule"],
        )

    # Simulate 500 concurrent honeypot activations
    tasks = [_activate_single(i) for i in range(500)]
    results = await asyncio.gather(*tasks)

    assert len(results) == 500
    assert len(manager.active_honeypots) == 500
    assert manager.stats["total_activated"] == 500


@pytest.mark.asyncio
async def test_async_ttl_cleanup_expired_honeypots():
    manager = HoneypotEscrowManager(activation_threshold=0.90, auto_release_hours=0.0001)

    # Activate honeypot with immediate expiration
    hp = manager.activate_honeypot(
        transaction_id="TXN-EXPIRE-001",
        source_account="SRC-EXP",
        target_account="MULE-EXP",
        amount=100000.0,
        currency="INR",
        risk_score=0.98,
        fraud_indicators=["extreme_velocity"],
    )

    # Force auto_release_time into the past
    hp.auto_release_time = datetime.now() - timedelta(minutes=10)

    # Run async TTL cleanup
    await manager.cleanup_expired_honeypots_async()

    assert hp.released is True
    assert hp.status == HoneypotStatus.RELEASED
