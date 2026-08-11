"""
Unit tests for Async Fabric Connection Pool under high workload (Issue #3456).
"""

import asyncio
import pytest
from src.features.blockchain_evidence import AsyncFabricConnectionPool, get_async_fabric_pool
from src.api.dependencies.subsystems import get_blockchain_connection_pool


@pytest.mark.asyncio
async def test_connection_pool_acquisition_and_release():
    pool = AsyncFabricConnectionPool(min_size=5, max_size=10)

    conn1 = await pool.acquire()
    conn2 = await pool.acquire()
    assert conn1 != conn2
    assert pool.active_count >= 5

    await pool.release(conn1)
    await pool.release(conn2)


@pytest.mark.asyncio
async def test_connection_pool_scaling():
    pool = AsyncFabricConnectionPool(min_size=2, max_size=5)
    conns = [await pool.acquire() for _ in range(5)]

    assert pool.active_count == 5
    assert len(conns) == 5

    for c in conns:
        await pool.release(c)


@pytest.mark.asyncio
async def test_execute_async_with_retry():
    pool = AsyncFabricConnectionPool(min_size=2, max_size=5, retries=2)

    def dummy_grpc_call(arg1, arg2):
        return f"result_{arg1}_{arg2}"

    result = await pool.execute_async(dummy_grpc_call, "val1", "val2")
    assert result == "result_val1_val2"


def test_dependency_injection_provider():
    pool_dep = get_blockchain_connection_pool()
    assert isinstance(pool_dep, AsyncFabricConnectionPool)
