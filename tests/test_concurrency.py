import pytest
import asyncio
import time
import httpx
from src.api.main import app


@pytest.mark.anyio
async def test_event_loop_responsiveness():
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as ac:

        async def fire_heavy_request():
            return await ac.post(
                "/api/v1/fraud/check",
                headers={
                    "X-API-Key": "d8f9b9f71c4c1a4b8689360d84386fc7b9c6a1e342898b3c940b5d1a8e108139"
                },
                json={
                    "transaction_id": "tx_concurrency_1",
                    "source_account": "acc_concurrency_test",
                    "target_account": "acc_target_test",
                    "amount": 1000.0,
                    "currency": "USD",
                    "timestamp": time.time(),
                    "biometrics": {
                        "hold_times": [100, 110, 105, 95, 120] * 10,
                        "flight_times": [150, 140, 160, 155, 145] * 10,
                    },
                },
            )

        async def fire_health_request():
            return await ac.get("/")

        heavy_tasks = [
            asyncio.create_task(fire_heavy_request())
            for _ in range(5)
        ]

        await asyncio.sleep(0.1)

        start_time = time.time()
        health_response = await fire_health_request()
        elapsed = time.time() - start_time

        results = await asyncio.gather(*heavy_tasks)

        for response in results:
            assert response.status_code == 200

        assert health_response.status_code == 200
        assert elapsed < 1.0