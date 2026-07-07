"""
Unit tests for the Asynchronous Bulk Graph Ingestion Endpoints
"""

import asyncio
import hashlib

import pytest
from httpx import ASGITransport, AsyncClient

from src.api.bulk_ingest_routes import bulk_ingestion_manager
from src.api.main import app, state
from src.api.security import Role

_TEST_API_KEY = "test-analyst-key"
_TEST_API_KEY_HASH = hashlib.sha256(_TEST_API_KEY.encode("utf-8")).hexdigest()
_HEADERS = {"X-API-Key": _TEST_API_KEY}


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def setup_auth(monkeypatch):
    """Enable real API key validation and set the expected test key hash."""
    monkeypatch.setenv("AEGIS_API_KEY_HASHES", _TEST_API_KEY_HASH)

    from src.api.security import _invalidate_auth_cache, require_api_key

    _invalidate_auth_cache()

    # Clear dependency overrides specifically for bulk endpoints to test real authentication
    app.dependency_overrides.pop(require_api_key, None)
    from fastapi.routing import APIRoute

    for route in app.routes:
        if isinstance(route, APIRoute) and route.path.startswith("/api/v1/bulk"):
            for dep in route.dependencies:
                fn = getattr(dep, "dependency", None)
                if fn:
                    app.dependency_overrides.pop(fn, None)


@pytest.fixture(autouse=True)
async def clean_graph_and_tasks():
    """Reset the graph database and task registry before/after each test."""
    import networkx as nx

    original_graph = getattr(state, "transaction_graph", None)
    original_loaded = getattr(state, "graph_loaded", False)

    state.transaction_graph = nx.DiGraph()
    state.graph_loaded = True
    bulk_ingestion_manager.tasks.clear()

    # We explicitly do NOT call start_worker() to prevent concurrent background processing.
    # Instead, the tests will manually dequeue and process tasks for 100% determinism.
    bulk_ingestion_manager.testing = True

    yield

    # Restores
    bulk_ingestion_manager.testing = False

    # Drain queue
    while not bulk_ingestion_manager.queue.empty():
        try:
            bulk_ingestion_manager.queue.get_nowait()
            bulk_ingestion_manager.queue.task_done()
        except (asyncio.QueueEmpty, ValueError):
            break

    # Restore original state
    state.transaction_graph = original_graph
    state.graph_loaded = original_loaded


@pytest.mark.anyio
async def test_bulk_ingest_json_endpoint_success():
    """Verify that a valid JSON payload is accepted and processed successfully."""
    payload = {
        "nodes": [
            {
                "id": "ACC_JSON_01",
                "type": "Account",
                "properties": {"is_mule": True, "risk_score": 0.9},
            },
            {
                "id": "DEV_JSON_01",
                "type": "Device",
                "properties": {"fingerprint": "json123"},
            },
        ],
        "edges": [
            {
                "source": "ACC_JSON_01",
                "target": "ACC_JSON_02",
                "type": "Transfer",
                "properties": {"amount": 50000.0, "mode": "UPI"},
            }
        ],
    }

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        # Submit task
        response = await client.post(
            "/api/v1/bulk/ingest", json=payload, headers=_HEADERS
        )
        assert response.status_code == 200
        data = response.json()
        assert "task_id" in data
        assert data["status"] == "pending"

        task_id = data["task_id"]

        # Dequeue and process task manually to verify database ingestion
        task_id_queued, nodes, edges = await bulk_ingestion_manager.queue.get()
        assert task_id_queued == task_id
        await bulk_ingestion_manager._process_ingestion(task_id, nodes, edges)
        bulk_ingestion_manager.queue.task_done()

        # Check status
        status_resp = await client.get(
            f"/api/v1/bulk/status/{task_id}", headers=_HEADERS
        )
        assert status_resp.status_code == 200
        status_data = status_resp.json()
        assert status_data["status"] == "completed"
        assert status_data["progress"]["successful_items"] == 3
        assert status_data["progress"]["failed_items"] == 0
        assert len(status_data["errors"]) == 0

        # Verify nodes and edges added to the graph
        assert state.transaction_graph.has_node("ACC_JSON_01")
        assert state.transaction_graph.nodes["ACC_JSON_01"]["type"] == "Account"
        assert state.transaction_graph.nodes["ACC_JSON_01"]["is_mule"] is True
        assert state.transaction_graph.nodes["ACC_JSON_01"]["risk_score"] == 0.9

        assert state.transaction_graph.has_node("DEV_JSON_01")
        assert state.transaction_graph.nodes["DEV_JSON_01"]["type"] == "Device"
        assert state.transaction_graph.nodes["DEV_JSON_01"]["fingerprint"] == "json123"

        assert state.transaction_graph.has_edge("ACC_JSON_01", "ACC_JSON_02")
        assert (
            state.transaction_graph.edges["ACC_JSON_01", "ACC_JSON_02"]["type"]
            == "Transfer"
        )
        assert (
            state.transaction_graph.edges["ACC_JSON_01", "ACC_JSON_02"]["amount"]
            == 50000.0
        )
        assert (
            state.transaction_graph.edges["ACC_JSON_01", "ACC_JSON_02"]["mode"] == "UPI"
        )


@pytest.mark.anyio
async def test_bulk_ingest_nodes_csv_success():
    """Verify that a nodes CSV file can be uploaded and processed successfully."""
    csv_data = (
        "id,type,is_mule,risk_score,balance\n"
        "ACC_CSV_N1,Account,true,0.75,10000.50\n"
        "DEV_CSV_N1,Device,false,0.05,\n"
    )

    files = {"file": ("nodes.csv", csv_data.encode("utf-8"), "text/csv")}
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/v1/bulk/ingest/file?data_type=nodes", files=files, headers=_HEADERS
        )
        assert response.status_code == 200
        data = response.json()
        task_id = data["task_id"]

        # Dequeue and process task manually
        task_id_queued, nodes, edges = await bulk_ingestion_manager.queue.get()
        assert task_id_queued == task_id
        await bulk_ingestion_manager._process_ingestion(task_id, nodes, edges)
        bulk_ingestion_manager.queue.task_done()

        # Check status
        status_resp = await client.get(
            f"/api/v1/bulk/status/{task_id}", headers=_HEADERS
        )
        status_data = status_resp.json()
        assert status_data["status"] == "completed"
        assert status_data["progress"]["successful_items"] == 2
        assert status_data["progress"]["failed_items"] == 0

        assert state.transaction_graph.has_node("ACC_CSV_N1")
        assert state.transaction_graph.nodes["ACC_CSV_N1"]["type"] == "Account"
        assert state.transaction_graph.nodes["ACC_CSV_N1"]["is_mule"] is True
        assert state.transaction_graph.nodes["ACC_CSV_N1"]["risk_score"] == 0.75
        assert state.transaction_graph.nodes["ACC_CSV_N1"]["balance"] == 10000.50

        assert state.transaction_graph.has_node("DEV_CSV_N1")
        assert state.transaction_graph.nodes["DEV_CSV_N1"]["type"] == "Device"
        assert state.transaction_graph.nodes["DEV_CSV_N1"]["is_mule"] is False
        assert state.transaction_graph.nodes["DEV_CSV_N1"]["risk_score"] == 0.05
        assert state.transaction_graph.nodes["DEV_CSV_N1"]["balance"] is None


@pytest.mark.anyio
async def test_bulk_ingest_edges_csv_success():
    """Verify that an edges CSV file can be uploaded and auto-detected successfully."""
    csv_data = (
        "source,target,type,amount,success\n"
        "ACC_CSV_E1,ACC_CSV_E2,Transfer,150000.0,true\n"
        "ACC_CSV_E2,ACC_CSV_E3,Transfer,20000,false\n"
    )

    files = {"file": ("edges.csv", csv_data.encode("utf-8"), "text/csv")}
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/v1/bulk/ingest/file", files=files, headers=_HEADERS
        )  # auto-detect
        assert response.status_code == 200
        data = response.json()
        task_id = data["task_id"]

        # Dequeue and process task manually
        task_id_queued, nodes, edges = await bulk_ingestion_manager.queue.get()
        assert task_id_queued == task_id
        await bulk_ingestion_manager._process_ingestion(task_id, nodes, edges)
        bulk_ingestion_manager.queue.task_done()

        # Check status
        status_resp = await client.get(
            f"/api/v1/bulk/status/{task_id}", headers=_HEADERS
        )
        status_data = status_resp.json()
        assert status_data["status"] == "completed"
        assert status_data["progress"]["successful_items"] == 2
        assert status_data["progress"]["failed_items"] == 0

        assert state.transaction_graph.has_edge("ACC_CSV_E1", "ACC_CSV_E2")
        assert (
            state.transaction_graph.edges["ACC_CSV_E1", "ACC_CSV_E2"]["amount"]
            == 150000.0
        )
        assert (
            state.transaction_graph.edges["ACC_CSV_E1", "ACC_CSV_E2"]["success"] is True
        )

        assert state.transaction_graph.has_edge("ACC_CSV_E2", "ACC_CSV_E3")
        assert (
            state.transaction_graph.edges["ACC_CSV_E2", "ACC_CSV_E3"]["amount"] == 20000
        )
        assert (
            state.transaction_graph.edges["ACC_CSV_E2", "ACC_CSV_E3"]["success"]
            is False
        )


@pytest.mark.anyio
async def test_bulk_ingest_skips_corrupt_rows():
    """Verify that corrupt CSV rows are skipped and recorded, while valid rows are processed."""
    csv_data = (
        "source,target,type,amount\n"
        "ACC_A,ACC_B,Transfer,100\n"
        "ACC_B,,Transfer,200\n"
        "ACC_B,ACC_C,Transfer,300\n"
        ",ACC_D,Transfer,400\n"
    )

    files = {"file": ("edges_mixed.csv", csv_data.encode("utf-8"), "text/csv")}
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/v1/bulk/ingest/file?data_type=edges", files=files, headers=_HEADERS
        )
        assert response.status_code == 200
        data = response.json()
        task_id = data["task_id"]

        # Dequeue and process task manually
        task_id_queued, nodes, edges = await bulk_ingestion_manager.queue.get()
        assert task_id_queued == task_id
        await bulk_ingestion_manager._process_ingestion(task_id, nodes, edges)
        bulk_ingestion_manager.queue.task_done()

        # Check status
        status_resp = await client.get(
            f"/api/v1/bulk/status/{task_id}", headers=_HEADERS
        )
        status_data = status_resp.json()
        assert status_data["status"] == "completed"
        assert status_data["progress"]["successful_items"] == 2
        assert status_data["progress"]["failed_items"] == 2
        assert len(status_data["errors"]) == 2
        assert any("Row 2 error" in err for err in status_data["errors"])
        assert any("Row 4 error" in err for err in status_data["errors"])

        assert state.transaction_graph.has_edge("ACC_A", "ACC_B")
        assert state.transaction_graph.has_edge("ACC_B", "ACC_C")
        assert not state.transaction_graph.has_edge("ACC_B", "")


@pytest.mark.anyio
async def test_bulk_ingest_status_not_found():
    """Verify that polling a non-existent task ID returns 404."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get(
            "/api/v1/bulk/status/non-existent-task-id", headers=_HEADERS
        )
        assert response.status_code == 404
        assert "not found" in response.json()["error"]["message"]


@pytest.mark.anyio
async def test_bulk_ingest_empty_payload_fails():
    """Verify that sending empty nodes/edges lists returns 400."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/api/v1/bulk/ingest", json={"nodes": [], "edges": []}, headers=_HEADERS
        )
        assert response.status_code == 400
        assert "at least one node or edge" in response.json()["error"]["message"]
