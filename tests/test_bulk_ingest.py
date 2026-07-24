"""Regression coverage for public bulk-ingestion route registration."""

from fastapi.testclient import TestClient

from src.api.main import app


def test_bulk_ingestion_routes_are_not_mounted() -> None:
    client = TestClient(app)

    response = client.post(
        "/api/v1/bulk/ingest",
        headers={"X-API-Key": "unused"},
        json={
            "nodes": [{"id": "untrusted-node", "type": "Account"}],
            "edges": [],
        },
    )

    assert response.status_code == 404
