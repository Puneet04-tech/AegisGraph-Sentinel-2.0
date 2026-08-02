"""Regression coverage for public bulk-ingestion route registration."""

import io

import pytest
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


# =============================================================================
# Upload limit enforcement
# =============================================================================

from src.api import bulk_ingest_routes
from src.api.bulk_ingest_routes import (
    MAX_EDGES_PER_REQUEST,
    MAX_NODES_PER_REQUEST,
    UploadTooLargeError,
    _bounded_bytes,
    _read_upload_with_budget,
    ingest_bulk_json,
    ingest_bulk_file,
)


class _FakeUploadFile:
    """Minimal stand-in for a FastAPI UploadFile."""

    def __init__(self, body: bytes, headers=None, filename="data.json", content_type="application/json"):
        self.file = io.BytesIO(body)
        self.headers = headers or {}
        self.filename = filename
        self.content_type = content_type

    async def read(self, size: int = -1) -> bytes:
        return self.file.read(size)


class TestBoundedBytes:
    def test_reads_within_budget(self) -> None:
        data = b"x" * 100
        result = b"".join(_bounded_bytes(io.BytesIO(data), max_bytes=10_000))
        assert result == data

    def test_exceeding_budget_raises(self) -> None:
        data = b"x" * 10_000
        with pytest.raises(UploadTooLargeError):
            b"".join(_bounded_bytes(io.BytesIO(data), max_bytes=1_000))


class TestReadUploadWithBudget:
    @pytest.mark.asyncio
    async def test_content_length_header_enforced(self) -> None:
        upload = _FakeUploadFile(
            body=b"{}",
            headers={"content-length": "5000000"},
        )
        with pytest.raises(UploadTooLargeError):
            await _read_upload_with_budget(upload, max_bytes=1024)

    @pytest.mark.asyncio
    async def test_streamed_body_budget_enforced(self) -> None:
        upload = _FakeUploadFile(body=b"y" * 10_000)
        with pytest.raises(UploadTooLargeError):
            await _read_upload_with_budget(upload, max_bytes=1024)

    @pytest.mark.asyncio
    async def test_body_within_budget(self) -> None:
        upload = _FakeUploadFile(body=b'{"nodes": []}')
        result = await _read_upload_with_budget(upload, max_bytes=10_000)
        assert result == b'{"nodes": []}'


class TestIngestBulkFileLimits:
    @pytest.mark.asyncio
    async def test_oversized_json_returns_413(self, monkeypatch) -> None:
        monkeypatch.setattr(bulk_ingest_routes, "MAX_UPLOAD_SIZE_BYTES", 1024)
        body = b'{"nodes": [{"id": "n1", "type": "Account"}], "edges": []}' + b"x" * 5000
        upload = _FakeUploadFile(body=body)
        with pytest.raises(Exception) as exc_info:
            await ingest_bulk_file(upload, data_type="auto")
        assert exc_info.value.status_code == 413

    @pytest.mark.asyncio
    async def test_too_many_nodes_rejected(self, monkeypatch) -> None:
        monkeypatch.setattr(bulk_ingest_routes, "MAX_NODES_PER_REQUEST", 2)
        body = {
            "nodes": [
                {"id": f"n{i}", "type": "Account"} for i in range(5)
            ],
            "edges": [],
        }
        upload = _FakeUploadFile(
            body=bulk_ingest_routes.json.dumps(body).encode("utf-8")
        )
        with pytest.raises(Exception) as exc_info:
            await ingest_bulk_file(upload, data_type="auto")
        assert exc_info.value.status_code == 400
        assert "maximum" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_csv_row_limit_rejected(self, monkeypatch) -> None:
        monkeypatch.setattr(bulk_ingest_routes, "MAX_ROWS_PER_CSV", 3)
        rows = "\n".join(
            [f"n{i},Account" for i in range(10)]
        )
        csv_body = f"id,type\n{rows}\n".encode("utf-8")
        upload = _FakeUploadFile(
            body=csv_body,
            filename="nodes.csv",
            content_type="text/csv",
        )
        with pytest.raises(Exception) as exc_info:
            await ingest_bulk_file(upload, data_type="auto")
        assert exc_info.value.status_code == 400
        assert "maximum" in str(exc_info.value.detail)


class TestIngestBulkJsonLimits:
    @pytest.mark.asyncio
    async def test_too_many_nodes_rejected(self, monkeypatch) -> None:
        monkeypatch.setattr(bulk_ingest_routes, "MAX_NODES_PER_REQUEST", 2)
        from src.api.schemas import BulkIngestRequest

        payload = BulkIngestRequest(
            nodes=[
                {"id": f"n{i}", "type": "Account"} for i in range(5)
            ],
            edges=[],
        )
        with pytest.raises(Exception) as exc_info:
            await ingest_bulk_json(payload)
        assert exc_info.value.status_code == 400
        assert "maximum" in str(exc_info.value.detail)
