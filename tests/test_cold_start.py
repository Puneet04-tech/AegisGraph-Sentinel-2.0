from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


TEST_API_KEY = "test-api-key"
TEST_API_KEY_HASH = hashlib.sha256(TEST_API_KEY.encode("utf-8")).hexdigest()


@pytest.fixture(scope="module")
def api_module():
    from src.api.main import app, state

    return app, state


@pytest.fixture()
def client(api_module, monkeypatch):
    app, state = api_module
    monkeypatch.setenv("AEGIS_API_KEY_HASHES", TEST_API_KEY_HASH)

    with state.services._lock:
        state.services._services.pop("mule_scorer", None)

    with TestClient(app) as test_client:
        yield test_client, state

    with state.services._lock:
        state.services._services.pop("mule_scorer", None)


_IMPORT_PROBE = """
import sys
import src.api.main
assert "torch" not in sys.modules, "src.api.main imported torch"
assert "librosa" not in sys.modules, "src.api.main imported librosa"
"""


def test_app_imports_without_heavy_libs():
    """The API module must import without pulling in torch or librosa.

    This runs in a subprocess. Evicting the modules from ``sys.modules`` here
    and re-importing leaks into the rest of the session: a later ``import
    torch`` re-executes torch's init and raises on the duplicate TORCH_LIBRARY
    registration, and the re-executed ``src.api.main`` builds a second app
    whose import side effects land on singletons other tests already hold.
    """
    result = subprocess.run(
        [sys.executable, "-c", _IMPORT_PROBE],
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).resolve().parent.parent),
    )

    assert result.returncode == 0, (
        "importing src.api.main pulled in a heavy library:\n"
        f"{result.stdout[-2000:]}\n{result.stderr[-2000:]}"
    )


def test_innovation_services_not_constructed_at_startup(client):
    test_client, state = client

    response = test_client.get("/health")

    assert response.status_code == 200
    assert state.services.optional_get("voice_analyzer") is None
    assert state.services.optional_get("blockchain_manager") is None


def test_mule_scorer_constructed_on_first_request(client):
    test_client, state = client

    assert state.services.optional_get("mule_scorer") is None

    payload = {
        "account_id": "ACC_NEW_123",
        "name": "Asha Verma",
        "age": 28,
        "profession": "Software Engineer",
        "email": "asha.verma@example.com",
        "phone": "+91-9876543210",
        "device_id": "device-12345",
        "ip_address": "203.0.113.10",
        "stated_address": "123 MG Road, Bengaluru, Karnataka",
        "facial_match": 0.94,
        "document_type": "PAN",
        "initial_deposit": 25000.0,
        "referrer": "REF-001",
        "form_completion_time_seconds": 180,
    }

    response = test_client.post(
        "/api/v1/accounts/score-opening",
        headers={"X-API-Key": TEST_API_KEY},
        json=payload,
    )

    assert response.status_code == 200, response.text
    assert state.services.optional_get("mule_scorer") is not None
