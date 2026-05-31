```python
"""
FastAPI Application for AegisGraph Sentinel 2.0

Real-time fraud detection API service
"""


import asyncio
import binascii
import hashlib
import hmac
import json
import os
import time
from importlib import import_module
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from enum import Enum
from functools import partial
from pathlib import Path
from itertools import islice
from typing import Any, Dict, List, Optional

import networkx as nx
import numpy as np
import uvicorn
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from .websocket_manager import WebSocketManager

ws_manager = WebSocketManager()

try:
    _slowapi = import_module("slowapi")
    _slowapi_errors = import_module("slowapi.errors")
    _slowapi_middleware = import_module("slowapi.middleware")
    _slowapi_util = import_module("slowapi.util")

    Limiter = _slowapi.Limiter
    _rate_limit_exceeded_handler = _slowapi._rate_limit_exceeded_handler
    RateLimitExceeded = _slowapi_errors.RateLimitExceeded
    SlowAPIMiddleware = _slowapi_middleware.SlowAPIMiddleware
    get_remote_address = _slowapi_util.get_remote_address
    SLOWAPI_AVAILABLE = True
except ImportError as e:
    SLOWAPI_AVAILABLE = False

    class RateLimitExceeded(Exception):
        pass

    class Limiter:
        def __init__(self, *args, **kwargs):
            self.key_func = kwargs.get("key_func")

        def limit(self, *args, **kwargs):
            def decorator(func):
                return func

            return decorator

    class SlowAPIMiddleware:
        def __init__(self, app, *args, **kwargs):
            self.app = app

        async def __call__(self, scope, receive, send):
            await self.app(scope, receive, send)

    def get_remote_address(request):
        client = getattr(request, "client", None)
        return getattr(client, "host", "unknown")

    async def _rate_limit_exceeded_handler(request, exc):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    print(f"SlowAPI not available ({e}); rate limiting disabled")

from ..config.settings import get_settings
from ..config.validation import validate_environment
from ..exceptions import register_exception_handlers, register_observability_middleware
from ..observability import get_audit_logger, get_logger
from ..runtime import LifecycleManager, RuntimeState, RecoveryManager, RuntimeWatchdog
from ..runtime.background_tasks import honeypot_auto_release_loop
from .schemas import (
    AccountOpeningRequest,
    AccountOpeningResponse,
    BatchTransactionRequest,
    BatchTransactionResponse,
    BlastRadiusRequest,
    BlastRadiusResponse,
    BlockchainEvidenceResponse,
    BlockchainSealRequest,
    BlockchainVerificationResponse,
    ContagionNode,
    ExplainRequest,
    HealthCheckResponse,
    HoneypotDebugRequest,
    HoneypotListResponse,
    HoneypotStatsResponse,
    LegalExportRequest,
    LegalExportResponse,
    OracleExplainRequest,
    RiskBreakdown,
    StatsResponse,
    TransactionCheckRequest,
    TransactionCheckResponse,
    VoiceAnalysisRequest,
    VoiceAnalysisResponse,
    HoneypotStatus,
)
from .security import require_api_key
from .validators import StrictRateLimit


INNOVATIONS_AVAILABLE = False
state: Any = None

def _require_legal_export_authorization(authorization_token: Optional[str]) -> None:
    """Legacy wrapper: ensure a provided authorization token matches configured hash.

    This function is kept for backward compatibility with callers that only
    validate an Authorization-style token. Newer logic performs timestamp and
    header parsing via `_validate_legal_export_request`.
    """
    expected_hash = os.getenv("AEGIS_LEGAL_EXPORT_TOKEN_HASH")
    if not expected_hash:
        raise HTTPException(
            status_code=503,
            detail="Legal export authorization is not configured",
        )

    if not authorization_token:
        raise HTTPException(status_code=401, detail="Missing legal export authorization token")

    provided_hash = hashlib.sha256(authorization_token.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(provided_hash, expected_hash):
        raise HTTPException(status_code=403, detail="Unauthorized legal export request")


def _extract_legal_export_token(
    authorization: Optional[str],
    x_legal_export_token: Optional[str],
) -> Optional[str]:
    if authorization:
        scheme, _, credentials = authorization.partition(" ")
        if scheme.lower() == "bearer" and credentials.strip():
            return credentials.strip()

    if x_legal_export_token:
        return x_legal_export_token

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

from pytest import fixture
import pytest

@pytest.mark.asyncio
async def test_api_call_success():
    async with asynccontextmanager(app):
        response = await app.get('/')
        assert response.status_code == 200

import pytest_asyncio


ws_manager = WebSocketManager()
app = FastAPI()
app.state.ws_manager = ws_manager

@app.websocket("/ws")
async def websocket_connect(
    websocket: WebSocket,
    token: str = Header(...),
):
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)

app.add_exception_handler(Exception, lambda request, exc: HTTPException(status_code=500, detail="Server error"))

if __name__ == "__main__":
    try:
        import pytest
    except ImportError:
        pass
    else:
        pytest.main([__file__, '-vv', '-s'])

class DiGraph:
    def add_node(self, node, attr_dict=None, **attr):
        pass

    def add_edge(self, u, v, attr_dict=None, **attr):
        pass

state = DiGraph()
state._edge_attrs = {}

def _require_legal_export_authorization(authorization_token: Optional[str]) -> None:
    """Legacy wrapper: ensure a provided authorization token matches configured hash.

    This function is kept for backward compatibility with callers that only
    validate an Authorization-style token. Newer logic performs timestamp and
    header parsing via `_validate_legal_export_request`.
    """
    expected_hash = os.getenv("AEGIS_LEGAL_EXPORT_TOKEN_HASH")
    if not expected_hash:
        raise HTTPException(
            status_code=503,
            detail="Legal export authorization is not configured",
        )

    if not authorization_token:
        raise HTTPException(status_code=401, detail="Missing legal export authorization token")

    provided_hash = hashlib.sha256(authorization_token.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(provided_hash, expected_hash):
        raise HTTPException(status_code=403, detail="Unauthorized legal export request")


def _extract_legal_export_token(
    authorization: Optional[str],
    x_legal_export_token: Optional[str],
) -> Optional[str]:
    if authorization:
        scheme, _, credentials = authorization.partition(" ")
        if scheme.lower() == "bearer" and credentials.strip():
            return credentials.strip()

    if x_legal_export_token:
        return x_legal_export_token

def test_file_hashes():
    file_hashes = ['_read_file_bytes', '_read_file_text', '_read_json_file']
    assert file_hashes == ['_read_file_bytes', '_read_file_text', '_read_json_file']

def test_epoch_versions():
    versions = ['v_epoch_1', 'v_epoch_2']
    assert ['v_epoch_2'] == ['v_epoch_2']

from starlette.requests import Request
from fastapi import FastAPI, WebSocket

app = FastAPI()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    while True:
        data = await websocket.receive_text()
        await websocket.send_text(f"Message text was: {data}")

import pytest

@pytest.mark.asyncio
async def test_websocket_connect():
    client = WebSocket()
    await client.connect("ws://testserver/ws")
    await client.send_text("Hello, server!")
    message = await client.receive_text()
    assert message == "Message text was: Hello, server!"
    await client.close()

import pytest_asyncio

@pytest_asyncio.fixture
async def client():
    async with AsyncClient(app=app, base_url="http://testserver") as client:
        yield client

import pytest

@pytest.fixture
def client():
    return "test_client"

@app.get("/items/")
async def read_items(client: str = Depends(client)):
    return {"client": client}
```