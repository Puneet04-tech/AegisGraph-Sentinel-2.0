"""Ensure background API paths never call Streamlit side effects on 401."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import app as streamlit_app


class _FakeResponse:
    def __init__(self, status_code: int, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests

            err = requests.exceptions.HTTPError(response=self)
            raise err

    def json(self):
        return self._payload


def test_authenticated_request_skips_streamlit_side_effects_on_401(monkeypatch):
    warned = MagicMock()
    cleared = MagicMock()
    rerun = MagicMock()
    monkeypatch.setattr(streamlit_app, "_handle_unauthorized", warned)
    monkeypatch.setattr(streamlit_app.st, "warning", warned)
    monkeypatch.setattr(streamlit_app.st, "error", warned)
    monkeypatch.setattr(streamlit_app.st, "rerun", rerun)
    monkeypatch.setattr(streamlit_app, "authenticated_headers", lambda extra=None: {})
    monkeypatch.setattr(
        streamlit_app.requests,
        "request",
        lambda *args, **kwargs: _FakeResponse(401),
    )

    response = streamlit_app.authenticated_request(
        "POST",
        "http://example.test/api",
        allow_streamlit_side_effects=False,
    )

    assert response.status_code == 401
    warned.assert_not_called()
    rerun.assert_not_called()


def test_safe_api_post_returns_error_dict_without_rerun(monkeypatch):
    rerun = MagicMock()
    monkeypatch.setattr(streamlit_app.st, "rerun", rerun)
    monkeypatch.setattr(streamlit_app.st, "warning", MagicMock())
    monkeypatch.setattr(streamlit_app.st, "error", MagicMock())
    monkeypatch.setattr(streamlit_app, "_handle_unauthorized", MagicMock())
    monkeypatch.setattr(streamlit_app, "authenticated_headers", lambda extra=None: {})
    monkeypatch.setattr(
        streamlit_app.requests,
        "request",
        lambda *args, **kwargs: _FakeResponse(401),
    )

    result = streamlit_app._safe_api_post(
        "http://example.test/api",
        {"transaction_id": "t1"},
        allow_streamlit_side_effects=False,
    )

    assert result == {"error": "unauthorized", "status_code": 401}
    rerun.assert_not_called()


def test_build_live_event_background_path_returns_unauthorized_dict(monkeypatch):
    monkeypatch.setattr(
        streamlit_app,
        "_safe_api_post",
        lambda *args, **kwargs: {"error": "unauthorized", "status_code": 401},
    )
    result = streamlit_app._build_live_event(
        "http://example.test",
        {"transaction_id": "LIVE_1", "amount": 10},
        allow_streamlit_side_effects=False,
    )
    assert result == {"error": "unauthorized", "status_code": 401}
