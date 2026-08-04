"""Refresh-token session preservation tests for AuthService.

Regression guard for issue #2863: ``refresh_tokens()`` passed a ``session_id``
kwarg to ``_create_auth_result()``, but that method did not accept it, so every
token refresh crashed with TypeError. Even after accepting the kwarg, the
refresh must *preserve* the original session rather than minting a fresh one —
otherwise a captured refresh token keeps working past logout and the session
registry fills with duplicate entries.
"""

import pytest

from src.exceptions import AuthenticationError
from src.saas.auth.credential_stores import InMemorySessionStore
from src.saas.auth.service import AuthService, InMemoryUserStore, UserRecord


def _make_service(users=None):
    store = InMemoryUserStore()
    for u in (users or []):
        store.add(u)
    sessions = InMemorySessionStore()
    svc = AuthService(
        {"jwt_secret": "test-secret-only", "access_token_expiry": 3600},
        user_store=store,
        session_store=sessions,
    )
    return svc, sessions


def _user(svc, user_id="u1"):
    return UserRecord(
        user_id,
        "member-org",
        "user@example.com",
        password_hash=svc.hash_password("correct-password"),
    )


def test_refresh_preserves_original_session_id():
    svc, _ = _make_service()
    svc.user_store.add(_user(svc))

    initial = svc.authenticate_user("user@example.com", "correct-password")
    refreshed = svc.refresh_tokens(initial.refresh_token)

    assert refreshed.session_id == initial.session_id
    assert svc.verify_token(refreshed.access_token).sid == initial.session_id


def test_refresh_does_not_duplicate_session_record():
    svc, sessions = _make_service()
    svc.user_store.add(_user(svc))

    initial = svc.authenticate_user("user@example.com", "correct-password")
    sessions_before = sessions.list_for_user("u1")

    svc.refresh_tokens(initial.refresh_token)
    sessions_after = sessions.list_for_user("u1")

    assert [s.session_id for s in sessions_before] == [initial.session_id]
    assert [s.session_id for s in sessions_after] == [initial.session_id]


def test_refresh_tokens_stay_bound_to_revoked_session():
    svc, sessions = _make_service()
    svc.user_store.add(_user(svc))

    initial = svc.authenticate_user("user@example.com", "correct-password")
    refreshed = svc.refresh_tokens(initial.refresh_token)

    # Logging out of the original session must kill even the freshly rotated
    # refresh token — proof the rotation stayed bound to the same session.
    sessions.revoke(initial.session_id)
    svc.revocation_store.revoke_session(initial.session_id, None)

    with pytest.raises(AuthenticationError):
        svc.refresh_tokens(refreshed.refresh_token)
