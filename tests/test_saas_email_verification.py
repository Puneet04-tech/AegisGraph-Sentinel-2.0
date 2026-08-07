"""Email verification token issuance, consumption and throttling.

`verify_user_email` used to accept any string of eight or more characters --
no token was ever generated, stored, hashed, expired or single-used anywhere in
the codebase, so `email_verified` was a flag any authenticated caller could set
on themselves. These tests pin the real token lifecycle.
"""

from __future__ import annotations

import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.saas.auth.credential_stores import (
    InMemoryEmailVerificationTokenStore,
    _hash,
)
from src.saas.routes import users as users_routes
from src.saas.routes.auth import get_current_user

# Mirrors tests/test_saas_users_security.py: the users router is not mounted on
# the production app, so it is exercised on a router-local one.
app = FastAPI()
app.include_router(users_routes.router)

TENANT = "org_alpha"
ADMIN = {"user_id": "u_admin", "organization_id": TENANT, "role": "admin"}
OTHER_ADMIN = {"user_id": "u_admin2", "organization_id": TENANT, "role": "admin"}

STRONG_PASSWORD = "Str0ng!Passw0rd#2026"


@pytest.fixture
def api_client():
    with TestClient(app) as client:
        yield client


def _as(user):
    app.dependency_overrides[get_current_user] = lambda: user


@pytest.fixture(autouse=True)
def _reset_state():
    users_routes._USER_STORE.clear()
    users_routes._AUDIT_LOG.clear()
    users_routes._verification_tokens = InMemoryEmailVerificationTokenStore()
    # The tenant usage counter is module-global, so it has to be reset too or
    # the subscription limit trips partway through the module.
    users_routes.set_tenant_resource_count(TENANT, "max_users", 0)
    _as(ADMIN)
    yield
    users_routes._USER_STORE.clear()
    users_routes._AUDIT_LOG.clear()
    app.dependency_overrides.pop(get_current_user, None)


@pytest.fixture
def sent_tokens(monkeypatch):
    """Capture tokens handed to the notification sender."""
    captured = []
    monkeypatch.setattr(
        users_routes._notification_sender,
        "send_email_verification",
        lambda email, token: captured.append((email, token)),
    )
    return captured


def _create_user(api_client, email="analyst@example.com"):
    response = api_client.post(
        "/api/v1/users/",
        json={"email": email, "password": STRONG_PASSWORD, "role": "member"},
    )
    assert response.status_code == 201, response.text
    return response.json()


class TestTokenIsRequired:
    def test_arbitrary_eight_character_string_is_rejected(self, api_client, sent_tokens):
        """The exact bypass this issue reports."""
        user = _create_user(api_client)
        response = api_client.post(
            f"/api/v1/users/{user['id']}/verify-email?token=aaaaaaaa"
        )
        assert response.status_code == 422
        assert api_client.get(f"/api/v1/users/{user['id']}").json()["email_verified"] is False

    def test_long_random_string_is_still_rejected(self, api_client, sent_tokens):
        user = _create_user(api_client)
        response = api_client.post(
            f"/api/v1/users/{user['id']}/verify-email?token={'z' * 64}"
        )
        assert response.status_code == 422

    def test_empty_token_is_rejected(self, api_client, sent_tokens):
        user = _create_user(api_client)
        assert api_client.post(
            f"/api/v1/users/{user['id']}/verify-email?token="
        ).status_code == 422

    def test_a_real_token_is_accepted(self, api_client, sent_tokens):
        user = _create_user(api_client)
        _, token = sent_tokens[-1]

        response = api_client.post(
            f"/api/v1/users/{user['id']}/verify-email?token={token}"
        )
        assert response.status_code == 200
        assert response.json()["email_verified"] is True
        assert api_client.get(f"/api/v1/users/{user['id']}").json()["email_verified"] is True


class TestSingleUse:
    def test_a_token_cannot_be_replayed(self, api_client, sent_tokens):
        user = _create_user(api_client)
        _, token = sent_tokens[-1]
        path = f"/api/v1/users/{user['id']}/verify-email?token={token}"

        assert api_client.post(path).status_code == 200

        # Already verified, so this is a no-op success rather than a second
        # consumption -- but the token itself is gone from the store.
        assert users_routes._verification_tokens.consume(
            token, user["id"], user["email"]
        ) is False

    def test_verifying_an_already_verified_address_is_idempotent(self, api_client, sent_tokens):
        user = _create_user(api_client)
        _, token = sent_tokens[-1]
        path = f"/api/v1/users/{user['id']}/verify-email?token={token}"

        assert api_client.post(path).status_code == 200
        second = api_client.post(path)
        assert second.status_code == 200
        assert second.json()["email_verified"] is True


class TestTokenBinding:
    def test_a_token_issued_for_one_user_cannot_verify_another(self, api_client, sent_tokens):
        first = _create_user(api_client, "one@example.com")
        _, first_token = sent_tokens[-1]
        second = _create_user(api_client, "two@example.com")

        response = api_client.post(
            f"/api/v1/users/{second['id']}/verify-email?token={first_token}"
        )
        assert response.status_code == 422
        assert api_client.get(f"/api/v1/users/{second['id']}").json()["email_verified"] is False

    def test_changing_the_email_invalidates_the_outstanding_token(self, api_client, sent_tokens):
        user = _create_user(api_client, "before@example.com")
        _, old_token = sent_tokens[-1]

        api_client.patch(
            f"/api/v1/users/{user['id']}", json={"email": "after@example.com"}
        )

        response = api_client.post(
            f"/api/v1/users/{user['id']}/verify-email?token={old_token}"
        )
        assert response.status_code == 422

    def test_changing_the_email_clears_the_verified_flag(self, api_client, sent_tokens):
        user = _create_user(api_client, "before@example.com")
        _, token = sent_tokens[-1]
        api_client.post(f"/api/v1/users/{user['id']}/verify-email?token={token}")
        assert api_client.get(f"/api/v1/users/{user['id']}").json()["email_verified"] is True

        api_client.patch(
            f"/api/v1/users/{user['id']}", json={"email": "after@example.com"}
        )
        assert api_client.get(f"/api/v1/users/{user['id']}").json()["email_verified"] is False

    def test_changing_the_email_issues_a_fresh_working_token(self, api_client, sent_tokens):
        user = _create_user(api_client, "before@example.com")
        api_client.patch(
            f"/api/v1/users/{user['id']}", json={"email": "after@example.com"}
        )
        email, new_token = sent_tokens[-1]
        assert email == "after@example.com"

        response = api_client.post(
            f"/api/v1/users/{user['id']}/verify-email?token={new_token}"
        )
        assert response.status_code == 200

    def test_an_unchanged_email_does_not_reset_verification(self, api_client, sent_tokens):
        user = _create_user(api_client, "same@example.com")
        _, token = sent_tokens[-1]
        api_client.post(f"/api/v1/users/{user['id']}/verify-email?token={token}")

        api_client.patch(
            f"/api/v1/users/{user['id']}", json={"email": "same@example.com"}
        )
        assert api_client.get(f"/api/v1/users/{user['id']}").json()["email_verified"] is True


class TestResend:
    def test_resend_issues_a_new_token(self, api_client, sent_tokens):
        user = _create_user(api_client)
        first_token = sent_tokens[-1][1]

        users_routes._verification_tokens._last_issued_at.clear()
        assert api_client.post(
            f"/api/v1/users/{user['id']}/resend-verification"
        ).status_code == 200

        second_token = sent_tokens[-1][1]
        assert second_token != first_token

    def test_resend_invalidates_the_previous_token(self, api_client, sent_tokens):
        user = _create_user(api_client)
        first_token = sent_tokens[-1][1]

        users_routes._verification_tokens._last_issued_at.clear()
        api_client.post(f"/api/v1/users/{user['id']}/resend-verification")

        assert api_client.post(
            f"/api/v1/users/{user['id']}/verify-email?token={first_token}"
        ).status_code == 422

    def test_the_reissued_token_works(self, api_client, sent_tokens):
        user = _create_user(api_client)
        users_routes._verification_tokens._last_issued_at.clear()
        api_client.post(f"/api/v1/users/{user['id']}/resend-verification")
        new_token = sent_tokens[-1][1]

        assert api_client.post(
            f"/api/v1/users/{user['id']}/verify-email?token={new_token}"
        ).status_code == 200

    def test_resend_is_throttled(self, api_client, sent_tokens):
        user = _create_user(api_client)
        # Registration just issued a token, so the cooldown is active.
        response = api_client.post(f"/api/v1/users/{user['id']}/resend-verification")
        assert response.status_code == 429
        assert int(response.headers["Retry-After"]) > 0

    def test_resend_on_a_verified_address_is_a_no_op(self, api_client, sent_tokens):
        user = _create_user(api_client)
        _, token = sent_tokens[-1]
        api_client.post(f"/api/v1/users/{user['id']}/verify-email?token={token}")

        response = api_client.post(f"/api/v1/users/{user['id']}/resend-verification")
        assert response.status_code == 200
        assert "already verified" in response.json()["message"].lower()


class TestAccessControl:
    def test_verification_still_requires_owner_or_admin(self, api_client, sent_tokens):
        user = _create_user(api_client)
        _, token = sent_tokens[-1]

        _as({"user_id": "u_stranger", "organization_id": TENANT, "role": "member"})
        response = api_client.post(
            f"/api/v1/users/{user['id']}/verify-email?token={token}"
        )
        assert response.status_code == 403

    def test_cross_tenant_verification_is_not_found(self, api_client, sent_tokens):
        user = _create_user(api_client)
        _, token = sent_tokens[-1]

        _as({"user_id": "u_other", "organization_id": "org_beta", "role": "admin"})
        response = api_client.post(
            f"/api/v1/users/{user['id']}/verify-email?token={token}"
        )
        assert response.status_code == 404

    def test_unknown_user_is_not_found(self, api_client):
        assert api_client.post(
            "/api/v1/users/user_missing/verify-email?token=whatever"
        ).status_code == 404


class TestStoreInternals:
    def test_raw_tokens_are_never_stored(self):
        store = InMemoryEmailVerificationTokenStore()
        token = store.issue("u1", "a@example.com")

        assert token not in store._tokens
        assert _hash(token) in store._tokens

    def test_expired_tokens_are_rejected_and_purged(self):
        store = InMemoryEmailVerificationTokenStore(ttl_seconds=0)
        token = store.issue("u1", "a@example.com")
        time.sleep(0.01)

        assert store.consume(token, "u1", "a@example.com") is False
        assert store._tokens == {}

    def test_wrong_email_is_rejected(self):
        store = InMemoryEmailVerificationTokenStore()
        token = store.issue("u1", "a@example.com")
        assert store.consume(token, "u1", "b@example.com") is False

    def test_wrong_user_is_rejected(self):
        store = InMemoryEmailVerificationTokenStore()
        token = store.issue("u1", "a@example.com")
        assert store.consume(token, "u2", "a@example.com") is False

    def test_email_comparison_is_case_and_space_insensitive(self):
        store = InMemoryEmailVerificationTokenStore()
        token = store.issue("u1", "  Analyst@Example.COM ")
        assert store.consume(token, "u1", "analyst@example.com") is True

    def test_unknown_token_is_rejected(self):
        store = InMemoryEmailVerificationTokenStore()
        store.issue("u1", "a@example.com")
        assert store.consume("not-a-real-token", "u1", "a@example.com") is False

    def test_empty_token_is_rejected(self):
        store = InMemoryEmailVerificationTokenStore()
        assert store.consume("", "u1", "a@example.com") is False

    def test_issuing_again_invalidates_the_previous_token(self):
        store = InMemoryEmailVerificationTokenStore()
        first = store.issue("u1", "a@example.com")
        second = store.issue("u1", "a@example.com")

        assert store.consume(first, "u1", "a@example.com") is False
        assert store.consume(second, "u1", "a@example.com") is True

    def test_invalidate_for_user_drops_outstanding_tokens(self):
        store = InMemoryEmailVerificationTokenStore()
        token = store.issue("u1", "a@example.com")
        store.invalidate_for_user("u1")
        assert store.consume(token, "u1", "a@example.com") is False

    def test_tokens_are_unique_per_issue(self):
        store = InMemoryEmailVerificationTokenStore()
        tokens = {store.issue(f"u{i}", f"u{i}@example.com") for i in range(50)}
        assert len(tokens) == 50

    def test_cooldown_reports_zero_before_first_issue(self):
        store = InMemoryEmailVerificationTokenStore()
        assert store.seconds_until_resend_allowed("u1") == 0

    def test_cooldown_is_reported_after_issuing(self):
        store = InMemoryEmailVerificationTokenStore(resend_cooldown_seconds=60)
        store.issue("u1", "a@example.com")
        assert 0 < store.seconds_until_resend_allowed("u1") <= 60

    def test_zero_cooldown_never_blocks(self):
        store = InMemoryEmailVerificationTokenStore(resend_cooldown_seconds=0)
        store.issue("u1", "a@example.com")
        assert store.seconds_until_resend_allowed("u1") == 0
