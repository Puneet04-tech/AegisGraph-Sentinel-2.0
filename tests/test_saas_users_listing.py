"""User directory listing: scoping, pagination, filtering, sorting and search.

The user management API could only retrieve a user by exact ID -- there was no
collection endpoint at all, so an administrator had no way to discover which
accounts existed without already knowing their opaque `user_{uuid4hex}`
identifier. The activity endpoint returned a single hardcoded record with an
invented IP and device string, and ignored its `limit`.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.saas.routes import users as users_routes
from src.saas.routes.auth import get_current_user

# Mirrors tests/test_saas_users_security.py: the router is not mounted on the
# production app, so it is exercised on a router-local one.
app = FastAPI()
app.include_router(users_routes.router)

TENANT = "org_alpha"
OTHER_TENANT = "org_beta"

ADMIN = {"user_id": "u_admin", "organization_id": TENANT, "role": "admin"}
OTHER_ADMIN = {"user_id": "u_admin_b", "organization_id": OTHER_TENANT, "role": "admin"}

STRONG_PASSWORD = "Str0ng!Passw0rd#2026"
LIST_PATH = "/api/v1/users/"


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
    for tenant in (TENANT, OTHER_TENANT):
        users_routes.set_tenant_resource_count(tenant, "max_users", 0)
    _as(ADMIN)
    yield
    users_routes._USER_STORE.clear()
    users_routes._AUDIT_LOG.clear()
    app.dependency_overrides.pop(get_current_user, None)


def _seed(tenant, user_id, email, **overrides):
    """Insert a record directly, bypassing subscription limits."""
    from datetime import datetime, timedelta, timezone

    record = {
        "id": user_id,
        "tenant_id": tenant,
        "email": email,
        "full_name": overrides.get("full_name"),
        "username": overrides.get("username"),
        "phone": None,
        "avatar_url": None,
        "role": overrides.get("role", "member"),
        "is_active": overrides.get("is_active", True),
        "email_verified": overrides.get("email_verified", False),
        "mfa_enabled": overrides.get("mfa_enabled", False),
        "last_login": overrides.get("last_login"),
        "created_at": overrides.get(
            "created_at", datetime.now(timezone.utc) - timedelta(days=1)
        ),
        "password_hash": "x",
    }
    users_routes._USER_STORE[user_id] = record
    return record


class TestEndpointExists:
    def test_listing_endpoint_is_reachable(self, api_client):
        """There was previously no collection endpoint at all."""
        response = api_client.get(LIST_PATH)
        assert response.status_code == 200

    def test_empty_tenant_returns_an_empty_page(self, api_client):
        body = api_client.get(LIST_PATH).json()
        assert body["items"] == []
        assert body["total"] == 0
        assert body["has_more"] is False

    def test_requires_authentication(self, api_client):
        app.dependency_overrides.pop(get_current_user, None)
        assert api_client.get(LIST_PATH).status_code in (401, 403)

    def test_it_does_not_shadow_get_by_id(self, api_client):
        """The literal path must be matched before /{user_id}."""
        _seed(TENANT, "u1", "a@example.com")
        assert api_client.get("/api/v1/users/u1").status_code == 200
        assert api_client.get(LIST_PATH).status_code == 200


class TestTenantScoping:
    def test_only_the_callers_tenant_is_returned(self, api_client):
        _seed(TENANT, "u1", "mine@example.com")
        _seed(OTHER_TENANT, "u2", "theirs@example.com")

        body = api_client.get(LIST_PATH).json()
        assert [u["email"] for u in body["items"]] == ["mine@example.com"]

    def test_the_other_tenant_sees_only_its_own(self, api_client):
        _seed(TENANT, "u1", "mine@example.com")
        _seed(OTHER_TENANT, "u2", "theirs@example.com")

        _as(OTHER_ADMIN)
        body = api_client.get(LIST_PATH).json()
        assert [u["email"] for u in body["items"]] == ["theirs@example.com"]

    def test_caller_without_a_tenant_is_rejected(self, api_client):
        _as({"user_id": "u_stray", "organization_id": None, "role": "admin"})
        assert api_client.get(LIST_PATH).status_code == 401

    def test_a_non_admin_sees_only_their_own_record(self, api_client):
        _seed(TENANT, "u_self", "self@example.com")
        _seed(TENANT, "u_other", "other@example.com")

        _as({"user_id": "u_self", "organization_id": TENANT, "role": "member"})
        body = api_client.get(LIST_PATH).json()
        assert [u["id"] for u in body["items"]] == ["u_self"]
        assert body["total"] == 1


class TestProjection:
    def test_sensitive_fields_are_never_returned(self, api_client):
        _seed(TENANT, "u1", "a@example.com")
        item = api_client.get(LIST_PATH).json()["items"][0]

        assert "password_hash" not in item
        assert "tenant_id" not in item

    def test_expected_fields_are_present(self, api_client):
        _seed(TENANT, "u1", "a@example.com", full_name="Ada L")
        item = api_client.get(LIST_PATH).json()["items"][0]

        assert item["id"] == "u1"
        assert item["email"] == "a@example.com"
        assert item["full_name"] == "Ada L"
        assert item["role"] == "member"


class TestPagination:
    def _seed_many(self, count=10):
        from datetime import datetime, timedelta, timezone

        base = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for i in range(count):
            _seed(
                TENANT,
                f"u{i:02d}",
                f"user{i:02d}@example.com",
                created_at=base + timedelta(days=i),
            )

    def test_first_page_reports_the_full_total(self, api_client):
        self._seed_many(10)
        body = api_client.get(f"{LIST_PATH}?page=1&page_size=3").json()

        assert len(body["items"]) == 3
        assert body["total"] == 10
        assert body["has_more"] is True

    def test_last_page_reports_no_more(self, api_client):
        self._seed_many(10)
        body = api_client.get(f"{LIST_PATH}?page=4&page_size=3").json()

        assert len(body["items"]) == 1
        assert body["has_more"] is False

    def test_page_beyond_the_end_is_empty_with_a_correct_total(self, api_client):
        self._seed_many(5)
        body = api_client.get(f"{LIST_PATH}?page=99&page_size=10").json()

        assert body["items"] == []
        assert body["total"] == 5
        assert body["has_more"] is False

    def test_pages_do_not_overlap_or_skip(self, api_client):
        self._seed_many(10)
        seen = []
        for page in range(1, 5):
            body = api_client.get(f"{LIST_PATH}?page={page}&page_size=3").json()
            seen.extend(u["id"] for u in body["items"])

        assert len(seen) == 10
        assert len(set(seen)) == 10

    def test_ordering_is_stable_across_identical_sort_values(self, api_client):
        from datetime import datetime, timezone

        # Every record shares a created_at, so only the id tiebreak orders them.
        same = datetime(2026, 5, 1, tzinfo=timezone.utc)
        for i in range(6):
            _seed(TENANT, f"u{i}", f"u{i}@example.com", created_at=same)

        first = [u["id"] for u in api_client.get(f"{LIST_PATH}?page_size=3").json()["items"]]
        second = [u["id"] for u in api_client.get(f"{LIST_PATH}?page_size=3").json()["items"]]
        assert first == second

    def test_page_size_bounds_are_enforced(self, api_client):
        assert api_client.get(f"{LIST_PATH}?page_size=0").status_code == 422
        assert api_client.get(f"{LIST_PATH}?page_size=101").status_code == 422
        assert api_client.get(f"{LIST_PATH}?page_size=100").status_code == 200

    def test_page_must_be_positive(self, api_client):
        assert api_client.get(f"{LIST_PATH}?page=0").status_code == 422


class TestFiltering:
    def test_filter_by_role(self, api_client):
        _seed(TENANT, "u1", "a@example.com", role="admin")
        _seed(TENANT, "u2", "b@example.com", role="member")

        body = api_client.get(f"{LIST_PATH}?role=admin").json()
        assert [u["id"] for u in body["items"]] == ["u1"]

    def test_role_filter_is_case_insensitive(self, api_client):
        _seed(TENANT, "u1", "a@example.com", role="admin")
        assert api_client.get(f"{LIST_PATH}?role=ADMIN").json()["total"] == 1

    def test_filter_by_is_active(self, api_client):
        _seed(TENANT, "u1", "a@example.com", is_active=True)
        _seed(TENANT, "u2", "b@example.com", is_active=False)

        assert api_client.get(f"{LIST_PATH}?is_active=false").json()["total"] == 1
        assert api_client.get(f"{LIST_PATH}?is_active=true").json()["total"] == 1

    def test_filter_by_email_verified(self, api_client):
        _seed(TENANT, "u1", "a@example.com", email_verified=True)
        _seed(TENANT, "u2", "b@example.com", email_verified=False)

        body = api_client.get(f"{LIST_PATH}?email_verified=false").json()
        assert [u["id"] for u in body["items"]] == ["u2"]

    def test_filter_by_mfa_enabled(self, api_client):
        _seed(TENANT, "u1", "a@example.com", mfa_enabled=False)
        _seed(TENANT, "u2", "b@example.com", mfa_enabled=True)

        body = api_client.get(f"{LIST_PATH}?mfa_enabled=true").json()
        assert [u["id"] for u in body["items"]] == ["u2"]

    def test_filters_combine(self, api_client):
        _seed(TENANT, "u1", "a@example.com", role="admin", is_active=True)
        _seed(TENANT, "u2", "b@example.com", role="admin", is_active=False)

        body = api_client.get(f"{LIST_PATH}?role=admin&is_active=true").json()
        assert [u["id"] for u in body["items"]] == ["u1"]

    def test_no_filters_returns_everything(self, api_client):
        _seed(TENANT, "u1", "a@example.com")
        _seed(TENANT, "u2", "b@example.com")
        assert api_client.get(LIST_PATH).json()["total"] == 2


class TestSearch:
    def test_matches_email(self, api_client):
        _seed(TENANT, "u1", "ada@example.com")
        _seed(TENANT, "u2", "bob@example.com")

        body = api_client.get(f"{LIST_PATH}?search=ada").json()
        assert [u["id"] for u in body["items"]] == ["u1"]

    def test_matches_username(self, api_client):
        _seed(TENANT, "u1", "a@example.com", username="lovelace")
        _seed(TENANT, "u2", "b@example.com", username="turing")

        body = api_client.get(f"{LIST_PATH}?search=turing").json()
        assert [u["id"] for u in body["items"]] == ["u2"]

    def test_matches_full_name(self, api_client):
        _seed(TENANT, "u1", "a@example.com", full_name="Ada Lovelace")
        body = api_client.get(f"{LIST_PATH}?search=lovelace").json()
        assert body["total"] == 1

    def test_is_case_insensitive(self, api_client):
        _seed(TENANT, "u1", "Ada@Example.com", full_name="Ada Lovelace")
        assert api_client.get(f"{LIST_PATH}?search=ADA").json()["total"] == 1

    def test_handles_records_with_null_optional_fields(self, api_client):
        _seed(TENANT, "u1", "a@example.com", full_name=None, username=None)
        assert api_client.get(f"{LIST_PATH}?search=nothing").json()["total"] == 0
        assert api_client.get(f"{LIST_PATH}?search=a@example").json()["total"] == 1

    def test_unicode_search_terms_are_handled(self, api_client):
        _seed(TENANT, "u1", "jose@example.com", full_name="José Álvarez")
        assert api_client.get(f"{LIST_PATH}?search=josé").json()["total"] == 1

    def test_no_match_returns_empty(self, api_client):
        _seed(TENANT, "u1", "a@example.com")
        body = api_client.get(f"{LIST_PATH}?search=zzzz").json()
        assert body["items"] == []
        assert body["total"] == 0

    def test_whitespace_only_search_is_ignored(self, api_client):
        _seed(TENANT, "u1", "a@example.com")
        assert api_client.get(f"{LIST_PATH}?search=%20%20").json()["total"] == 1

    def test_search_stays_within_the_tenant(self, api_client):
        _seed(TENANT, "u1", "ada@example.com")
        _seed(OTHER_TENANT, "u2", "ada@other.com")

        body = api_client.get(f"{LIST_PATH}?search=ada").json()
        assert [u["id"] for u in body["items"]] == ["u1"]


class TestSorting:
    def _seed_pair(self):
        from datetime import datetime, timezone

        _seed(
            TENANT, "u1", "zulu@example.com",
            full_name="Zoe", role="member",
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        _seed(
            TENANT, "u2", "alpha@example.com",
            full_name="Ada", role="admin",
            created_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
        )

    @pytest.mark.parametrize(
        "field", ["created_at", "email", "full_name", "role", "last_login"]
    )
    def test_every_allowed_field_sorts_in_both_directions(self, api_client, field):
        self._seed_pair()

        ascending = api_client.get(f"{LIST_PATH}?sort_by={field}&sort_order=asc")
        descending = api_client.get(f"{LIST_PATH}?sort_by={field}&sort_order=desc")

        assert ascending.status_code == 200
        assert descending.status_code == 200
        assert [u["id"] for u in ascending.json()["items"]] == list(
            reversed([u["id"] for u in descending.json()["items"]])
        )

    def test_sort_by_email_ascending(self, api_client):
        self._seed_pair()
        body = api_client.get(f"{LIST_PATH}?sort_by=email&sort_order=asc").json()
        assert [u["email"] for u in body["items"]] == [
            "alpha@example.com",
            "zulu@example.com",
        ]

    def test_sort_by_created_at_descending(self, api_client):
        self._seed_pair()
        body = api_client.get(f"{LIST_PATH}?sort_by=created_at&sort_order=desc").json()
        assert [u["id"] for u in body["items"]] == ["u2", "u1"]

    def test_a_disallowed_sort_field_is_rejected(self, api_client):
        """An allow-list, rather than interpolating caller input."""
        response = api_client.get(f"{LIST_PATH}?sort_by=password_hash")
        assert response.status_code == 422

    def test_an_invalid_sort_order_is_rejected(self, api_client):
        assert api_client.get(f"{LIST_PATH}?sort_order=sideways").status_code == 422

    def test_records_missing_the_sort_field_sort_last(self, api_client):
        from datetime import datetime, timezone

        _seed(TENANT, "u1", "a@example.com", last_login=None)
        _seed(
            TENANT, "u2", "b@example.com",
            last_login=datetime(2026, 3, 1, tzinfo=timezone.utc),
        )

        body = api_client.get(f"{LIST_PATH}?sort_by=last_login&sort_order=asc").json()
        assert [u["id"] for u in body["items"]] == ["u2", "u1"]


class TestActivity:
    def test_activity_reflects_real_recorded_events(self, api_client):
        _seed(TENANT, "u1", "a@example.com")
        users_routes._audit("user_updated", "u_admin", TENANT, "u1")
        users_routes._audit("user_deactivated", "u_admin", TENANT, "u1")

        body = api_client.get("/api/v1/users/u1/activity").json()
        assert body["total"] == 2
        # Newest first.
        assert [a["action"] for a in body["activities"]] == [
            "user_deactivated",
            "user_updated",
        ]

    def test_no_history_returns_an_empty_list_not_a_fabricated_record(self, api_client):
        _seed(TENANT, "u1", "a@example.com")
        body = api_client.get("/api/v1/users/u1/activity").json()

        assert body["activities"] == []
        assert body["total"] == 0

    def test_the_invented_login_record_is_gone(self, api_client):
        _seed(TENANT, "u1", "a@example.com")
        body = api_client.get("/api/v1/users/u1/activity").json()

        serialised = str(body)
        assert "192.168.1.1" not in serialised
        assert "Chrome on Windows" not in serialised

    def test_limit_is_honoured(self, api_client):
        _seed(TENANT, "u1", "a@example.com")
        for _ in range(5):
            users_routes._audit("user_updated", "u_admin", TENANT, "u1")

        body = api_client.get("/api/v1/users/u1/activity?limit=2").json()
        assert len(body["activities"]) == 2
        # total counts everything recorded, not just the page.
        assert body["total"] == 5

    def test_limit_bounds_are_enforced(self, api_client):
        _seed(TENANT, "u1", "a@example.com")
        assert api_client.get("/api/v1/users/u1/activity?limit=0").status_code == 422
        assert api_client.get("/api/v1/users/u1/activity?limit=501").status_code == 422

    def test_activity_is_scoped_to_the_target_user(self, api_client):
        _seed(TENANT, "u1", "a@example.com")
        _seed(TENANT, "u2", "b@example.com")
        users_routes._audit("user_updated", "u_admin", TENANT, "u2")

        assert api_client.get("/api/v1/users/u1/activity").json()["total"] == 0

    def test_activity_is_scoped_to_the_tenant(self, api_client):
        _seed(TENANT, "u1", "a@example.com")
        users_routes._audit("user_updated", "u_admin", OTHER_TENANT, "u1")

        assert api_client.get("/api/v1/users/u1/activity").json()["total"] == 0

    def test_cross_tenant_activity_is_not_found(self, api_client):
        _seed(TENANT, "u1", "a@example.com")
        _as(OTHER_ADMIN)
        assert api_client.get("/api/v1/users/u1/activity").status_code == 404


class TestAuditRetention:
    def test_the_audit_log_is_bounded(self):
        assert users_routes._AUDIT_LOG.maxlen == users_routes._AUDIT_LOG_CAPACITY

    def test_it_evicts_rather_than_growing(self):
        capacity = users_routes._AUDIT_LOG.maxlen
        for i in range(capacity + 25):
            users_routes._audit(f"action_{i}", "actor", TENANT, "u1")

        assert len(users_routes._AUDIT_LOG) == capacity
        assert users_routes._AUDIT_LOG[-1]["action"] == f"action_{capacity + 24}"
