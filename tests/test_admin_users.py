"""
Regression test for TC-B2EF2592: unauthenticated `GET /admin/users` must not
leak the user directory (and no caller, admin or not, should ever receive
plaintext passwords in that response).

Invariant under test (from the finding): only administrators may view the
full list of user accounts, and even then the response must not contain
plaintext passwords. A visitor with no session at all, and a logged-in
non-admin user, must be rejected.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from app import TOKENS, app


@pytest.fixture
def client():
    TOKENS.clear()
    with app.test_client() as c:
        yield c


def login(client, username, password):
    resp = client.post("/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()["token"]


def test_unauthenticated_request_is_rejected_and_leaks_nothing(client):
    resp = client.get("/admin/users")

    assert resp.status_code in (401, 403)
    body = resp.get_json() or {}
    assert "users" not in body
    assert "admin-pw" not in resp.get_data(as_text=True)


def test_non_admin_user_is_rejected_and_leaks_nothing(client):
    token = login(client, "alice", "alice-pw")

    resp = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code in (401, 403)
    body = resp.get_json() or {}
    assert "users" not in body
    assert "admin-pw" not in resp.get_data(as_text=True)


def test_admin_user_can_list_users_without_plaintext_passwords(client):
    token = login(client, "admin", "admin-pw")

    resp = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 200
    body = resp.get_json()
    users = body["users"]
    assert set(users) == {"alice", "bob", "admin"}
    for record in users.values():
        assert "password" not in record


def test_control_accounts_endpoint_still_requires_auth(client):
    # Positive control: the sibling endpoint's auth gate is untouched by
    # this fix, so an unauthenticated request must still be rejected.
    resp = client.get("/accounts/1")

    assert resp.status_code == 401


def test_control_authenticated_account_lookup_still_works(client):
    # Legitimate, previously-working behavior must be preserved: a valid
    # bearer token still grants access to the caller's own account details.
    token = login(client, "alice", "alice-pw")

    resp = client.get("/accounts/1", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["username"] == "alice"
    assert body["balance"] == 100
