"""Regression test for GET /admin/users authentication and authorization.

Invariant under test: an unauthenticated caller, or an authenticated caller
who is not an admin, must not be able to retrieve the full user directory
(plaintext passwords, emails, balances, and admin flags). Only a caller
holding a valid bearer token for an account with admin=True may do so.
"""
import pytest

import app as app_module


@pytest.fixture
def client():
    app_module.app.testing = True
    # Module-level TOKENS is shared state; isolate it per test so sessions
    # created by one test can't leak into another.
    saved_tokens = dict(app_module.TOKENS)
    app_module.TOKENS.clear()
    with app_module.app.test_client() as test_client:
        yield test_client
    app_module.TOKENS.clear()
    app_module.TOKENS.update(saved_tokens)


def login(client, username, password):
    resp = client.post("/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()["token"]


def test_unauthenticated_request_is_rejected(client):
    # Positive control: a comparable, already-protected endpoint rejects the
    # same unauthenticated caller. This proves the app's auth mechanism
    # works in general, so a failure below is isolated to /admin/users and
    # not a broken test environment.
    control = client.get("/accounts/1")
    assert control.status_code == 401

    resp = client.get("/admin/users")
    assert resp.status_code in (401, 403)
    body = resp.get_json() or {}
    assert "users" not in body, (
        f"unauthenticated caller must not receive the user directory, got: {body}"
    )


def test_non_admin_token_is_rejected(client):
    token = login(client, "alice", "alice-pw")

    resp = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 403
    body = resp.get_json() or {}
    assert "users" not in body, (
        f"non-admin caller must not receive the user directory, got: {body}"
    )


def test_admin_token_is_accepted(client):
    token = login(client, "admin", "admin-pw")

    resp = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 200
    body = resp.get_json()
    assert "alice" in body["users"]
    assert "admin" in body["users"]
