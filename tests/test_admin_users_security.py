"""Regression tests for the /admin/users endpoint security fixes.

Covers two invariants:

- TC-CFC97340: an unauthenticated or non-admin user must not retrieve the admin
  user directory via GET /admin/users (401 unauthenticated, 403 non-admin).
- TC-30CB64A6: the application must never return user passwords in any API
  response.

A positive control — an authenticated standard user reading their own account —
is asserted GREEN first so a red result is provably the invariant, not a broken
environment.
"""
import pytest

from app import app, USERS, TOKENS


@pytest.fixture()
def client():
    app.config.update(TESTING=True)
    with app.test_client() as c:
        yield c


def _login(client, username):
    """Log in a seeded user and return their bearer token."""
    password = USERS[username]["password"]
    resp = client.post("/login", json={"username": username, "password": password})
    assert resp.status_code == 200
    return resp.get_json()["token"]


# ---------------------------------------------------------------------------
# Positive control — the legitimate path must keep working.
# ---------------------------------------------------------------------------

def test_positive_control_account_access_works(client):
    """An authenticated standard user can read their own account (no password)."""
    token = _login(client, "alice")
    resp = client.get("/accounts/1", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["id"] == 1
    assert body["email"] == "alice@sieve.test"
    assert "password" not in body


# ---------------------------------------------------------------------------
# TC-CFC97340 — access control on GET /admin/users
# ---------------------------------------------------------------------------

def test_admin_users_rejects_unauthenticated(client):
    """No Authorization header -> 401."""
    resp = client.get("/admin/users")
    assert resp.status_code == 401


def test_admin_users_rejects_invalid_token(client):
    """Invalid bearer token -> 401."""
    resp = client.get("/admin/users", headers={"Authorization": "Bearer garbage"})
    assert resp.status_code == 401


def test_admin_users_rejects_non_admin(client):
    """Valid non-admin token -> 403."""
    token = _login(client, "alice")
    resp = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_admin_users_allows_admin(client):
    """Valid admin token -> 200 with user directory."""
    token = _login(client, "admin")
    resp = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    users = resp.get_json()["users"]
    assert set(users.keys()) == {"alice", "bob", "admin"}


# ---------------------------------------------------------------------------
# TC-30CB64A6 — no plaintext passwords in any API response
# ---------------------------------------------------------------------------

def test_admin_users_response_has_no_passwords(client):
    """Even with a valid admin token, the response must not include passwords."""
    token = _login(client, "admin")
    resp = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    users = resp.get_json()["users"]
    for user in users.values():
        assert "password" not in user
