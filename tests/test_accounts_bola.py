"""Regression tests for object-level authorization on GET /accounts/<id>.

These reproduce a broken object-level authorization (BOLA / IDOR) flaw where
any signed-in user could read any account's private details (email + balance)
simply by changing the account id in the URL.

Expected behavior:
  * A signed-in user may read their OWN account (200, positive control).
  * A signed-in user may NOT read another user's account (403, no data leak).
  * Authentication is still required (missing token -> 401).
  * An admin may read any account (self-and-any access).

Against the unfixed handler the cross-account cases return 200 with the other
account's private data, so `test_user_cannot_read_*` fail. After enforcing
ownership they return 403 and pass.
"""
import os
import sys

# Make the application importable regardless of how pytest is invoked.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import app as sieve


@pytest.fixture
def client():
    sieve.app.config["TESTING"] = True
    sieve.TOKENS.clear()  # isolate token state between tests
    with sieve.app.test_client() as test_client:
        yield test_client
    sieve.TOKENS.clear()


def _login(client, username, password):
    resp = client.post("/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return resp.get_json()["token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_owner_can_read_own_account(client):
    """(a) Positive control: alice (owns id 1) reads her own account -> 200."""
    token = _login(client, "alice", "alice-pw")
    resp = client.get("/accounts/1", headers=_auth(token))
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["id"] == 1
    assert body["username"] == "alice"
    assert body["email"] == "alice@sieve.test"


def test_user_cannot_read_another_users_account(client):
    """(b) alice must NOT read bob's account (id 2) -> 403, no data leak.

    Fails on unfixed code (200 with bob's email/balance).
    """
    token = _login(client, "alice", "alice-pw")
    resp = client.get("/accounts/2", headers=_auth(token))
    assert resp.status_code == 403
    body = resp.get_json()
    assert "email" not in body
    assert "balance" not in body


def test_user_cannot_read_admin_account(client):
    """(b) alice must NOT read the admin account (id 3) -> 403, no data leak.

    Fails on unfixed code (200 with admin's email/balance).
    """
    token = _login(client, "alice", "alice-pw")
    resp = client.get("/accounts/3", headers=_auth(token))
    assert resp.status_code == 403
    body = resp.get_json()
    assert "email" not in body
    assert "balance" not in body


def test_unauthenticated_request_is_rejected(client):
    """(c) No token -> 401; authentication is still enforced (not 403)."""
    resp = client.get("/accounts/2")
    assert resp.status_code == 401


def test_admin_can_read_any_account(client):
    """(d) Optional: an admin may read any account -> 200."""
    token = _login(client, "admin", "admin-pw")
    resp = client.get("/accounts/1", headers=_auth(token))
    assert resp.status_code == 200
    assert resp.get_json()["username"] == "alice"


def test_nonexistent_account_still_returns_404(client):
    """Non-existent account id is preserved as 404 for a valid requester."""
    token = _login(client, "alice", "alice-pw")
    resp = client.get("/accounts/999", headers=_auth(token))
    assert resp.status_code == 404
