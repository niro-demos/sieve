"""Regression tests for object-level authorization on GET /accounts/<id>.

Guards the invariant: a signed-in standard user must not be able to read
another user's account record (email, balance) by changing the id in the URL.

These tests are self-contained: they drive the Flask app in-process via
`app.test_client()` and do not depend on any running container. They make no
assumption about the bearer-token string format — each test logs in and uses
whatever token the login endpoint returns.
"""
import os
import sys

import pytest

# Make the app at the repository root importable regardless of pytest's cwd.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, USERS  # noqa: E402


def _login(client, username):
    """Log in as `username` using the app's own seeded credentials and return
    the issued token. Reads the password from the imported USERS table so the
    test embeds no credentials and stays valid if seed values change."""
    resp = client.post(
        "/login",
        json={"username": username, "password": USERS[username]["password"]},
    )
    assert resp.status_code == 200, f"login for {username} failed: {resp.status_code}"
    token = resp.get_json()["token"]
    assert token, f"login for {username} returned no token"
    return token


@pytest.fixture
def client():
    app.config.update(TESTING=True)
    return app.test_client()


def test_owner_can_read_own_account(client):
    """Positive control: alice (id 1) reading her own account still works."""
    token = _login(client, "alice")
    resp = client.get("/accounts/1", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["id"] == 1
    assert body["username"] == "alice"
    assert body["email"] == USERS["alice"]["email"]
    assert body["balance"] == USERS["alice"]["balance"]


def test_standard_user_cannot_read_other_accounts(client):
    """Core regression: alice's token must NOT read bob (id 2) or admin (id 3).

    Pre-fix these return HTTP 200 with the other users' email and balance, so
    these assertions fail and expose the BOLA/IDOR bug. Post-fix they return
    403 and no victim data is disclosed."""
    token = _login(client, "alice")
    for victim_id in (2, 3):
        resp = client.get(
            f"/accounts/{victim_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403, (
            f"standard user alice read /accounts/{victim_id} -> "
            f"{resp.status_code} (expected 403); body={resp.get_data(as_text=True)}"
        )
        # Defense-in-depth: even on an unexpected status, no victim PII leaks.
        body = resp.get_json(silent=True) or {}
        assert "email" not in body
        assert "balance" not in body


def test_admin_can_read_any_account(client):
    """Admin bypass positive control: admin may read someone else's account."""
    token = _login(client, "admin")
    resp = client.get("/accounts/1", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["id"] == 1
    assert body["username"] == "alice"


def test_missing_token_is_unauthorized(client):
    """Authentication must still be enforced: no token -> 401."""
    resp = client.get("/accounts/2")
    assert resp.status_code == 401
