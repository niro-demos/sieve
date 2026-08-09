"""
Regression tests for Sieve's API.

Covers TC-B080B7F4: GET /accounts/<id> must enforce object-level
authorization — only the account owner (or an admin) may read a given
account, not merely any holder of a valid bearer token.
"""
import pytest

from app import TOKENS, USERS
from app import app as flask_app


@pytest.fixture
def client():
    flask_app.config.update(TESTING=True)
    # Each seeded user always logs in to the same deterministic
    # `token-<id>` value, so clear any tokens minted by a previous test to
    # keep tests independent of run order.
    TOKENS.clear()
    with flask_app.test_client() as client:
        yield client


def login(client, username, password):
    resp = client.post("/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()["token"]


def test_user_can_read_own_account(client):
    """Positive control: a user can always read their own account."""
    token = login(client, "alice", "alice-pw")

    resp = client.get("/accounts/1", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["username"] == "alice"
    assert body["email"] == USERS["alice"]["email"]


def test_user_cannot_read_another_users_account(client):
    """TC-B080B7F4: a non-admin user must not be able to read another
    user's account (email, balance) via GET /accounts/<id>, even with a
    valid token of their own."""
    token = login(client, "alice", "alice-pw")

    resp = client.get("/accounts/2", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code in (403, 404), (
        f"alice must not be able to read bob's account (id=2); got "
        f"{resp.status_code}: {resp.get_json()}"
    )
    body = resp.get_json()
    assert body is None or "balance" not in body


def test_user_cannot_read_admin_account(client):
    """TC-B080B7F4: the same missing check also exposes the admin
    account's data to any authenticated non-admin user."""
    token = login(client, "alice", "alice-pw")

    resp = client.get("/accounts/3", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code in (403, 404), (
        f"alice must not be able to read the admin account (id=3); got "
        f"{resp.status_code}: {resp.get_json()}"
    )
    body = resp.get_json()
    assert body is None or "balance" not in body


def test_admin_can_read_any_account(client):
    """Admins retain full account visibility — the fix must not remove
    legitimate admin access."""
    token = login(client, "admin", "admin-pw")

    resp = client.get("/accounts/1", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 200
    assert resp.get_json()["username"] == "alice"


def test_no_token_is_still_unauthorized(client):
    """Baseline: the pre-existing authentication gate must still work."""
    resp = client.get("/accounts/1")

    assert resp.status_code == 401
