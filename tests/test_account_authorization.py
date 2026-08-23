"""Regression tests for object-level authorization on GET /accounts/<id>.

Invariant under test:
    A logged-in user may only view their OWN account. Requesting an account
    they do not own must be denied (403/404) and must never disclose another
    user's private record (email, balance). Admins may read any account.

These tests drive the Flask app via its native test client (no live server
needed). The app seeds its users in-memory at import time, so we recreate the
PoC's actors (alice, bob, admin) by logging in through the app itself.
"""
import pytest

from app import app as flask_app
from app import TOKENS


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    TOKENS.clear()  # isolate token state between tests
    with flask_app.test_client() as c:
        yield c
    TOKENS.clear()


def login(client, username, password):
    resp = client.post("/login", json={"username": username, "password": password})
    assert resp.status_code == 200, f"login for {username} failed: {resp.status_code} {resp.data!r}"
    return resp.get_json()["token"]


# --- Positive control: the legitimate owner keeps working (stays green) -------

def test_owner_can_read_own_account(client):
    token = login(client, "alice", "alice-pw")
    resp = client.get("/accounts/1", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["username"] == "alice"
    assert body["email"] == "alice@sieve.test"


# --- The invariant: no cross-account reads (RED before the fix) ---------------

@pytest.mark.parametrize(
    "requester_user, requester_pw, victim_id, victim_email",
    [
        ("alice", "alice-pw", 2, "bob@sieve.test"),    # alice must not read bob
        ("bob", "bob-pw", 1, "alice@sieve.test"),      # bob must not read alice
        ("alice", "alice-pw", 3, "admin@sieve.test"),  # alice must not read admin
    ],
)
def test_user_cannot_read_other_users_account(
    client, requester_user, requester_pw, victim_id, victim_email
):
    token = login(client, requester_user, requester_pw)
    resp = client.get(
        f"/accounts/{victim_id}", headers={"Authorization": f"Bearer {token}"}
    )
    # Ownership must be enforced: deny with 403 (or 404), never disclose.
    assert resp.status_code in (403, 404), (
        f"{requester_user} read account {victim_id}: expected 403/404, "
        f"got {resp.status_code} {resp.data!r}"
    )
    assert victim_email.encode() not in resp.data, (
        f"{requester_user} was disclosed {victim_id}'s private record"
    )


# --- Admins keep full read access (preserved behavior) -----------------------

@pytest.mark.parametrize("account_id, expected_username", [(1, "alice"), (2, "bob"), (3, "admin")])
def test_admin_can_read_any_account(client, account_id, expected_username):
    token = login(client, "admin", "admin-pw")
    resp = client.get(
        f"/accounts/{account_id}", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200
    assert resp.get_json()["username"] == expected_username


# --- Preserved auth/not-found behavior ---------------------------------------

def test_unauthenticated_request_rejected(client):
    resp = client.get("/accounts/1")
    assert resp.status_code == 401


def test_invalid_token_rejected(client):
    resp = client.get("/accounts/1", headers={"Authorization": "Bearer not-a-real-token"})
    assert resp.status_code == 401


def test_nonexistent_account_returns_404(client):
    token = login(client, "alice", "alice-pw")
    resp = client.get("/accounts/999", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 404
