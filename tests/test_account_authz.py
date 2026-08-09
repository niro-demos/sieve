"""Regression tests for the GET /accounts/<id> object-level authorization fix
(TC-18CE0316).

Invariant: an authenticated user must not be able to read another user's
account details by requesting that user's account ID. Only the account owner
(or an admin) may read a given account.
"""
import pytest

from app import app, USERS, TOKENS


@pytest.fixture(autouse=True)
def reset_tokens():
    """Each test starts with a clean token store."""
    TOKENS.clear()
    yield
    TOKENS.clear()


@pytest.fixture
def client():
    app.config.update(TESTING=True)
    return app.test_client()


def login(client, username):
    pw = USERS[username]["password"]
    resp = client.post("/login", json={"username": username, "password": pw})
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()["token"]


# --- Authentication boundary (unchanged by the fix) ---


def test_no_token_is_unauthorized(client):
    assert client.get("/accounts/1").status_code == 401


def test_invalid_token_is_unauthorized(client):
    resp = client.get("/accounts/1", headers={"Authorization": "bogus-token"})
    assert resp.status_code == 401


# --- Positive control: owner reads own account ---


def test_owner_reads_own_account(client):
    token = login(client, "alice")
    resp = client.get("/accounts/1", headers={"Authorization": token})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["id"] == 1
    assert body["username"] == "alice"


# --- The invariant: cross-user reads must be denied ---


@pytest.mark.parametrize("account_id", [2, 3])
def test_alice_cannot_read_other_accounts(client, account_id):
    """Alice (account id=1) must not read Bob (id=2) or admin (id=3)."""
    token = login(client, "alice")
    resp = client.get(f"/accounts/{account_id}", headers={"Authorization": token})
    assert resp.status_code in (403, 404), (
        f"Alice's token should not access /accounts/{account_id}, "
        f"got HTTP {resp.status_code} {resp.get_json()}"
    )
    body = resp.get_json()
    # Must not leak the target account's data.
    assert "balance" not in body
    assert "email" not in body


def test_bob_cannot_read_alice_account(client):
    token = login(client, "bob")
    resp = client.get("/accounts/1", headers={"Authorization": token})
    assert resp.status_code in (403, 404)


# --- Admin may still read any account ---


def test_admin_can_read_any_account(client):
    token = login(client, "admin")
    for account_id in (1, 2, 3):
        resp = client.get(f"/accounts/{account_id}", headers={"Authorization": token})
        assert resp.status_code == 200, (
            f"admin should access /accounts/{account_id}, "
            f"got HTTP {resp.status_code}"
        )
