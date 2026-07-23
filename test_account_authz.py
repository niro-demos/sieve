"""Regression tests for object-level authorization on GET /accounts/<id>.

Invariant: a logged-in user may read only their OWN account (email, balance);
an admin may read any account. A non-owner request must be denied (403), and an
unauthenticated request must be rejected (401). It must never return 200 with
another user's record.

These tests drive the Flask app via its native test client (no live server),
recreating the actors the PoC exercised (a standard user, another standard user,
and an admin) from the app's own seeded fixtures.
"""
import app as sieve_app
import pytest


@pytest.fixture
def client():
    sieve_app.app.config["TESTING"] = True
    # Isolate token state per test so runs don't leak into each other.
    sieve_app.TOKENS.clear()
    with sieve_app.app.test_client() as c:
        yield c
    sieve_app.TOKENS.clear()


def _login(client, username, password):
    resp = client.post("/login", json={"username": username, "password": password})
    assert resp.status_code == 200, f"login for {username} failed: {resp.status_code}"
    return resp.get_json()["token"]


def _get_account(client, account_id, token=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.get(f"/accounts/{account_id}", headers=headers)


def test_owner_can_read_own_account(client):
    """Positive control: the legitimate case stays green (alice reads account 1)."""
    token = _login(client, "alice", "alice-pw")
    resp = _get_account(client, 1, token=token)
    assert resp.status_code == 200
    assert resp.get_json()["email"] == "alice@sieve.test"


def test_unauthenticated_read_is_rejected(client):
    """Negative control: no bearer token -> 401 (auth layer intact)."""
    resp = _get_account(client, 2, token=None)
    assert resp.status_code == 401


@pytest.mark.parametrize(
    "victim_id, victim_email",
    [
        (2, "bob@sieve.test"),     # another standard user
        (3, "admin@sieve.test"),   # the admin account
    ],
)
def test_standard_user_cannot_read_other_account(client, victim_id, victim_email):
    """Exploit case: alice's valid token must NOT disclose another account.

    On the unfixed handler this returns 200 with the victim's record; a correct
    handler returns 403 and never leaks the victim's email/balance.
    """
    token = _login(client, "alice", "alice-pw")
    resp = _get_account(client, victim_id, token=token)
    assert resp.status_code == 403, (
        f"cross-account read of account {victim_id} returned {resp.status_code}, "
        f"expected 403 (IDOR/BOLA)"
    )
    body = resp.get_json() or {}
    assert body.get("email") != victim_email, (
        f"account {victim_id}'s record was disclosed to a non-owner"
    )


def test_admin_can_read_any_account(client):
    """An admin may read any account (admin reads alice's and bob's)."""
    token = _login(client, "admin", "admin-pw")
    for account_id, email in ((1, "alice@sieve.test"), (2, "bob@sieve.test")):
        resp = _get_account(client, account_id, token=token)
        assert resp.status_code == 200
        assert resp.get_json()["email"] == email
