"""Regression tests for session-token issuance in POST /login.

Security invariant under test:
    A session token issued by the sign-in endpoint must not be predictable or
    constructible by an actor who has not authenticated as that user. Only a
    successful login as a specific account may yield a token that grants access
    to it.

These tests run against the app's own Flask test client (no live server, no
seeded harness DB). The seeded USERS dict in app.py is the app's in-memory
"database", so we drive it directly — mirroring the PoC scenario (attacker
=> alice/id 1, victim => bob/id 2) with the project's own data.
"""
import re

import pytest

import app as sieve


@pytest.fixture
def client():
    sieve.app.config["TESTING"] = True
    # Isolate token state between tests so one login can't leak into another.
    sieve.TOKENS.clear()
    with sieve.app.test_client() as c:
        yield c
    sieve.TOKENS.clear()


def _login(client, username, password):
    return client.post("/login", json={"username": username, "password": password})


def test_login_issues_unpredictable_token():
    """The issued token must not be a deterministic function of the user id."""
    with sieve.app.test_client() as c:
        sieve.TOKENS.clear()
        resp = _login(c, "alice", "alice-pw")
        assert resp.status_code == 200
        token = resp.get_json()["token"]
        alice_id = sieve.USERS["alice"]["id"]

        # The old flaw: token == f"token-{id}". A secure token must not equal
        # the id-derived string, must not contain the bare id, and must carry
        # enough entropy to be unguessable.
        assert token != f"token-{alice_id}"
        assert not re.fullmatch(r"token-\d+", token), (
            f"token {token!r} is an id-derived, predictable string"
        )
        assert len(token) >= 20, f"token {token!r} is too short to be unguessable"


def test_forged_id_based_token_is_rejected(client):
    """An attacker who guesses `token-<victim id>` must not gain access.

    Reproduces the finding: attacker (alice) authenticates once, the victim
    (bob) has an active session, and the attacker constructs bob's token by
    substituting the sequential id — never proving bob's credentials.
    """
    # Attacker logs in legitimately (precondition: any working login).
    attacker_login = _login(client, "alice", "alice-pw")
    assert attacker_login.status_code == 200

    # Victim has signed in at least once (their session exists server-side).
    victim_login = _login(client, "bob", "bob-pw")
    assert victim_login.status_code == 200

    victim_id = sieve.USERS["bob"]["id"]
    forged_token = f"token-{victim_id}"  # the attacker's guess

    resp = client.get(
        f"/accounts/{victim_id}",
        headers={"Authorization": f"Bearer {forged_token}"},
    )
    # INVARIANT: a merely-predicted token must be rejected, never grant access
    # to the victim's private account record.
    assert resp.status_code == 401, (
        "predicted id-based token was accepted -> account takeover "
        f"(got {resp.status_code}: {resp.get_json()!r})"
    )


def test_legitimate_token_still_works(client):
    """Control: a token issued by a real login grants access to that account.

    Proves the 401 above is the invariant firing, not a broken auth gate.
    """
    login = _login(client, "bob", "bob-pw")
    assert login.status_code == 200
    token = login.get_json()["token"]

    resp = client.get(
        f"/accounts/{sieve.USERS['bob']['id']}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.get_json()["username"] == "bob"


def test_garbage_token_rejected(client):
    """Control: an unissued token is rejected (auth gate is healthy)."""
    resp = client.get("/accounts/1", headers={"Authorization": "Bearer nope"})
    assert resp.status_code == 401
