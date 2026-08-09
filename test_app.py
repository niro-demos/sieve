"""
Regression test for the forgeable-token vulnerability (TC-F5399DC5).

Invariant: an attacker who knows a user's sequential account id must NOT be able
to predict or forge that user's authentication token without the password.

The app seeds users with hardcoded sequential account ids (alice=1, bob=2,
admin=3). On the vulnerable code the issued token is the deterministic
`token-<id>`, so an attacker who learns an id (say admin's, id=3) can forge
`token-3` and read that account with no password, provided the user has logged in
once since server start. After the fix the token is cryptographically random and
unpredictable, so the forged `token-<id>` is rejected.

Controls (stay green on both vulnerable and fixed code) prove any RED is the
invariant, not a broken environment:
  - a real login token still reads the owner's account (auth works), and
  - an unrelated invalid token is still rejected (the auth check exists).
"""
import importlib

import pytest

import app as sieve_app


@pytest.fixture()
def client():
    # Each test starts from a clean token store so logins don't leak across tests.
    sieve_app.TOKENS.clear()
    importlib.reload(sieve_app)
    sieve_app.app.config["TESTING"] = True
    return sieve_app.app.test_client()


def _login(client, username, password):
    resp = client.post("/login", json={"username": username, "password": password})
    assert resp.status_code == 200, f"login({username}) failed: {resp.status_code} {resp.get_data(as_text=True)}"
    return resp.get_json()["token"]


def test_id_derived_token_is_rejected_after_fix(client):
    # admin's account id is the hardcoded sequential value 3 in app.py.
    admin_id = 3

    # The victim (admin) logs in normally with their own credentials, minting an
    # active session. The attacker never sees admin's password.
    _login(client, "admin", "admin-pw")

    # The attacker forges the token from the id ALONE (no password, no login).
    forged = f"token-{admin_id}"  # "token-3" — derived purely from the public id

    # Invariant: the forged, id-derived token MUST be rejected.
    # Vulnerable code accepts it (200); fixed code rejects it (401).
    resp = client.get(f"/accounts/{admin_id}", headers={"Authorization": forged})
    assert resp.status_code == 401, (
        f"INVARIANT VIOLATED: forged id-derived token {forged!r} (no password) "
        f"was accepted with HTTP {resp.status_code}: {resp.get_data(as_text=True)}"
    )


def test_issued_token_is_not_predictable_from_id(client):
    alice_id = 1  # hardcoded sequential id in app.py

    token = _login(client, "alice", "alice-pw")

    # The issued token must not be a deterministic function of the user's id.
    assert token != f"token-{alice_id}", (
        f"token is the predictable token-<id> ({token!r}); it must be unguessable"
    )


def test_each_login_mints_a_fresh_token(client):
    # Two logins of the same user must not reuse a deterministic token.
    first = _login(client, "alice", "alice-pw")
    second = _login(client, "alice", "alice-pw")
    assert first != second, (
        f"login reissued the same token ({first!r}); each login must mint a fresh token"
    )


# --- controls: healthy baseline that must stay green on both red and fixed code ---


def test_control_legitimate_token_reads_own_account(client):
    alice_id = 1  # hardcoded sequential id in app.py
    token = _login(client, "alice", "alice-pw")

    resp = client.get(f"/accounts/{alice_id}", headers={"Authorization": token})
    assert resp.status_code == 200
    assert resp.get_json()["username"] == "alice"


def test_control_invalid_token_is_rejected(client):
    alice_id = 1  # hardcoded sequential id in app.py

    resp = client.get(f"/accounts/{alice_id}", headers={"Authorization": "token-notreal"})
    assert resp.status_code == 401
