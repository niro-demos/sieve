"""
Regression test: session tokens issued by POST /login must not be guessable
from a user's account id.

Invariant under test (see niro finding TC-D3DE8A98): an attacker who never
authenticated must not be able to compute another user's valid session token
-- including the administrator's -- from their small sequential account id,
and use it to read that account via GET /accounts/<id>.

Prior to the fix, app.py generated `token = f"token-{user['id']}"`, so once a
real user logged in once (seeding TOKENS), anyone could compute `token-<id>`
for any small integer id and be treated as that user -- with no login, no
password, and no expiry.
"""
import re

import pytest

import app as app_module


@pytest.fixture
def client():
    # Each test gets a clean in-memory token store so tests don't leak state
    # into each other (app.py's TOKENS/USERS are module-level globals).
    app_module.TOKENS.clear()
    app_module.app.config.update(TESTING=True)
    with app_module.app.test_client() as c:
        yield c
    app_module.TOKENS.clear()


def login(client, username, password):
    resp = client.post("/login", json={"username": username, "password": password})
    assert resp.status_code == 200, f"setup failed: could not log in as {username}: {resp.status_code} {resp.get_json()}"
    return resp.get_json()["token"]


def test_guessed_token_from_account_id_is_rejected(client):
    """
    Core invariant: once alice, bob, and the admin have each logged in once
    (normal server state), an unauthenticated attacker who never called
    /login must not be able to compute a working token from the victim's
    account id.
    """
    # --- Setup: seed normal server state, exactly like real users would.
    real_token_alice = login(client, "alice", "alice-pw")
    login(client, "bob", "bob-pw")
    real_token_admin = login(client, "admin", "admin-pw")

    # --- Positive control: alice's own legitimately-issued token works on
    # her own account. Proves the environment/app is healthy.
    resp = client.get("/accounts/1", headers={"Authorization": f"Bearer {real_token_alice}"})
    assert resp.status_code == 200
    assert resp.get_json()["username"] == "alice"

    # --- Attack: compute the legacy predictable pattern token-<id> for the
    # admin account (id=3) with zero knowledge of the admin password, and
    # try to use it as an unauthenticated attacker would.
    guessed_admin_token = f"token-{3}"
    resp = client.get("/accounts/3", headers={"Authorization": f"Bearer {guessed_admin_token}"})
    assert resp.status_code == 401, (
        "VULNERABLE: guessed token derived from account id granted access to the "
        f"admin account: {resp.status_code} {resp.get_json()}"
    )

    # --- Negative control: a random garbage token must also be rejected,
    # confirming auth is not simply disabled.
    resp = client.get("/accounts/1", headers={"Authorization": "Bearer garbage-token-xyz"})
    assert resp.status_code == 401

    # The real admin token must still work for the admin -- the fix must not
    # break legitimate authenticated access.
    resp = client.get("/accounts/3", headers={"Authorization": f"Bearer {real_token_admin}"})
    assert resp.status_code == 200
    assert resp.get_json()["username"] == "admin"


def test_issued_tokens_are_not_derived_from_account_id(client):
    """
    Stronger structural check: the token issued at login must not follow the
    predictable `token-<id>` shape at all, and must carry real entropy
    (long, random, unique per login) so it can't be recomputed from a
    disclosed/enumerable account id.
    """
    token = login(client, "alice", "alice-pw")

    assert not re.fullmatch(r"token-\d+", token), (
        f"token is still derived from a predictable id pattern: {token!r}"
    )
    # Enough entropy that it isn't practically guessable/enumerable.
    assert len(token) >= 32

    # Logging in again must not reissue the same deterministic value.
    token2 = login(client, "alice", "alice-pw")
    assert token != token2, "token must be freshly random on each login, not derived from stable data"
