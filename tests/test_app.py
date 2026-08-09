"""
Regression test for TC-E3E2833F — deterministic session tokens allow full
account takeover without credentials.

Invariant under test: session tokens issued at login must not be
predictable. An attacker who has never authenticated as a given user must
not be able to derive that user's valid session token from public
information (their sequential user id) and use it to act as them.

app.py used to mint tokens as f"token-{user['id']}" in login(). Because user
ids are small sequential integers (alice=1, bob=2, admin=3), anyone could
compute another user's exact token without ever knowing their password, as
soon as that user had authenticated once (populating the process-wide
TOKENS map) -- see diagnosis.md in the finding bundle for the full
root-cause note.
"""
import pytest

import app as app_module


@pytest.fixture(autouse=True)
def reset_token_store():
    """Each test gets a clean session-token map, independent of others."""
    app_module.TOKENS.clear()
    yield
    app_module.TOKENS.clear()


@pytest.fixture
def client():
    app_module.app.testing = True
    with app_module.app.test_client() as c:
        yield c


def test_forged_sequential_token_does_not_grant_account_takeover(client):
    # Ambient legitimate activity: bob and admin each log in once elsewhere
    # (as real users routinely do), so their tokens exist in the server-side
    # session store. The attacker below never does this for bob or admin.
    resp = client.post("/login", json={"username": "bob", "password": "bob-pw"})
    assert resp.status_code == 200
    resp = client.post("/login", json={"username": "admin", "password": "admin-pw"})
    assert resp.status_code == 200

    # Negative control: a random, non-guessable bearer token must not grant
    # access. Proves the auth check on /accounts/<id> itself isn't just open.
    resp = client.get(
        "/accounts/2", headers={"Authorization": "Bearer totally-not-a-real-token"}
    )
    assert resp.status_code == 401

    # Positive control: the attacker's one legitimate credential (alice) logs
    # in normally and can read her own account with her own issued token.
    resp = client.post("/login", json={"username": "alice", "password": "alice-pw"})
    assert resp.status_code == 200
    alice_token = resp.get_json()["token"]
    # The token must not itself be the predictable "token-<id>" shape.
    assert alice_token != "token-1"

    resp = client.get("/accounts/1", headers={"Authorization": f"Bearer {alice_token}"})
    assert resp.status_code == 200
    assert resp.get_json()["username"] == "alice"

    # Exploit / invariant: without ever POSTing /login as bob or admin, an
    # attacker who only knows their public, sequential user ids (bob=2,
    # admin=3) must not be able to derive their valid session tokens.
    forged_bob_token = "token-2"
    forged_admin_token = "token-3"

    resp = client.get(
        "/accounts/2", headers={"Authorization": f"Bearer {forged_bob_token}"}
    )
    assert resp.status_code == 401, (
        "forged token derived from bob's public id was accepted -- "
        f"session tokens are predictable (body={resp.get_json()})"
    )

    resp = client.get(
        "/accounts/3", headers={"Authorization": f"Bearer {forged_admin_token}"}
    )
    assert resp.status_code == 401, (
        "forged token derived from admin's public id was accepted -- "
        f"full unauthenticated admin takeover via predictable tokens "
        f"(body={resp.get_json()})"
    )


def test_login_still_works_and_issues_usable_token(client):
    """Legitimate login must keep working and the issued token must grant
    access to exactly the caller's own account (no regression to normal
    auth flow from the token-generation fix)."""
    resp = client.post("/login", json={"username": "alice", "password": "alice-pw"})
    assert resp.status_code == 200
    token = resp.get_json()["token"]
    assert isinstance(token, str) and token != ""

    resp = client.get("/accounts/1", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body == {
        "id": 1,
        "username": "alice",
        "email": "alice@sieve.test",
        "balance": 100,
    }


def test_invalid_credentials_are_rejected(client):
    resp = client.post(
        "/login", json={"username": "alice", "password": "wrong-password"}
    )
    assert resp.status_code == 401
    assert "token" not in resp.get_json()
