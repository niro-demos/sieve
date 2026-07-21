"""
Regression tests for Sieve's session-token issuance.

Invariant under test (see the security finding this closes):
  A session token issued by POST /login must not be predictable or
  forgeable -- an attacker who does not know a user's password must not be
  able to derive that user's valid session token just from knowing (or
  guessing) their small integer user id.

The vulnerable implementation minted `token = f"token-{user['id']}"`, so
anyone could compute a valid, non-expiring token for *any* account
(including admin) purely from the account's small sequential id, without
ever knowing that account's password or ever calling /login as that user.
"""
import re

import pytest

import app as app_module


@pytest.fixture
def client():
    app_module.app.config["TESTING"] = True
    # Each test starts from a clean slate regardless of test order.
    app_module.TOKENS.clear()
    with app_module.app.test_client() as c:
        yield c


def login(client, username, password):
    return client.post("/login", json={"username": username, "password": password})


def test_id_derived_token_does_not_grant_access_to_bobs_account(client):
    # Bob (id=2) logs in for real, so a legitimate token exists server-side --
    # but the attacker in this test never observes it.
    bob_login = login(client, "bob", "bob-pw")
    assert bob_login.status_code == 200
    real_bob_token = bob_login.get_json()["token"]

    # The attacker never authenticates as Bob. They only know Bob's user id
    # (2) and the old, deterministic derivation formula `token-{id}`.
    guessed_bob_token = "token-2"
    resp = client.get(
        "/accounts/2", headers={"Authorization": f"Bearer {guessed_bob_token}"}
    )
    assert resp.status_code == 401, (
        "a guessed, id-derived token granted access to Bob's account: "
        f"{resp.get_json()}"
    )

    # Sanity: Bob's real, honestly-issued token still works for his own
    # account -- the fix must not break legitimate auth.
    resp = client.get(
        "/accounts/2", headers={"Authorization": f"Bearer {real_bob_token}"}
    )
    assert resp.status_code == 200
    assert resp.get_json()["id"] == 2

    # The guessed value must not coincide with the real one -- proves the
    # rejection above is due to unpredictability, not a lucky fluke.
    assert guessed_bob_token != real_bob_token


def test_id_derived_token_does_not_grant_access_to_admin_account(client):
    # The real admin logs in elsewhere (e.g. their own legitimate session),
    # so a genuine token for id=3 exists server-side -- but the attacker
    # never observes it and never authenticates as admin themselves.
    admin_login = login(client, "admin", "admin-pw")
    assert admin_login.status_code == 200

    # Full admin account compromise via a guessed token is the highest-value
    # instance of this bug -- attacker never authenticates as admin at all.
    guessed_admin_token = "token-3"
    resp = client.get(
        "/accounts/3", headers={"Authorization": f"Bearer {guessed_admin_token}"}
    )
    assert resp.status_code == 401, (
        "a guessed, id-derived token granted access to the ADMIN account: "
        f"{resp.get_json()}"
    )


def test_token_for_nonexistent_user_id_is_rejected(client):
    # Negative control: this must 401 both before and after the fix, so a
    # regression here would mean the endpoint became a blanket auth bypass
    # rather than specifically fixing id-derivability.
    resp = client.get(
        "/accounts/999", headers={"Authorization": "Bearer token-999"}
    )
    assert resp.status_code == 401


def test_issued_token_is_not_id_derived_and_has_real_entropy(client):
    resp = login(client, "alice", "alice-pw")
    assert resp.status_code == 200
    token = resp.get_json()["token"]

    # The token must not be a thin wrapper around the user id.
    assert not re.fullmatch(r"token-\d+", token), f"token is still id-derived: {token!r}"

    # And it must look like a real random token, not a short/guessable value.
    assert len(token) >= 32, f"token looks low-entropy: {token!r}"
