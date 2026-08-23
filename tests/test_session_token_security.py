"""Regression tests for TC-ECE06C9F — predictable session tokens.

Invariant under test: a valid session token must NOT be computable from public,
trivially-enumerable information (a small sequential account id). A person who
never supplies the victim's password must not gain access to the victim's
account by presenting a guessed ``token-<id>`` bearer token.

The tests drive the Flask app in-process via its test client; no live server or
seeded database is needed — the app seeds its users in memory at import time.
"""
import pytest

# Mirrors the seeded accounts in app.USERS. Victims are addressed only by their
# PUBLIC, enumerable ids — never by any token the app hands back.
SEEDED = {
    "alice": {"id": 1, "password": "alice-pw"},
    "bob": {"id": 2, "password": "bob-pw"},
    "admin": {"id": 3, "password": "admin-pw"},
}


def login(client, username):
    resp = client.post(
        "/login",
        json={"username": username, "password": SEEDED[username]["password"]},
    )
    assert resp.status_code == 200, (
        f"login for {username!r} failed: {resp.status_code} {resp.data!r}"
    )
    return resp.get_json()["token"]


@pytest.mark.parametrize("victim", ["bob", "admin"])
def test_guessed_token_cannot_impersonate_account(client, victim):
    """A token guessed as ``token-<public id>`` must be rejected (401), even
    after the victim has an active session from normal login."""
    victim_id = SEEDED[victim]["id"]

    # Victim logged in normally, so their real session is live in the store.
    login(client, victim)

    # The attacker knows ONLY the victim's public id and computes the
    # historically-predictable token from it. It must not validate.
    guessed = f"token-{victim_id}"
    resp = client.get(
        f"/accounts/{victim_id}",
        headers={"Authorization": f"Bearer {guessed}"},
    )
    assert resp.status_code == 401, (
        f"guessed token {guessed!r} was accepted ({resp.status_code}) — session "
        f"tokens are predictable and allow account takeover without credentials"
    )


def test_issued_token_is_not_derived_from_account_id(client):
    """A token minted by a real login must not equal the guessable
    ``token-<id>`` value and must carry meaningful entropy."""
    for username, meta in SEEDED.items():
        token = login(client, username)
        assert token != f"token-{meta['id']}", (
            f"login for {username!r} returned the predictable token {token!r}"
        )
        # A high-entropy secret is substantially longer than ``token-<id>``.
        assert len(token) >= 16, (
            f"token {token!r} for {username!r} is too short to be unguessable"
        )


# --- Positive controls: prove the reds above are the invariant, not a broken
#     environment. These pass both before and after the fix. -------------------


def test_real_login_token_grants_access(client):
    """Baseline-up control: a genuinely issued token still reads its account."""
    token = login(client, "alice")
    resp = client.get(
        "/accounts/1", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200
    assert resp.get_json()["username"] == "alice"


def test_random_unissued_token_rejected(client):
    """Baseline-down control: an opaque, never-issued token is rejected."""
    resp = client.get(
        "/accounts/1",
        headers={"Authorization": "Bearer opaque-random-never-issued-6f3a9c1e"},
    )
    assert resp.status_code == 401
