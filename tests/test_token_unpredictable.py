"""Regression test: session tokens must be unguessable.

Security invariant
------------------
An attacker must not be able to obtain a working session for another user by
guessing the session token.

Background
----------
The login handler previously minted tokens as the deterministic string
``token-<user id>``. Because the id is a small sequential integer, anyone could
forge a logged-in victim's session by guessing ``token-<id>`` -- no credentials
required. This test reproduces that forgery entirely in-process using Flask's
test client (no live container needed):

* The victim (bob, id 2) logs in normally so an entry exists in the token store;
  forgery only works against a user who has already logged in.
* A credential-less "attacker" constructs the deterministic guess ``token-2``
  from the (public) integer id -- WITHOUT ever using bob's real token -- and
  presents it to a token-protected endpoint.
* The guess must be REJECTED (401).

  - Against the unfixed app the guess equals the real token, so the endpoint
    returns 200 and this test FAILS, detecting the vulnerability.
  - Against the fixed app the real token is cryptographically random, so the
    guess is rejected (401) and this test PASSES.

A positive control confirms bob's REAL token still works, so the fix does not
break legitimate authentication.
"""
import os
import re
import sys

# Make the test self-contained: ensure the repo root (parent of tests/) is on
# sys.path so ``import app`` works regardless of how pytest is invoked.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from app import USERS
from app import app as flask_app

BOB_USERNAME = "bob"
BOB_ID = USERS[BOB_USERNAME]["id"]  # 2
BOB_PASSWORD = USERS[BOB_USERNAME]["password"]
# The legacy, fully-guessable token string an attacker would reconstruct.
PREDICTABLE_GUESS = f"token-{BOB_ID}"


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    return flask_app.test_client()


def _login(client, username, password):
    resp = client.post("/login", json={"username": username, "password": password})
    assert resp.status_code == 200, f"login for {username} failed ({resp.status_code})"
    return resp.get_json()["token"]


def test_guessed_token_is_rejected(client):
    """A token guessed from the user id must not grant a session."""
    # Victim logs in normally so an entry exists in the token store. The real
    # token is deliberately discarded -- the attacker never observes it.
    _login(client, BOB_USERNAME, BOB_PASSWORD)

    # Attacker forges the deterministic guess from the public integer id only.
    forged = client.get(
        f"/accounts/{BOB_ID}",
        headers={"Authorization": f"Bearer {PREDICTABLE_GUESS}"},
    )
    assert forged.status_code == 401, (
        "guessed token 'token-<id>' was accepted -- session forgery is possible"
    )


def test_real_token_still_works(client):
    """Positive control: a legitimately issued token must keep working."""
    real_token = _login(client, BOB_USERNAME, BOB_PASSWORD)
    ok = client.get(
        f"/accounts/{BOB_ID}",
        headers={"Authorization": f"Bearer {real_token}"},
    )
    assert ok.status_code == 200
    assert ok.get_json()["username"] == BOB_USERNAME


def test_issued_token_is_unpredictable(client):
    """The issued token must not be derivable from the user id."""
    real_token = _login(client, BOB_USERNAME, BOB_PASSWORD)
    # Must not equal the predictable guess and must not follow the legacy
    # ``token-<id>`` pattern that encodes the id.
    assert real_token != PREDICTABLE_GUESS
    assert not re.fullmatch(r"token-\d+", real_token), (
        f"token still follows the predictable 'token-<id>' pattern: {real_token!r}"
    )
    # Must carry enough entropy to be unguessable.
    assert len(real_token) >= 20, "issued token is too short to be unguessable"
