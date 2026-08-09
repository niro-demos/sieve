"""
Regression tests for TC-72527B93 — Forgible sequential tokens let any remote
attacker impersonate every user.

Invariant:
  An attacker must not be able to impersonate any user by guessing or
  constructing a valid authentication token without providing that user's
  correct credentials.

These tests cover ONLY the token-generation root cause in ``login()``.
Authorization checks on ``/accounts/<id>`` and ``/admin/users`` are separate
findings with their own PRs.
"""
import re

import pytest

from app import app, TOKENS


@pytest.fixture(autouse=True)
def reset_tokens():
    """Clear the in-memory token store between tests for isolation."""
    TOKENS.clear()
    yield
    TOKENS.clear()


@pytest.fixture()
def client():
    app.config.update(TESTING=True)
    with app.test_client() as c:
        yield c


def login(client, username, password):
    return client.post("/login", json={"username": username, "password": password})


def auth(token):
    return {"Authorization": "Bearer " + token}


# ---------------------------------------------------------------------------
# Positive controls — legitimate access with correct credentials works.
# These prove the environment is healthy, so a failure below is the invariant,
# not a broken setup.
# ---------------------------------------------------------------------------
def test_legitimate_login_returns_token(client):
    resp = login(client, "alice", "alice-pw")
    assert resp.status_code == 200
    assert resp.get_json().get("token")


def test_legitimate_user_reads_own_account(client):
    resp = login(client, "alice", "alice-pw")
    token = resp.get_json()["token"]
    resp = client.get("/accounts/1", headers=auth(token))
    assert resp.status_code == 200
    assert resp.get_json()["username"] == "alice"


# ---------------------------------------------------------------------------
# Tokens must be cryptographically random and unforgeable — not derivable from
# the user id.
# ---------------------------------------------------------------------------
def test_token_is_not_sequential_id_format(client):
    """A token must never be of the predictable ``token-<id>`` form."""
    resp = login(client, "alice", "alice-pw")
    token = resp.get_json()["token"]
    assert not re.fullmatch(r"token-\d+", token), f"token is forgeable: {token}"


def test_repeated_logins_produce_different_tokens(client):
    """Each login mints a fresh random token, not a reused deterministic one."""
    t1 = login(client, "alice", "alice-pw").get_json()["token"]
    t2 = login(client, "alice", "alice-pw").get_json()["token"]
    assert t1 != t2


def test_forged_token_rejected_on_account(client):
    """A constructed ``token-<id>`` must not authenticate, even after a real
    login has populated the token store."""
    login(client, "alice", "alice-pw")
    resp = client.get("/accounts/1", headers=auth("token-1"))
    assert resp.status_code in (401, 403)
