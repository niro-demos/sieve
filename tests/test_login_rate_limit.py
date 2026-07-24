#!/usr/bin/env python3
"""
Regression test for: POST /login has no rate limiting, lockout, or CAPTCHA
against repeated wrong-password attempts.

Invariant: the login endpoint must slow down or block an attacker who
repeatedly submits wrong passwords for the same account instead of
processing every guess at full speed forever.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as app_module  # noqa: E402


@pytest.fixture
def client():
    app_module.app.config.update(TESTING=True)
    # Reset all mutable global state so tests don't leak into each other.
    app_module.TOKENS.clear()
    if hasattr(app_module, "FAILED_LOGIN_ATTEMPTS"):
        app_module.FAILED_LOGIN_ATTEMPTS.clear()
    with app_module.app.test_client() as c:
        yield c


def login(client, username, password):
    return client.post("/login", json={"username": username, "password": password})


def test_repeated_wrong_password_attempts_are_throttled(client):
    """A brute-force burst of wrong passwords against one account must
    eventually be rejected with 429, not processed at full speed forever."""
    statuses = [login(client, "alice", f"wrong-guess-{i}").status_code for i in range(20)]

    assert 429 in statuses, (
        f"expected a 429 after repeated wrong-password attempts against the same "
        f"account, but got statuses={statuses} (endpoint never throttled)"
    )


def test_lockout_blocks_even_the_correct_password(client):
    """Once an account is locked out from failed attempts, the correct
    password must also be rejected until the lockout clears - otherwise the
    'lockout' is cosmetic and an attacker's own correct guess would still
    succeed mid-lockout."""
    for i in range(20):
        login(client, "alice", f"wrong-guess-{i}")

    resp = login(client, "alice", "alice-pw")
    assert resp.status_code == 429, (
        f"expected the account to remain locked even for its correct password "
        f"during the lockout window, got {resp.status_code}"
    )


def test_lockout_is_scoped_to_the_targeted_account(client):
    """Brute-forcing one account must not lock out or otherwise block a
    different, unrelated account's legitimate login (no accidental global
    denial-of-service via lockout)."""
    for i in range(20):
        login(client, "alice", f"wrong-guess-{i}")

    resp = login(client, "bob", "bob-pw")
    assert resp.status_code == 200
    assert "token" in resp.get_json()


def test_successful_login_resets_the_failure_counter(client):
    """A handful of wrong guesses below the lockout threshold, followed by
    the correct password, must succeed and clear the failure count - normal
    users who mistype their password a couple of times should not be
    penalized."""
    for i in range(3):
        login(client, "alice", f"wrong-guess-{i}")

    resp = login(client, "alice", "alice-pw")
    assert resp.status_code == 200
    assert "token" in resp.get_json()
