"""
Regression test for TC-21EB3215: POST /login must throttle/lock out repeated
failed password attempts for a username, instead of answering an unlimited
number of guesses at full request-handling speed.

Invariant under test (from niro/findings/TC-21EB3215/finding.json):
"The login endpoint must not allow unlimited, unthrottled password guesses
for a username -- repeated failed attempts should eventually be slowed,
blocked, or flagged."

Each test reloads the app module first, so every test starts from a clean
in-memory USERS/TOKENS/lockout-state baseline and tests don't leak state
into each other.
"""
import importlib
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as app_module

ATTEMPTS = 30


@pytest.fixture
def client():
    importlib.reload(app_module)
    app_module.app.config["TESTING"] = True
    return app_module.app.test_client()


def do_login(client, username, password):
    return client.post("/login", json={"username": username, "password": password})


def test_repeated_failed_logins_are_eventually_blocked(client):
    """Positive control + exploit, mirroring the PoC: a legitimate login
    must succeed normally, and a burst of wrong-password guesses for one
    username must eventually be refused (429/423) rather than evaluated at
    full speed forever.
    """
    # Control: the target is healthy and a correct login works.
    control = do_login(client, "alice", "alice-pw")
    assert control.status_code == 200 and "token" in control.get_json(), (
        "positive control failed: legitimate alice/alice-pw login did not "
        f"succeed (status={control.status_code}, body={control.get_json()})"
    )

    # Exploit: unlimited wrong-password guesses for a single username.
    username = "brute-force-target"
    statuses = []
    for i in range(ATTEMPTS):
        resp = do_login(client, username, f"wrong-guess-{i}")
        statuses.append(resp.status_code)

    assert any(s in (429, 423) for s in statuses), (
        f"VULNERABLE: all {ATTEMPTS} consecutive failed /login attempts for "
        f"username={username!r} returned a normal 401 with no lockout -- "
        f"statuses={sorted(set(statuses))}. The endpoint applies no "
        f"throttling, lockout, or CAPTCHA whatsoever."
    )


def test_lockout_is_scoped_to_the_offending_username(client):
    """A lockout triggered by brute-forcing one username must not lock out a
    different, legitimate user -- proving the block is scoped, not a global
    outage that would itself be a regression.
    """
    attacker_username = "brute-force-target-2"
    for i in range(ATTEMPTS):
        do_login(client, attacker_username, f"wrong-guess-{i}")

    # A different, correct login must still succeed even while the attacker
    # username is locked out.
    resp = do_login(client, "bob", "bob-pw")
    assert resp.status_code == 200
    assert "token" in resp.get_json()


def test_locked_out_username_rejects_even_the_correct_password(client):
    """Once locked out, the *correct* password for the abused username must
    also be refused for the lockout window -- otherwise the lockout only
    blocks wrong guesses and the attacker can still slip the right one in.
    """
    username = "alice"
    for i in range(ATTEMPTS):
        do_login(client, username, f"wrong-guess-{i}")

    resp = do_login(client, username, "alice-pw")
    assert resp.status_code in (429, 423), (
        f"expected the locked-out account to reject the correct password "
        f"while locked out, got status={resp.status_code}"
    )
