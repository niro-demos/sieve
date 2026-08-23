"""Regression test for TC-533B8473 — POST /login must throttle/lock out repeated
failed password attempts for the same account (CWE-307).

Invariant under test:
    The login endpoint must limit or slow down repeated failed password attempts
    for the same account, so an attacker who knows a username cannot try unlimited
    passwords at full speed. After a small threshold of rapid failures for one
    username the endpoint must stop evaluating passwords and instead return
    ``429 Too Many Requests`` with a ``Retry-After`` header (a temporary lockout),
    and a legitimate successful login before the threshold must reset the counter
    so ordinary users who mistype a password are never penalised.

These tests run entirely in-process against the Flask app via its test client —
no live server, no seeded database — so they are deterministic and CI-friendly.
Each test starts from clean in-memory auth state (see the ``client`` fixture),
which keeps the lockout counters from leaking between tests.
"""
import pytest

import app as sieve_app


@pytest.fixture
def client():
    """A fresh Flask test client with all in-memory auth state reset.

    Clearing ``TOKENS`` and the throttle counters between tests is what keeps the
    (deliberately low) failure threshold from locking out a later test's login.
    The ``getattr`` guard means this fixture also works against the *unfixed* app
    (which has no ``FAILED_LOGINS``), so the red run fails on a real assertion
    rather than a setup error.
    """
    sieve_app.app.config.update(TESTING=True)
    sieve_app.TOKENS.clear()
    failed = getattr(sieve_app, "FAILED_LOGINS", None)
    if failed is not None:
        failed.clear()
    return sieve_app.app.test_client()


def _login(client, username, password):
    return client.post("/login", json={"username": username, "password": password})


def _threshold():
    # The fix exposes a module-level threshold; default to 5 if absent so this
    # test is meaningful even before the fix lands.
    return getattr(sieve_app, "LOGIN_MAX_FAILED_ATTEMPTS", 5)


def test_legitimate_login_succeeds(client):
    """Positive control / healthy baseline: correct credentials return 200 + token.

    This is the paired green case: it proves the endpoint serves valid logins
    normally, so a failure in the attack test below is the missing throttle, not
    a broken environment.
    """
    r = _login(client, "admin", "admin-pw")
    assert r.status_code == 200
    assert r.get_json().get("token")


def test_repeated_failures_lock_out_the_account(client):
    """Attack: a burst of wrong passwords for one username must trip a temporary
    lockout — ``429`` + ``Retry-After`` — after which even the *correct* password
    is refused for the duration of the lockout window.
    """
    threshold = _threshold()

    saw_429 = False
    saw_retry_after = False
    for i in range(threshold + 20):  # fire well past the threshold, full speed
        r = _login(client, "admin", f"wrong-password-{i}")
        assert r.status_code in (401, 429)
        if r.status_code == 429:
            saw_429 = True
            if r.headers.get("Retry-After"):
                saw_retry_after = True

    assert saw_429, (
        "expected HTTP 429 once repeated failed logins crossed the threshold; "
        "the endpoint kept accepting full-speed guesses (no throttle/lockout)"
    )
    assert saw_retry_after, "expected a Retry-After header on the 429 lockout response"

    # The account is now locked: even the correct password must be refused until
    # the lockout window elapses (this is what stops the brute-forcer cold).
    r = _login(client, "admin", "admin-pw")
    assert r.status_code == 429, (
        "correct password succeeded during an active lockout — the account was "
        "never actually locked out"
    )
    assert r.headers.get("Retry-After")


def test_success_before_threshold_resets_counter(client):
    """A successful login clears the failed-attempt counter, so a handful of
    mistyped passwords followed by a correct one — then more mistypes — never
    trips the lockout. Guards the fix against penalising legitimate users.
    """
    threshold = _threshold()

    for i in range(threshold - 1):  # just under the threshold
        assert _login(client, "alice", f"wrong-{i}").status_code == 401
    assert _login(client, "alice", "alice-pw").status_code == 200  # resets counter

    for i in range(threshold - 1):  # a fresh run that must NOT lock out
        r = _login(client, "alice", f"still-wrong-{i}")
        assert r.status_code == 401, (
            "a successful login should have reset the failed-attempt counter"
        )


def test_lockout_is_scoped_per_username(client):
    """The lockout is keyed to the account under attack: hammering 'admin' must
    not lock out an unrelated user 'bob', who logs in normally.
    """
    threshold = _threshold()
    for i in range(threshold + 5):
        _login(client, "admin", f"wrong-{i}")

    r = _login(client, "bob", "bob-pw")
    assert r.status_code == 200
    assert r.get_json().get("token")
