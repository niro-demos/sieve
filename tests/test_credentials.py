"""
Regression tests for the credential-storage security invariant.

Invariant under test: the application must not embed real login passwords as
plaintext literals in its source, and the in-memory ``USERS`` store must keep
only non-reversible password *hashes* -- never a plaintext value that could be
copied out of the code (or its VCS history) and replayed against the live
service. Authentication must still accept a correct password and reject a wrong
one.

These tests FAIL against the pre-fix code -- which hardcoded plaintext passwords
in ``USERS`` and compared them with ``==`` -- and PASS after the fix, which
sources credentials from the environment and stores/verifies them with
``werkzeug.security`` password hashes.
"""
import importlib
import os
import sys

import pytest
from werkzeug.security import check_password_hash

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

APP_SOURCE = os.path.join(REPO_ROOT, "app.py")

# Test-only credentials, supplied via the environment the way the fixed app
# expects. These are NOT real secrets and deliberately differ from any value
# baked into the source, so a correct-password test cannot pass by accident.
TEST_CREDENTIALS = {
    "alice": "alice-test-pw-3f9c",
    "bob": "bob-test-pw-7a1d",
    "admin": "admin-test-pw-b204",
}
ENV_VARS = {
    "alice": "SIEVE_ALICE_PASSWORD",
    "bob": "SIEVE_BOB_PASSWORD",
    "admin": "SIEVE_ADMIN_PASSWORD",
}

# Historical plaintext login passwords that must never reappear as source
# literals (this is exactly what the finding exploited).
FORBIDDEN_PLAINTEXT_LITERALS = ("admin-pw", "alice-pw", "bob-pw")


@pytest.fixture()
def app_module(monkeypatch):
    """Import app.py fresh with test credentials supplied via the environment."""
    for user, env_name in ENV_VARS.items():
        monkeypatch.setenv(env_name, TEST_CREDENTIALS[user])
    sys.modules.pop("app", None)
    module = importlib.import_module("app")
    yield module
    sys.modules.pop("app", None)


@pytest.fixture()
def client(app_module):
    app_module.app.config.update(TESTING=True)
    return app_module.app.test_client()


def test_source_has_no_plaintext_password_literals():
    src = open(APP_SOURCE, encoding="utf-8").read()
    leaked = [lit for lit in FORBIDDEN_PLAINTEXT_LITERALS if lit in src]
    assert not leaked, (
        f"app.py still embeds plaintext login password literal(s): {leaked}. "
        "Passwords must be sourced from configuration, never hardcoded plaintext."
    )


def test_stored_credentials_are_hashes_not_reversible_plaintext(app_module):
    users = app_module.USERS
    for user, plaintext in TEST_CREDENTIALS.items():
        record = users[user]
        # No stored field may hold the reversible plaintext login password.
        for key, value in record.items():
            assert value != plaintext, (
                f"USERS[{user!r}][{key!r}] stores the plaintext login password; "
                "the stored form must be a non-reversible hash."
            )
        # The credential must be present as a verifiable password hash.
        assert "password_hash" in record, (
            f"USERS[{user!r}] is missing a 'password_hash' field; the stored "
            "form must be a hash, not plaintext."
        )
        stored = record["password_hash"]
        assert stored != plaintext
        assert check_password_hash(stored, plaintext), (
            f"USERS[{user!r}]['password_hash'] does not verify the configured "
            "password via check_password_hash."
        )


def test_correct_password_authenticates(client):
    resp = client.post(
        "/login", json={"username": "admin", "password": TEST_CREDENTIALS["admin"]}
    )
    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json().get("token")


def test_wrong_password_is_rejected(client):
    resp = client.post(
        "/login", json={"username": "admin", "password": "not-the-password"}
    )
    assert resp.status_code == 401
