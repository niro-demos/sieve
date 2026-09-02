"""Regression tests: session tokens must be unpredictable and unforgeable.

These tests pin the security invariant that a session token must not be
derivable from a user's public, sequential account id. Concretely they assert
that:

  (a) the token returned by ``POST /login`` is NOT the guessable ``token-<id>``
      string and carries real entropy;
  (b) a token forged as ``token-<victim id>`` is REJECTED by an authenticated
      route (``GET /accounts/<id>``) even after that victim has logged in
      normally — this fails (HTTP 200) on the vulnerable code and passes
      (HTTP 401) once tokens are random;
  (c) a token that ``POST /login`` actually issued still authenticates.

The seeded demo credentials used below are the ones baked into ``app.py`` and
documented in the project README for this local/CI smoke-test target; they are
not production secrets.
"""
import importlib
import os
import sys

import pytest

# Make the repository root (which holds app.py) importable regardless of the
# directory pytest is invoked from.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


@pytest.fixture
def client():
    # Reload the module so each test starts from a clean, process-global
    # in-memory TOKENS state (tokens otherwise persist for the process life).
    import app as app_module

    importlib.reload(app_module)
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as test_client:
        yield test_client


def _login(client, username, password):
    return client.post("/login", json={"username": username, "password": password})


def test_issued_token_is_not_derivable_from_account_id(client):
    """(a) The issued token must not be the id-derived ``token-<id>`` string."""
    resp = _login(client, "alice", "alice-pw")
    assert resp.status_code == 200
    token = resp.get_json()["token"]

    # It must not be the zero-entropy token derived from alice's account id (1).
    assert token != "token-1"
    assert token != f"token-{1}"
    # And it must not follow the guessable ``token-<id>`` shape at all.
    assert not token.startswith("token-")
    # High entropy: a secrets.token_urlsafe(32) value is >= 40 URL-safe chars.
    assert len(token) >= 32


def test_forged_id_derived_token_is_rejected_even_after_victim_login(client):
    """(b) A ``token-<id>`` forged from a victim's public id must be rejected,
    even after the victim has legitimately logged in."""
    # Precondition: victim bob performs his own ordinary login.
    victim = _login(client, "bob", "bob-pw")
    assert victim.status_code == 200

    # Attacker forges bob's token purely from his public account id (2) — no
    # password, no captured token.
    forged = "token-2"
    resp = client.get("/accounts/2", headers={"Authorization": f"Bearer {forged}"})

    # Must be rejected. Vulnerable code returns 200 and discloses bob's account.
    assert resp.status_code == 401


def test_legitimately_issued_token_still_authenticates(client):
    """(c) A token actually issued by ``/login`` must still authenticate."""
    login = _login(client, "alice", "alice-pw")
    assert login.status_code == 200
    token = login.get_json()["token"]

    resp = client.get("/accounts/1", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["id"] == 1
    assert body["username"] == "alice"
