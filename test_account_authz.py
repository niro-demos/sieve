"""Regression tests for object-level authorization on GET /accounts/<id>.

Invariant: a logged-in user may read ONLY their own account details, never
another user's account by changing the numeric id in the URL. Cross-account
reads must be refused (403), while a user reading their own account still
succeeds (200).

These exercise the app via Flask's built-in test client, so each run drives a
fresh in-process app with the seeded in-memory USERS/TOKENS — no live server
and no external database required.
"""
import pytest

import app as sieve


@pytest.fixture
def client():
    sieve.app.config["TESTING"] = True
    # Isolate token state between tests (module-level dict in the app).
    sieve.TOKENS.clear()
    with sieve.app.test_client() as c:
        yield c
    sieve.TOKENS.clear()


def _login(client, username, password):
    resp = client.post("/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    return resp.get_json()["token"]


def test_owner_can_read_own_account(client):
    """Positive control: alice reads her own account (id 1) -> 200 with her record."""
    token = _login(client, "alice", "alice-pw")
    resp = client.get("/accounts/1", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["username"] == "alice"
    assert body["id"] == 1


@pytest.mark.parametrize("victim_id, victim_name", [(2, "bob"), (3, "admin")])
def test_user_cannot_read_other_users_account(client, victim_id, victim_name):
    """IDOR guard: alice's own token must NOT disclose another user's account.

    On the vulnerable code this returns 200 with the victim's email/balance
    (RED). After the fix it must return 403 and never leak the victim record.
    """
    token = _login(client, "alice", "alice-pw")
    resp = client.get(
        f"/accounts/{victim_id}", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 403, (
        f"cross-account read of {victim_name} (id={victim_id}) was not refused: "
        f"status={resp.status_code} body={resp.get_data(as_text=True)}"
    )
    body = resp.get_json() or {}
    # The victim's private fields must never appear in the response.
    assert body.get("username") != victim_name
    assert "email" not in body
    assert "balance" not in body


def test_unauthenticated_request_is_rejected(client):
    """No/invalid token still yields 401 (authentication unaffected by the fix)."""
    resp = client.get("/accounts/1", headers={"Authorization": "Bearer not-a-real-token"})
    assert resp.status_code == 401
