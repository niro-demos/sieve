import pytest

from app import TOKENS, app


@pytest.fixture
def client():
    TOKENS.clear()
    app.config.update(TESTING=True)
    with app.test_client() as test_client:
        yield test_client
    TOKENS.clear()


def login(client, username, password):
    response = client.post("/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return response.get_json()["token"]


def test_standard_users_can_only_read_their_own_account(client):
    alice_token = login(client, "alice", "alice-pw")
    bob_token = login(client, "bob", "bob-pw")

    alice_account = client.get("/accounts/1", headers={"Authorization": f"Bearer {alice_token}"})
    bob_account = client.get("/accounts/2", headers={"Authorization": f"Bearer {bob_token}"})

    assert alice_account.status_code == 200
    assert alice_account.get_json()["username"] == "alice"
    assert bob_account.status_code == 200
    assert bob_account.get_json()["username"] == "bob"

    alice_reading_bob = client.get("/accounts/2", headers={"Authorization": f"Bearer {alice_token}"})
    bob_reading_alice = client.get("/accounts/1", headers={"Authorization": f"Bearer {bob_token}"})

    assert alice_reading_bob.status_code == 403
    assert bob_reading_alice.status_code == 403
