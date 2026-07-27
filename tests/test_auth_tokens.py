import pytest

from app import TOKENS, app


@pytest.fixture
def client():
    TOKENS.clear()
    app.config.update(TESTING=True)
    with app.test_client() as test_client:
        yield test_client
    TOKENS.clear()


def login(client, username="alice", password="alice-pw"):
    response = client.post(
        "/login",
        json={"username": username, "password": password},
    )
    assert response.status_code == 200
    body = response.get_json()
    assert "token" in body
    return body["token"]


def test_issued_bearer_token_can_read_account(client):
    token = login(client)

    response = client.get(
        "/accounts/1",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.get_json()["username"] == "alice"


def test_predicted_bearer_token_cannot_read_active_session_account(client):
    issued_token = login(client)
    assert issued_token != "token-1"

    response = client.get(
        "/accounts/1",
        headers={"Authorization": "Bearer token-1"},
    )

    assert response.status_code == 401
