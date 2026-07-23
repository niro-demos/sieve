import unittest

from app import TOKENS, USERS, app


class AuthTokenTests(unittest.TestCase):
    def setUp(self):
        TOKENS.clear()
        self.client = app.test_client()

    def login(self, username, password):
        response = self.client.post(
            "/login",
            json={"username": username, "password": password},
        )
        self.assertEqual(response.status_code, 200)
        token = response.get_json()["token"]
        self.assertTrue(token)
        return token

    def assert_account_read_allowed(self, token, account_id, username):
        response = self.client.get(
            f"/accounts/{account_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["username"], username)

    def test_predicted_session_tokens_are_rejected(self):
        actors = [
            ("alice", 1),
            ("bob", 2),
        ]

        for username, account_id in actors:
            token = self.login(username, USERS[username]["password"])
            self.assert_account_read_allowed(token, account_id, username)

        for username, account_id in actors:
            with self.subTest(username=username):
                response = self.client.get(
                    f"/accounts/{account_id}",
                    headers={"Authorization": f"Bearer token-{account_id}"},
                )
                self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()
