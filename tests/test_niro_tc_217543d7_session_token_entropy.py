"""Regression coverage for TC-217543D7."""

import secrets
import unittest
from werkzeug.security import generate_password_hash

import app


class SessionTokenEntropyTests(unittest.TestCase):
    def setUp(self):
        password = secrets.token_urlsafe(32)
        password_hash = generate_password_hash(password)
        self.synthetic_users = {
            "token-entropy-owner": {
                "id": 2175437,
                "password": password,
                "password_hash": password_hash,
                "email": "token-entropy-owner@example.test",
                "balance": 0,
                "admin": False,
            },
            "token-entropy-first-target": {
                "id": 2175438,
                "password": password,
                "password_hash": password_hash,
                "email": "token-entropy-first-target@example.test",
                "balance": 0,
                "admin": False,
            },
            "token-entropy-second-target": {
                "id": 2175439,
                "password": password,
                "password_hash": password_hash,
                "email": "token-entropy-second-target@example.test",
                "balance": 0,
                "admin": False,
            },
        }
        self.assertNotEqual(set(self.synthetic_users), set(app.USERS))
        app.USERS.update(self.synthetic_users)
        app.TOKENS.clear()
        self.client = app.app.test_client()

    def tearDown(self):
        for username in self.synthetic_users:
            app.USERS.pop(username, None)
        app.TOKENS.clear()

    def login(self, username):
        response = self.client.post(
            "/login",
            json={
                "username": username,
                "password": self.synthetic_users[username]["password"],
            },
        )
        self.assertEqual(response.status_code, 200, response.get_json())
        token = response.get_json().get("token")
        self.assertIsInstance(token, str)
        self.assertTrue(token)
        return token

    def test_predicted_tokens_cannot_authenticate_as_other_users(self):
        """Sequential guesses must not authorize access to other accounts."""
        owner_token = self.login("token-entropy-owner")
        self.login("token-entropy-first-target")
        self.login("token-entropy-second-target")

        # Positive control: an actually issued token remains valid.
        response = self.client.get(
            "/accounts/2175437",
            headers={"Authorization": f"Bearer {owner_token}"},
        )
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(response.get_json()["username"], "token-entropy-owner")

        # Authentication remains enabled for unknown and missing tokens.
        for headers in ({"Authorization": "Bearer token-99"}, {}):
            with self.subTest(headers=headers):
                response = self.client.get(
                    "/accounts/2175438", headers=headers
                )
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.get_json(), {"error": "unauthorized"})

        # The target users have logged in, but their real tokens were never
        # disclosed. Predicting token-<sequential id> must not authenticate the
        # caller as either target account.
        for guessed_token, account_id, username in (
            ("token-2175438", 2175438, "token-entropy-first-target"),
            ("token-2175439", 2175439, "token-entropy-second-target"),
        ):
            with self.subTest(username=username, guessed_token=guessed_token):
                response = self.client.get(
                    f"/accounts/{account_id}",
                    headers={"Authorization": f"Bearer {guessed_token}"},
                )
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.get_json(), {"error": "unauthorized"})


if __name__ == "__main__":
    unittest.main()
