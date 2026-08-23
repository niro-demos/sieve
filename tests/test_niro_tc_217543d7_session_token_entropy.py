"""Regression coverage for TC-217543D7."""

import unittest

import app


class SessionTokenEntropyTests(unittest.TestCase):
    def setUp(self):
        app.TOKENS.clear()
        self.client = app.app.test_client()

    def tearDown(self):
        app.TOKENS.clear()

    def login(self, username):
        response = self.client.post(
            "/login",
            json={"username": username, "password": app.USERS[username]["password"]},
        )
        self.assertEqual(response.status_code, 200, response.get_json())
        token = response.get_json().get("token")
        self.assertIsInstance(token, str)
        self.assertTrue(token)
        return token

    def test_predicted_tokens_cannot_authenticate_as_other_users(self):
        """Sequential guesses must not authorize access to other accounts."""
        alice_token = self.login("alice")
        self.login("bob")
        self.login("admin")

        # Positive control: an actually issued token remains valid.
        response = self.client.get(
            "/accounts/1", headers={"Authorization": f"Bearer {alice_token}"}
        )
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(response.get_json()["username"], "alice")

        # Authentication remains enabled for unknown and missing tokens.
        for headers in ({"Authorization": "Bearer token-99"}, {}):
            with self.subTest(headers=headers):
                response = self.client.get("/accounts/2", headers=headers)
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.get_json(), {"error": "unauthorized"})

        # Bob and administrator have logged in, but their credentials and real
        # tokens were never disclosed. Predicting token-<sequential id> must not
        # authenticate the caller as either account.
        for guessed_token, account_id, username in (
            ("token-2", 2, "bob"),
            ("token-3", 3, "admin"),
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
