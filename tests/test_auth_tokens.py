import unittest

import app as sieve


class AccountTokenTests(unittest.TestCase):
    def setUp(self):
        sieve.TOKENS.clear()
        self.client = sieve.app.test_client()

    def login(self, username, password):
        response = self.client.post(
            "/login",
            json={"username": username, "password": password},
        )
        self.assertEqual(response.status_code, 200)
        return response.get_json()["token"]

    def test_login_issues_opaque_tokens_not_derived_from_account_ids(self):
        token = self.login("bob", "bob-pw")

        self.assertNotEqual(token, "token-2")

        legitimate = self.client.get(
            "/accounts/2",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(legitimate.status_code, 200)
        self.assertEqual(legitimate.get_json()["username"], "bob")

        guessed = self.client.get(
            "/accounts/2",
            headers={"Authorization": "Bearer token-2"},
        )
        self.assertEqual(guessed.status_code, 401)

    def test_account_requires_bearer_authorization_scheme(self):
        token = self.login("alice", "alice-pw")

        legitimate = self.client.get(
            "/accounts/1",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(legitimate.status_code, 200)

        without_bearer = self.client.get(
            "/accounts/1",
            headers={"Authorization": token},
        )
        self.assertEqual(without_bearer.status_code, 401)


if __name__ == "__main__":
    unittest.main()
