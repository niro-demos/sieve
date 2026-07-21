import copy
import unittest

import app as sieve


ORIGINAL_USERS = copy.deepcopy(sieve.USERS)


class AuthSecurityTest(unittest.TestCase):
    def setUp(self):
        sieve.USERS.clear()
        sieve.USERS.update(copy.deepcopy(ORIGINAL_USERS))
        sieve.TOKENS.clear()
        self.client = sieve.app.test_client()

    def test_published_default_credentials_are_rejected(self):
        invalid = self.client.post(
            "/login",
            json={"username": "not-a-user", "password": "not-a-password"},
        )
        self.assertEqual(invalid.status_code, 401)

        for username, password in (
            ("alice", "alice-pw"),
            ("bob", "bob-pw"),
            ("admin", "admin-pw"),
        ):
            with self.subTest(username=username):
                response = self.client.post(
                    "/login",
                    json={"username": username, "password": password},
                )
                self.assertEqual(response.status_code, 401)
                self.assertNotIn("token", response.get_json())

    def test_login_tokens_are_not_predictable_from_user_ids(self):
        sieve.USERS["bob"]["password"] = "bob-unique-test-password"

        unauthenticated = self.client.get("/accounts/2")
        self.assertEqual(unauthenticated.status_code, 401)

        login = self.client.post(
            "/login",
            json={"username": "bob", "password": "bob-unique-test-password"},
        )
        self.assertEqual(login.status_code, 200)

        issued_token = login.get_json()["token"]
        legitimate = self.client.get(
            "/accounts/2",
            headers={"Authorization": f"Bearer {issued_token}"},
        )
        self.assertEqual(legitimate.status_code, 200)
        self.assertEqual(legitimate.get_json()["username"], "bob")

        predictable_token = "token-2"
        self.assertNotEqual(issued_token, predictable_token)

        guessed = self.client.get(
            "/accounts/2",
            headers={"Authorization": f"Bearer {predictable_token}"},
        )
        self.assertEqual(guessed.status_code, 401)


if __name__ == "__main__":
    unittest.main()
