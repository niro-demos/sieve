import copy
import unittest

import app as sieve


ORIGINAL_USERS = copy.deepcopy(sieve.USERS)


class SecurityRegressionTests(unittest.TestCase):
    def setUp(self):
        sieve.USERS.clear()
        sieve.USERS.update(copy.deepcopy(ORIGINAL_USERS))
        sieve.TOKENS.clear()
        self.client = sieve.app.test_client()

    def set_password(self, username, password):
        sieve.USERS[username]["password"] = password

    def login(self, username, password):
        response = self.client.post(
            "/login",
            json={"username": username, "password": password},
        )
        self.assertEqual(response.status_code, 200, response.get_json())
        token = response.get_json().get("token")
        self.assertTrue(token)
        return token

    def auth_headers(self, token):
        return {"Authorization": f"Bearer {token}"}

    def test_public_default_credentials_do_not_issue_sessions(self):
        public_defaults = [
            ("alice", "alice-pw"),
            ("bob", "bob-pw"),
            ("admin", "admin-pw"),
        ]

        root = self.client.get("/")
        self.assertEqual(root.status_code, 200)

        wrong_password = self.client.post(
            "/login",
            json={"username": "admin", "password": "not-admin-pw"},
        )
        self.assertEqual(wrong_password.status_code, 401)
        self.assertNotIn("token", wrong_password.get_json())

        for username, password in public_defaults:
            with self.subTest(username=username):
                response = self.client.post(
                    "/login",
                    json={"username": username, "password": password},
                )
                self.assertEqual(response.status_code, 401)
                self.assertNotIn("token", response.get_json())

    def test_constructed_bearer_token_is_rejected(self):
        self.set_password("bob", "bob-test-secret")

        legitimate_token = self.login("bob", "bob-test-secret")
        legitimate = self.client.get(
            "/accounts/2",
            headers=self.auth_headers(legitimate_token),
        )
        self.assertEqual(legitimate.status_code, 200)
        self.assertEqual(legitimate.get_json()["username"], "bob")

        guessed = self.client.get(
            "/accounts/2",
            headers=self.auth_headers("token-2"),
        )
        self.assertIn(guessed.status_code, (401, 403))

    def test_account_details_require_owner_token(self):
        self.set_password("alice", "alice-test-secret")
        self.set_password("bob", "bob-test-secret")

        alice_token = self.login("alice", "alice-test-secret")
        bob_token = self.login("bob", "bob-test-secret")

        alice_own_account = self.client.get(
            "/accounts/1",
            headers=self.auth_headers(alice_token),
        )
        self.assertEqual(alice_own_account.status_code, 200)
        self.assertEqual(alice_own_account.get_json()["username"], "alice")

        bob_own_account = self.client.get(
            "/accounts/2",
            headers=self.auth_headers(bob_token),
        )
        self.assertEqual(bob_own_account.status_code, 200)
        self.assertEqual(bob_own_account.get_json()["username"], "bob")

        unauthenticated = self.client.get("/accounts/2")
        self.assertEqual(unauthenticated.status_code, 401)

        alice_reads_bob = self.client.get(
            "/accounts/2",
            headers=self.auth_headers(alice_token),
        )
        self.assertEqual(alice_reads_bob.status_code, 403)

        bob_reads_alice = self.client.get(
            "/accounts/1",
            headers=self.auth_headers(bob_token),
        )
        self.assertEqual(bob_reads_alice.status_code, 403)

    def test_admin_directory_requires_admin_token(self):
        self.set_password("alice", "alice-test-secret")
        self.set_password("admin", "admin-test-secret")

        alice_token = self.login("alice", "alice-test-secret")
        admin_token = self.login("admin", "admin-test-secret")

        unauthenticated = self.client.get("/admin/users")
        self.assertEqual(unauthenticated.status_code, 401)

        standard_user = self.client.get(
            "/admin/users",
            headers=self.auth_headers(alice_token),
        )
        self.assertEqual(standard_user.status_code, 403)

        admin_user = self.client.get(
            "/admin/users",
            headers=self.auth_headers(admin_token),
        )
        self.assertEqual(admin_user.status_code, 200)
        self.assertIn("users", admin_user.get_json())

    def test_admin_directory_never_discloses_password_fields(self):
        self.set_password("admin", "admin-test-secret")
        admin_token = self.login("admin", "admin-test-secret")

        response = self.client.get(
            "/admin/users",
            headers=self.auth_headers(admin_token),
        )
        self.assertEqual(response.status_code, 200)
        users = response.get_json()["users"]
        self.assertTrue(users)
        for username, record in users.items():
            with self.subTest(username=username):
                self.assertNotIn("password", record)


if __name__ == "__main__":
    unittest.main()
