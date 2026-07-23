import unittest

from app import TOKENS, app


class AccountAuthorizationTest(unittest.TestCase):
    def setUp(self):
        TOKENS.clear()
        self.client = app.test_client()

    def login(self, username, password):
        response = self.client.post(
            "/login",
            json={"username": username, "password": password},
        )
        self.assertEqual(response.status_code, 200)
        return response.get_json()["token"]

    def assert_can_read_own_account(self, token, account_id, username):
        response = self.client.get(
            f"/accounts/{account_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["id"], account_id)
        self.assertEqual(response.get_json()["username"], username)

    def test_signed_in_users_cannot_read_other_accounts(self):
        alice_token = self.login("alice", "alice-pw")
        bob_token = self.login("bob", "bob-pw")

        self.assert_can_read_own_account(alice_token, 1, "alice")
        self.assert_can_read_own_account(bob_token, 2, "bob")

        for actor, token, target_id in (
            ("alice", alice_token, 2),
            ("bob", bob_token, 1),
        ):
            with self.subTest(actor=actor, target_id=target_id):
                response = self.client.get(
                    f"/accounts/{target_id}",
                    headers={"Authorization": f"Bearer {token}"},
                )
                self.assertIn(response.status_code, (403, 404))


if __name__ == "__main__":
    unittest.main()
