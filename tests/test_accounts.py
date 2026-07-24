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

    def get_account(self, account_id, token):
        return self.client.get(
            f"/accounts/{account_id}",
            headers={"Authorization": f"Bearer {token}"},
        )

    def test_account_holder_can_read_own_account(self):
        alice_token = self.login("alice", "alice-pw")

        response = self.get_account(1, alice_token)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["username"], "alice")

    def test_account_holder_cannot_read_another_account(self):
        alice_token = self.login("alice", "alice-pw")
        bob_token = self.login("bob", "bob-pw")

        alice_reads_bob = self.get_account(2, alice_token)
        bob_reads_alice = self.get_account(1, bob_token)

        self.assertEqual(alice_reads_bob.status_code, 403)
        self.assertEqual(bob_reads_alice.status_code, 403)


if __name__ == "__main__":
    unittest.main()
