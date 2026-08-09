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

    def test_account_holder_cannot_read_another_account(self):
        alice_token = self.login("alice", "alice-pw")

        own_response = self.client.get(
            "/accounts/1",
            headers={"Authorization": f"Bearer {alice_token}"},
        )
        self.assertEqual(own_response.status_code, 200)
        self.assertEqual(own_response.get_json()["username"], "alice")

        cross_response = self.client.get(
            "/accounts/2",
            headers={"Authorization": f"Bearer {alice_token}"},
        )
        self.assertEqual(cross_response.status_code, 403)
        self.assertNotIn("bob@sieve.test", cross_response.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
