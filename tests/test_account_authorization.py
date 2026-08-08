import unittest

from app import TOKENS, USERS, app


class AccountAuthorizationTest(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        TOKENS.clear()
        self.client = app.test_client()

    def login(self, username, password):
        response = self.client.post(
            "/login",
            json={"username": username, "password": password},
        )
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        token = response.get_json()["token"]
        self.assertTrue(token)
        return token

    def auth_header(self, token):
        return {"Authorization": f"Bearer {token}"}

    def test_standard_user_can_only_read_owned_account(self):
        token = self.login("alice", USERS["alice"]["password"])

        own_response = self.client.get("/accounts/1", headers=self.auth_header(token))
        self.assertEqual(own_response.status_code, 200, own_response.get_data(as_text=True))
        self.assertEqual(own_response.get_json()["username"], "alice")

        unauthenticated = self.client.get("/accounts/2")
        self.assertEqual(unauthenticated.status_code, 401, unauthenticated.get_data(as_text=True))

        for account_id in (2, 3):
            with self.subTest(account_id=account_id):
                response = self.client.get(
                    f"/accounts/{account_id}",
                    headers=self.auth_header(token),
                )
                self.assertEqual(response.status_code, 403, response.get_data(as_text=True))
                self.assertEqual(response.get_json(), {"error": "forbidden"})

    def test_missing_account_still_returns_not_found(self):
        token = self.login("alice", USERS["alice"]["password"])

        response = self.client.get("/accounts/999", headers=self.auth_header(token))

        self.assertEqual(response.status_code, 404, response.get_data(as_text=True))
        self.assertEqual(response.get_json(), {"error": "not found"})


if __name__ == "__main__":
    unittest.main()
