import unittest

from app import TOKENS, USERS, app


class AdminUsersTest(unittest.TestCase):
    def setUp(self):
        TOKENS.clear()
        self.client = app.test_client()

    def login(self, username="admin", password=None):
        password = password or USERS[username]["password"]
        response = self.client.post(
            "/login",
            json={"username": username, "password": password},
        )
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertIsInstance(body, dict)
        self.assertIn("token", body)
        return body["token"]

    def assert_admin_directory_control(self):
        token = self.login()
        response = self.client.get(
            "/admin/users",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertIsInstance(body, dict)
        self.assertIn("users", body)
        self.assertIn("admin", body["users"])
        return body

    def password_field_paths(self, value, path="$"):
        if isinstance(value, dict):
            paths = []
            for key, child in value.items():
                child_path = f"{path}.{key}"
                if key == "password":
                    paths.append(child_path)
                paths.extend(self.password_field_paths(child, child_path))
            return paths
        if isinstance(value, list):
            paths = []
            for index, child in enumerate(value):
                paths.extend(self.password_field_paths(child, f"{path}[{index}]"))
            return paths
        return []

    def test_authenticated_admin_can_read_directory_control(self):
        self.assert_admin_directory_control()

    def test_admin_directory_requires_authentication(self):
        self.assert_admin_directory_control()

        response = self.client.get("/admin/users")

        self.assertIn(response.status_code, (401, 403))
        body = response.get_json()
        self.assertFalse(isinstance(body, dict) and body.get("users"))

    def test_admin_directory_rejects_invalid_bearer_token(self):
        self.assert_admin_directory_control()

        response = self.client.get(
            "/admin/users?limit=1&search=%27%22%3Ctest%3E",
            headers={"Authorization": "Bearer not-a-token"},
        )

        self.assertIn(response.status_code, (401, 403))
        self.assertEqual([], self.password_field_paths(response.get_json()))

    def test_admin_directory_requires_admin_user(self):
        self.assert_admin_directory_control()
        token = self.login("alice")

        response = self.client.get(
            "/admin/users",
            headers={"Authorization": f"Bearer {token}"},
        )

        self.assertEqual(response.status_code, 403)
        body = response.get_json()
        self.assertFalse(isinstance(body, dict) and body.get("users"))

    def test_admin_directory_uses_safe_response_projection(self):
        body = self.assert_admin_directory_control()

        self.assertEqual([], self.password_field_paths(body))
        for username, record in body["users"].items():
            self.assertEqual(
                {"id", "username", "email"},
                set(record),
                f"{username} directory record exposes unsafe fields",
            )


if __name__ == "__main__":
    unittest.main()
