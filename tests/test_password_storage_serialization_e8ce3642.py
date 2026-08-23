import secrets
import unittest
from unittest.mock import patch

from werkzeug.security import check_password_hash, generate_password_hash

import app


class PasswordStorageSerializationTests(unittest.TestCase):
    def setUp(self):
        self.password = secrets.token_urlsafe(24)
        self.username = "directory-admin"
        credential_key = self._password_credential_key()
        credential = (
            generate_password_hash(self.password)
            if credential_key == "password_hash"
            else self.password
        )
        self.user = {
            "id": 1,
            credential_key: credential,
            "email": "directory-admin@example.test",
            "balance": 0,
            "admin": True,
        }

    def _password_credential_key(self):
        sample_user = next(iter(app.USERS.values()))
        if "password_hash" in sample_user:
            return "password_hash"
        if "password" in sample_user:
            return "password"
        self.fail("users have no password credential field")

    def test_admin_directory_omits_password_material(self):
        users = {self.username: self.user}

        with patch.dict(app.USERS, users, clear=True):
            login_response = app.app.test_client().post(
                "/login",
                json={"username": self.username, "password": self.password},
            )
            self.assertEqual(login_response.status_code, 200)
            token = login_response.get_json()["token"]

            response = app.app.test_client().get(
                "/admin/users",
                headers={"Authorization": f"Bearer {token}"},
            )
            self.assertEqual(response.status_code, 200)

            serialized_user = response.get_json()["users"][self.username]
            exposed_password_keys = [
                key
                for key in serialized_user
                if key == "password" or key.startswith("password_")
            ]
            self.assertEqual(
                exposed_password_keys,
                [],
                "the user directory serialized password material",
            )
            self.assertEqual(
                set(serialized_user),
                {"id", "email", "balance", "admin"},
            )

    def test_password_is_stored_as_a_verifiable_hash(self):
        users = {self.username: self.user}

        with patch.dict(app.USERS, users, clear=True):
            login_response = app.app.test_client().post(
                "/login",
                json={"username": self.username, "password": self.password},
            )
            self.assertEqual(login_response.status_code, 200)

            stored_credential = next(
                value
                for key, value in app.USERS[self.username].items()
                if key == "password" or key.startswith("password_")
            )
            credential_key = next(
                key
                for key in app.USERS[self.username]
                if key == "password" or key.startswith("password_")
            )
            self.assertNotEqual(
                credential_key,
                "password",
                "the application expects a plaintext password field",
            )
            self.assertNotEqual(
                stored_credential,
                self.password,
                "the password was stored verbatim",
            )
            try:
                self.assertTrue(
                    check_password_hash(stored_credential, self.password),
                    "the stored credential cannot verify the password",
                )
            except ValueError as error:
                self.fail(f"the stored credential is not a password hash: {error}")


if __name__ == "__main__":
    unittest.main()
