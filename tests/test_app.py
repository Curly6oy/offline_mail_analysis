import io
import os
import re
import unittest

os.environ.setdefault("FLASK_SECRET_KEY", "test-secret-key")
os.environ.setdefault("OFFLINE_MAIL_USERNAME", "test-user")

from werkzeug.security import generate_password_hash

os.environ.setdefault("OFFLINE_MAIL_PASSWORD_HASH", generate_password_hash("test-password"))

from app import app


SAMPLE = b"""From: Ivan Petrov <ivan@example.com>
To: office@example.org
Subject: Test
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Ivan Petrov
Phone: +7 999 123-45-67
Passport: 1234 567890
Visit https://example.com/private-token
"""


class AppTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = app.test_client()

    def _csrf(self):
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
        self.assertIsNotNone(match)
        return match.group(1).decode()

    def _login(self):
        token = self._csrf()
        response = self.client.post(
            "/login",
            data={"username": "test-user", "password": "test-password", "csrf_token": token},
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/check")

    def test_healthz_is_public_and_safe(self):
        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {"status": "ok"})
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_check_requires_login(self):
        response = self.client.get("/check")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_login_and_csrf_protection(self):
        token = self._csrf()
        response = self.client.post(
            "/login",
            data={"username": "test-user", "password": "test-password"},
        )
        self.assertEqual(response.status_code, 400)

        response = self.client.post(
            "/login",
            data={"username": "test-user", "password": "test-password", "csrf_token": token},
        )
        self.assertEqual(response.status_code, 302)

    def test_bad_login_is_rejected(self):
        token = self._csrf()
        response = self.client.post(
            "/login",
            data={"username": "test-user", "password": "wrong", "csrf_token": token},
        )
        self.assertEqual(response.status_code, 401)

    def test_upload_rejects_non_eml(self):
        self._login()
        with self.client.session_transaction() as session:
            token = session["csrf_token"]
        response = self.client.post(
            "/check",
            data={
                "csrf_token": token,
                "email_file": (io.BytesIO(b"not email"), "message.txt"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Поддерживается только .eml".encode(), response.data)

    def test_upload_does_not_render_raw_pii(self):
        self._login()
        with self.client.session_transaction() as session:
            token = session["csrf_token"]
        response = self.client.post(
            "/check",
            data={
                "csrf_token": token,
                "email_file": (io.BytesIO(SAMPLE), "message.eml"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"999 123-45-67", response.data)
        self.assertNotIn(b"1234 567890", response.data)
        self.assertNotIn(b"private-token", response.data)
        self.assertIn(b"example.com", response.data)

    def test_security_headers_are_present(self):
        response = self.client.get("/login")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        self.assertIn("script-src 'none'", response.headers["Content-Security-Policy"])

    def test_missing_upload_is_rejected(self):
        self._login()
        with self.client.session_transaction() as session:
            token = session["csrf_token"]
        response = self.client.post("/check", data={"csrf_token": token})
        self.assertEqual(response.status_code, 400)

    def test_empty_upload_is_rejected(self):
        self._login()
        with self.client.session_transaction() as session:
            token = session["csrf_token"]
        response = self.client.post(
            "/check",
            data={"csrf_token": token, "email_file": (io.BytesIO(b""), "empty.eml")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Файл пустой".encode(), response.data)

    def test_oversized_upload_returns_413(self):
        self._login()
        with self.client.session_transaction() as session:
            token = session["csrf_token"]
        response = self.client.post(
            "/check",
            data={
                "csrf_token": token,
                "email_file": (io.BytesIO(b"x" * (10 * 1024 * 1024 + 1)), "large.eml"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 413)

    def test_logout_requires_csrf(self):
        self._login()
        response = self.client.post("/logout")
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
