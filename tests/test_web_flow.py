import unittest
import uuid
import re

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.login_guard import clear_attempts_for_tests
from app.main import app
from app.models import User
from app.security import hash_password
from app.settings import get_settings


class WebFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        clear_attempts_for_tests()
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()

    def _csrf_token_from_page(self, path: str) -> str:
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200)
        match = re.search(r'name="csrf_token" value="([^"]+)"', response.text)
        self.assertIsNotNone(match)
        return match.group(1)

    def test_register_login_book_and_user_isolation(self) -> None:
        strong_password = "Pass#1234"
        email1 = f"user1_{uuid.uuid4().hex[:8]}@example.com"
        email2 = f"user2_{uuid.uuid4().hex[:8]}@example.com"

        # Register and book an appointment as user 1.
        register_1 = self.client.post(
            "/register",
            data={
                "email": email1,
                "password": strong_password,
                "csrf_token": self._csrf_token_from_page("/register"),
            },
            follow_redirects=False,
        )
        self.assertEqual(register_1.status_code, 303)

        book_1 = self.client.post(
            "/book-appointment",
            data={
                "date": "2026-03-05",
                "time": "09:45",
                "csrf_token": self._csrf_token_from_page("/dashboard"),
            },
            follow_redirects=False,
        )
        self.assertEqual(book_1.status_code, 303)

        self.client.get("/logout", follow_redirects=False)

        # Register and book as user 2.
        register_2 = self.client.post(
            "/register",
            data={
                "email": email2,
                "password": strong_password,
                "csrf_token": self._csrf_token_from_page("/register"),
            },
            follow_redirects=False,
        )
        self.assertEqual(register_2.status_code, 303)

        book_2 = self.client.post(
            "/book-appointment",
            data={
                "date": "2026-03-06",
                "time": "10:15",
                "csrf_token": self._csrf_token_from_page("/dashboard"),
            },
            follow_redirects=False,
        )
        self.assertEqual(book_2.status_code, 303)

        dashboard_2 = self.client.get("/dashboard")
        self.assertEqual(dashboard_2.status_code, 200)
        self.assertIn(email2, dashboard_2.text)
        self.assertIn("2026-03-06", dashboard_2.text)
        self.assertNotIn(email1, dashboard_2.text)
        self.assertNotIn("2026-03-05", dashboard_2.text)

    def test_invalid_booking_shows_error_flash(self) -> None:
        strong_password = "Pass#1234"
        email = f"user_{uuid.uuid4().hex[:8]}@example.com"
        self.client.post(
            "/register",
            data={
                "email": email,
                "password": strong_password,
                "csrf_token": self._csrf_token_from_page("/register"),
            },
            follow_redirects=False,
        )

        bad_book = self.client.post(
            "/book-appointment",
            data={
                "date": "invalid-date",
                "time": "bad-time",
                "csrf_token": self._csrf_token_from_page("/dashboard"),
            },
            follow_redirects=False,
        )
        self.assertEqual(bad_book.status_code, 303)

        dashboard = self.client.get("/dashboard")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn("Invalid date or time format.", dashboard.text)

    def test_admin_access_control(self) -> None:
        strong_password = "Pass#1234"
        email = f"admin_{uuid.uuid4().hex[:8]}@example.com"
        db = SessionLocal()
        try:
            admin_user = User(email=email, password=hash_password(strong_password), role="admin")
            db.add(admin_user)
            db.commit()
        finally:
            db.close()

        # Anonymous user should be redirected to login.
        anonymous_admin = self.client.get("/admin", follow_redirects=False)
        self.assertEqual(anonymous_admin.status_code, 303)
        self.assertEqual(anonymous_admin.headers.get("location"), "/login")

        # Admin login should grant access.
        login = self.client.post(
            "/login",
            data={
                "email": email,
                "password": strong_password,
                "csrf_token": self._csrf_token_from_page("/login"),
            },
            follow_redirects=False,
        )
        self.assertEqual(login.status_code, 303)

        admin_page = self.client.get("/admin")
        self.assertEqual(admin_page.status_code, 200)
        self.assertIn("Admin Console", admin_page.text)

    def test_request_id_header_is_present(self) -> None:
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn("X-Request-ID", response.headers)

    def test_health_and_readiness_endpoints(self) -> None:
        health = self.client.get("/healthz")
        readiness = self.client.get("/readyz")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json().get("status"), "ok")
        self.assertEqual(readiness.status_code, 200)
        self.assertEqual(readiness.json().get("status"), "ready")

    def test_api_v1_auth_routes_work(self) -> None:
        strong_password = "Pass#1234"
        email = f"apiv1_{uuid.uuid4().hex[:8]}@example.com"
        register = self.client.post(
            "/api/v1/auth/register",
            json={"email": email, "password": strong_password},
        )
        login = self.client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": strong_password},
        )
        self.assertEqual(register.status_code, 201)
        self.assertEqual(login.status_code, 200)

    def test_api_login_rate_limit_and_lockout(self) -> None:
        strong_password = "Pass#1234"
        settings = get_settings()
        email = f"limit_{uuid.uuid4().hex[:8]}@example.com"

        self.client.post(
            "/api/v1/auth/register",
            json={"email": email, "password": strong_password},
        )

        last_status = None
        for _ in range(settings.login_max_attempts):
            res = self.client.post(
                "/api/v1/auth/login",
                json={"email": email, "password": "wrong-pass"},
            )
            last_status = res.status_code

        self.assertIn(last_status, [401, 429])

        blocked = self.client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "wrong-pass"},
        )
        self.assertEqual(blocked.status_code, 429)

    def test_web_form_rejects_invalid_csrf(self) -> None:
        email = f"csrf_{uuid.uuid4().hex[:8]}@example.com"
        response = self.client.post(
            "/register",
            data={
                "email": email,
                "password": "Pass#1234",
                "csrf_token": "invalid-token",
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 403)

    def test_web_password_reset_flow(self) -> None:
        original_password = "Pass#1234"
        new_password = "New#5678Pass"
        email = f"reset_{uuid.uuid4().hex[:8]}@example.com"

        register = self.client.post(
            "/register",
            data={
                "email": email,
                "password": original_password,
                "csrf_token": self._csrf_token_from_page("/register"),
            },
            follow_redirects=False,
        )
        self.assertEqual(register.status_code, 303)
        self.client.get("/logout", follow_redirects=False)

        forgot = self.client.post(
            "/forgot-password",
            data={"email": email, "csrf_token": self._csrf_token_from_page("/forgot-password")},
        )
        self.assertEqual(forgot.status_code, 200)
        token_match = re.search(r"Dev reset token: <code>([^<]+)</code>", forgot.text)
        self.assertIsNotNone(token_match)
        reset_token = token_match.group(1)

        reset = self.client.post(
            "/reset-password",
            data={
                "token": reset_token,
                "new_password": new_password,
                "csrf_token": self._csrf_token_from_page(f"/reset-password?token={reset_token}"),
            },
            follow_redirects=False,
        )
        self.assertEqual(reset.status_code, 303)
        self.assertEqual(reset.headers.get("location"), "/login")

        old_login = self.client.post(
            "/login",
            data={
                "email": email,
                "password": original_password,
                "csrf_token": self._csrf_token_from_page("/login"),
            },
            follow_redirects=False,
        )
        self.assertEqual(old_login.status_code, 401)

        new_login = self.client.post(
            "/login",
            data={
                "email": email,
                "password": new_password,
                "csrf_token": self._csrf_token_from_page("/login"),
            },
            follow_redirects=False,
        )
        self.assertEqual(new_login.status_code, 303)


if __name__ == "__main__":
    unittest.main()
