import unittest
import uuid

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import User
from app.security import hash_password


class WebFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()

    def test_register_login_book_and_user_isolation(self) -> None:
        email1 = f"user1_{uuid.uuid4().hex[:8]}@example.com"
        email2 = f"user2_{uuid.uuid4().hex[:8]}@example.com"

        # Register and book an appointment as user 1.
        register_1 = self.client.post(
            "/register",
            data={"email": email1, "password": "pass1234"},
            follow_redirects=False,
        )
        self.assertEqual(register_1.status_code, 303)

        book_1 = self.client.post(
            "/book-appointment",
            data={"date": "2026-03-05", "time": "09:45"},
            follow_redirects=False,
        )
        self.assertEqual(book_1.status_code, 303)

        self.client.get("/logout", follow_redirects=False)

        # Register and book as user 2.
        register_2 = self.client.post(
            "/register",
            data={"email": email2, "password": "pass1234"},
            follow_redirects=False,
        )
        self.assertEqual(register_2.status_code, 303)

        book_2 = self.client.post(
            "/book-appointment",
            data={"date": "2026-03-06", "time": "10:15"},
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
        email = f"user_{uuid.uuid4().hex[:8]}@example.com"
        self.client.post(
            "/register",
            data={"email": email, "password": "pass1234"},
            follow_redirects=False,
        )

        bad_book = self.client.post(
            "/book-appointment",
            data={"date": "invalid-date", "time": "bad-time"},
            follow_redirects=False,
        )
        self.assertEqual(bad_book.status_code, 303)

        dashboard = self.client.get("/dashboard")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn("Invalid date or time format.", dashboard.text)

    def test_admin_access_control(self) -> None:
        email = f"admin_{uuid.uuid4().hex[:8]}@example.com"
        db = SessionLocal()
        try:
            admin_user = User(email=email, password=hash_password("pass1234"), role="admin")
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
            data={"email": email, "password": "pass1234"},
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
        email = f"apiv1_{uuid.uuid4().hex[:8]}@example.com"
        register = self.client.post(
            "/api/v1/auth/register",
            json={"email": email, "password": "pass1234"},
        )
        login = self.client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": "pass1234"},
        )
        self.assertEqual(register.status_code, 201)
        self.assertEqual(login.status_code, 200)


if __name__ == "__main__":
    unittest.main()
