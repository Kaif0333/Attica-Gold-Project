import unittest
import uuid
import re
import os

os.environ["EXPOSE_OTP_IN_RESPONSE"] = "1"
os.environ["EXPOSE_RESET_TOKEN_IN_RESPONSE"] = "1"
os.environ["SMTP_ENABLED"] = "0"

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.login_guard import clear_attempts_for_tests
from app.main import app
from app.models import Appointment, AppointmentEvent, User
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

    def _otp_from_response(self, response_text: str) -> str:
        match = re.search(r"Dev OTP: <code>([^<]+)</code>", response_text)
        self.assertIsNotNone(match)
        return match.group(1)

    def _register_with_otp(self, email: str, password: str) -> None:
        register = self.client.post(
            "/register",
            data={
                "email": email,
                "password": password,
                "csrf_token": self._csrf_token_from_page("/register"),
            },
        )
        self.assertEqual(register.status_code, 200)
        otp = self._otp_from_response(register.text)

        verify = self.client.post(
            "/verify-otp",
            data={"otp_code": otp, "csrf_token": self._csrf_token_from_page("/verify-otp")},
            follow_redirects=False,
        )
        self.assertEqual(verify.status_code, 303)

    def _login_with_otp(self, email: str, password: str) -> int:
        login = self.client.post(
            "/login",
            data={
                "email": email,
                "password": password,
                "csrf_token": self._csrf_token_from_page("/login"),
            },
            follow_redirects=False,
        )
        if login.status_code != 200:
            return login.status_code

        otp = self._otp_from_response(login.text)
        verify = self.client.post(
            "/verify-otp",
            data={"otp_code": otp, "csrf_token": self._csrf_token_from_page("/verify-otp")},
            follow_redirects=False,
        )
        return verify.status_code

    def test_register_login_book_and_user_isolation(self) -> None:
        strong_password = "Pass#1234"
        email1 = f"user1_{uuid.uuid4().hex[:8]}@example.com"
        email2 = f"user2_{uuid.uuid4().hex[:8]}@example.com"

        # Register and book an appointment as user 1.
        self._register_with_otp(email1, strong_password)

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
        self._register_with_otp(email2, strong_password)

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
        self._register_with_otp(email, strong_password)

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
        login_status = self._login_with_otp(email, strong_password)
        self.assertEqual(login_status, 303)

        admin_page = self.client.get("/admin")
        self.assertEqual(admin_page.status_code, 200)
        self.assertIn("Admin Console", admin_page.text)
        self.assertIn("Recent Audit Logs", admin_page.text)

    def test_request_id_header_is_present(self) -> None:
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn("X-Request-ID", response.headers)

    def test_security_headers_are_applied(self) -> None:
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertIn("Content-Security-Policy", response.headers)
        # Tests run in development defaults, so HSTS should not be forced.
        self.assertNotIn("Strict-Transport-Security", response.headers)

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

        self._register_with_otp(email, original_password)
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

        old_login_status = self._login_with_otp(email, original_password)
        self.assertEqual(old_login_status, 401)

        new_login_status = self._login_with_otp(email, new_password)
        self.assertEqual(new_login_status, 303)

    def test_admin_can_update_user_role(self) -> None:
        strong_password = "Pass#1234"
        admin_email = f"admin_role_{uuid.uuid4().hex[:8]}@example.com"
        target_email = f"target_role_{uuid.uuid4().hex[:8]}@example.com"

        db = SessionLocal()
        try:
            admin_user = User(email=admin_email, password=hash_password(strong_password), role="admin")
            target_user = User(email=target_email, password=hash_password(strong_password), role="client")
            db.add(admin_user)
            db.add(target_user)
            db.commit()
            db.refresh(target_user)
            target_id = target_user.id
        finally:
            db.close()

        login_status = self._login_with_otp(admin_email, strong_password)
        self.assertEqual(login_status, 303)

        update = self.client.post(
            f"/admin/users/{target_id}/role",
            data={"role": "staff", "csrf_token": self._csrf_token_from_page("/admin")},
            follow_redirects=False,
        )
        self.assertEqual(update.status_code, 303)
        self.assertEqual(update.headers.get("location"), "/admin")

        db = SessionLocal()
        try:
            updated_user = db.query(User).filter(User.id == target_id).first()
            self.assertIsNotNone(updated_user)
            self.assertEqual(updated_user.role, "staff")
        finally:
            db.close()

    def test_admin_self_demotion_is_blocked(self) -> None:
        strong_password = "Pass#1234"
        admin_email = f"admin_self_{uuid.uuid4().hex[:8]}@example.com"

        db = SessionLocal()
        try:
            admin_user = User(email=admin_email, password=hash_password(strong_password), role="admin")
            db.add(admin_user)
            db.commit()
            db.refresh(admin_user)
            admin_id = admin_user.id
        finally:
            db.close()

        login_status = self._login_with_otp(admin_email, strong_password)
        self.assertEqual(login_status, 303)

        demote = self.client.post(
            f"/admin/users/{admin_id}/role",
            data={"role": "client", "csrf_token": self._csrf_token_from_page("/admin")},
            follow_redirects=False,
        )
        self.assertEqual(demote.status_code, 303)
        self.assertEqual(demote.headers.get("location"), "/admin")

        db = SessionLocal()
        try:
            still_admin = db.query(User).filter(User.id == admin_id).first()
            self.assertIsNotNone(still_admin)
            self.assertEqual(still_admin.role, "admin")
        finally:
            db.close()

    def test_admin_smtp_check_when_disabled(self) -> None:
        strong_password = "Pass#1234"
        admin_email = f"admin_smtp_{uuid.uuid4().hex[:8]}@example.com"

        db = SessionLocal()
        try:
            admin_user = User(email=admin_email, password=hash_password(strong_password), role="admin")
            db.add(admin_user)
            db.commit()
        finally:
            db.close()

        login_status = self._login_with_otp(admin_email, strong_password)
        self.assertEqual(login_status, 303)

        smtp_check = self.client.post(
            "/admin/smtp-check",
            data={"csrf_token": self._csrf_token_from_page("/admin")},
            follow_redirects=False,
        )
        self.assertEqual(smtp_check.status_code, 303)
        self.assertEqual(smtp_check.headers.get("location"), "/admin")

        admin_page = self.client.get("/admin")
        self.assertIn("SMTP is disabled", admin_page.text)

    def test_admin_bootstrap_status_endpoint(self) -> None:
        strong_password = "Pass#1234"
        admin_email = f"admin_bootstrap_{uuid.uuid4().hex[:8]}@example.com"

        db = SessionLocal()
        try:
            admin_user = User(email=admin_email, password=hash_password(strong_password), role="admin")
            db.add(admin_user)
            db.commit()
        finally:
            db.close()

        anonymous = self.client.get("/admin/bootstrap-status", follow_redirects=False)
        self.assertEqual(anonymous.status_code, 303)
        self.assertEqual(anonymous.headers.get("location"), "/login")

        login_status = self._login_with_otp(admin_email, strong_password)
        self.assertEqual(login_status, 303)

        status = self.client.get("/admin/bootstrap-status")
        self.assertEqual(status.status_code, 200)
        payload = status.json()
        self.assertIn("bootstrap_configured", payload)
        self.assertIn("bootstrap_email", payload)
        self.assertIn("admin_user_exists", payload)
        self.assertIn("admin_user_role", payload)

    def test_dashboard_personalization_for_admin_role(self) -> None:
        strong_password = "Pass#1234"
        admin_email = f"admin_dash_{uuid.uuid4().hex[:8]}@example.com"

        db = SessionLocal()
        try:
            admin_user = User(email=admin_email, password=hash_password(strong_password), role="admin")
            db.add(admin_user)
            db.commit()
        finally:
            db.close()

        login_status = self._login_with_otp(admin_email, strong_password)
        self.assertEqual(login_status, 303)

        dashboard = self.client.get("/dashboard")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn("Admin Dashboard", dashboard.text)
        self.assertIn("Governance Snapshot", dashboard.text)
        self.assertIn("Open Admin Console", dashboard.text)

    def test_staff_console_access_control(self) -> None:
        strong_password = "Pass#1234"
        staff_email = f"staff_{uuid.uuid4().hex[:8]}@example.com"
        client_email = f"client_{uuid.uuid4().hex[:8]}@example.com"

        db = SessionLocal()
        try:
            staff_user = User(email=staff_email, password=hash_password(strong_password), role="staff")
            client_user = User(email=client_email, password=hash_password(strong_password), role="client")
            db.add(staff_user)
            db.add(client_user)
            db.commit()
        finally:
            db.close()

        anonymous = self.client.get("/staff", follow_redirects=False)
        self.assertEqual(anonymous.status_code, 303)
        self.assertEqual(anonymous.headers.get("location"), "/login")

        client_login = self._login_with_otp(client_email, strong_password)
        self.assertEqual(client_login, 303)
        denied = self.client.get("/staff", follow_redirects=False)
        self.assertEqual(denied.status_code, 303)
        self.assertEqual(denied.headers.get("location"), "/dashboard")

        self.client.get("/logout", follow_redirects=False)
        staff_login = self._login_with_otp(staff_email, strong_password)
        self.assertEqual(staff_login, 303)
        staff_page = self.client.get("/staff")
        self.assertEqual(staff_page.status_code, 200)
        self.assertIn("Staff Console", staff_page.text)

    def test_staff_can_reschedule_note_and_cancel_appointment(self) -> None:
        strong_password = "Pass#1234"
        staff_email = f"staff_ops_{uuid.uuid4().hex[:8]}@example.com"
        client_email = f"client_ops_{uuid.uuid4().hex[:8]}@example.com"

        db = SessionLocal()
        try:
            staff_user = User(email=staff_email, password=hash_password(strong_password), role="staff")
            client_user = User(email=client_email, password=hash_password(strong_password), role="client")
            db.add(staff_user)
            db.add(client_user)
            db.commit()
            db.refresh(client_user)

            appointment = Appointment(
                user_id=client_user.id,
                user_email=client_email,
                date="2026-03-10",
                time="11:00",
            )
            db.add(appointment)
            db.commit()
            db.refresh(appointment)
            appointment_id = appointment.id
        finally:
            db.close()

        staff_login = self._login_with_otp(staff_email, strong_password)
        self.assertEqual(staff_login, 303)

        reschedule = self.client.post(
            f"/staff/appointments/{appointment_id}/reschedule",
            data={
                "date": "2026-03-12",
                "time": "14:30",
                "csrf_token": self._csrf_token_from_page("/staff"),
            },
            follow_redirects=False,
        )
        self.assertEqual(reschedule.status_code, 303)
        self.assertEqual(reschedule.headers.get("location"), "/staff")

        note = self.client.post(
            f"/staff/appointments/{appointment_id}/note",
            data={
                "note": "Customer asked for follow-up call.",
                "csrf_token": self._csrf_token_from_page("/staff"),
            },
            follow_redirects=False,
        )
        self.assertEqual(note.status_code, 303)
        self.assertEqual(note.headers.get("location"), "/staff")

        db = SessionLocal()
        try:
            updated = db.query(Appointment).filter(Appointment.id == appointment_id).first()
            self.assertIsNotNone(updated)
            self.assertEqual(updated.date, "2026-03-12")
            self.assertEqual(updated.time, "14:30")
            self.assertEqual(updated.status, "rescheduled")
        finally:
            db.close()

        cancel = self.client.post(
            f"/staff/appointments/{appointment_id}/cancel",
            data={"csrf_token": self._csrf_token_from_page("/staff")},
            follow_redirects=False,
        )
        self.assertEqual(cancel.status_code, 303)
        self.assertEqual(cancel.headers.get("location"), "/staff")

        db = SessionLocal()
        try:
            cancelled = db.query(Appointment).filter(Appointment.id == appointment_id).first()
            self.assertIsNotNone(cancelled)
            self.assertEqual(cancelled.status, "cancelled")

            events = db.query(AppointmentEvent).filter(AppointmentEvent.appointment_id == appointment_id).all()
            actions = {event.action for event in events}
            self.assertIn("rescheduled", actions)
            self.assertIn("note_added", actions)
            self.assertIn("cancelled", actions)
        finally:
            db.close()

    def test_admin_can_export_appointments_csv(self) -> None:
        strong_password = "Pass#1234"
        admin_email = f"admin_export_{uuid.uuid4().hex[:8]}@example.com"
        client_email = f"client_export_{uuid.uuid4().hex[:8]}@example.com"

        db = SessionLocal()
        try:
            admin_user = User(email=admin_email, password=hash_password(strong_password), role="admin")
            client_user = User(email=client_email, password=hash_password(strong_password), role="client")
            db.add(admin_user)
            db.add(client_user)
            db.commit()
            db.refresh(client_user)

            appointment = Appointment(
                user_id=client_user.id,
                user_email=client_email,
                date="2026-04-01",
                time="10:00",
                status="scheduled",
            )
            db.add(appointment)
            db.commit()
        finally:
            db.close()

        unauthorized = self.client.get("/admin/reports/appointments.csv", follow_redirects=False)
        self.assertEqual(unauthorized.status_code, 303)
        self.assertEqual(unauthorized.headers.get("location"), "/login")

        login_status = self._login_with_otp(admin_email, strong_password)
        self.assertEqual(login_status, 303)
        exported = self.client.get("/admin/reports/appointments.csv")
        self.assertEqual(exported.status_code, 200)
        self.assertEqual(exported.headers.get("content-type"), "text/csv; charset=utf-8")
        self.assertIn("attachment; filename=\"appointments_report.csv\"", exported.headers.get("content-disposition", ""))
        self.assertIn("status", exported.text)
        self.assertIn(client_email, exported.text)

    def test_staff_can_complete_appointment(self) -> None:
        strong_password = "Pass#1234"
        staff_email = f"staff_complete_{uuid.uuid4().hex[:8]}@example.com"
        client_email = f"client_complete_{uuid.uuid4().hex[:8]}@example.com"

        db = SessionLocal()
        try:
            staff_user = User(email=staff_email, password=hash_password(strong_password), role="staff")
            client_user = User(email=client_email, password=hash_password(strong_password), role="client")
            db.add(staff_user)
            db.add(client_user)
            db.commit()
            db.refresh(client_user)

            appointment = Appointment(
                user_id=client_user.id,
                user_email=client_email,
                date="2026-04-02",
                time="15:15",
                status="scheduled",
            )
            db.add(appointment)
            db.commit()
            db.refresh(appointment)
            appointment_id = appointment.id
        finally:
            db.close()

        login_status = self._login_with_otp(staff_email, strong_password)
        self.assertEqual(login_status, 303)
        complete = self.client.post(
            f"/staff/appointments/{appointment_id}/complete",
            data={"csrf_token": self._csrf_token_from_page("/staff")},
            follow_redirects=False,
        )
        self.assertEqual(complete.status_code, 303)
        self.assertEqual(complete.headers.get("location"), "/staff")

        db = SessionLocal()
        try:
            done = db.query(Appointment).filter(Appointment.id == appointment_id).first()
            self.assertIsNotNone(done)
            self.assertEqual(done.status, "completed")
            events = db.query(AppointmentEvent).filter(AppointmentEvent.appointment_id == appointment_id).all()
            actions = {event.action for event in events}
            self.assertIn("completed", actions)
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
