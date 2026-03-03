import os
import unittest
from contextlib import contextmanager

from app.settings import get_settings


@contextmanager
def temporary_env(**updates):
    original = {}
    missing = object()
    for key, value in updates.items():
        original[key] = os.environ.get(key, missing)
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    get_settings.cache_clear()
    try:
        yield
    finally:
        for key, value in original.items():
            if value is missing:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        get_settings.cache_clear()


class SettingsParsingTests(unittest.TestCase):
    def test_invalid_same_site_falls_back_to_default_for_environment(self) -> None:
        with temporary_env(ENVIRONMENT="development", SESSION_SAMESITE="invalid-value"):
            settings = get_settings()
            self.assertEqual(settings.session_same_site, "lax")

        with temporary_env(ENVIRONMENT="production", SESSION_SAMESITE="invalid-value"):
            settings = get_settings()
            self.assertEqual(settings.session_same_site, "strict")

    def test_invalid_numeric_values_fall_back_to_safe_defaults(self) -> None:
        with temporary_env(
            LOGIN_MAX_ATTEMPTS="0",
            LOGIN_WINDOW_SECONDS="-10",
            LOGIN_LOCKOUT_SECONDS="0",
            PASSWORD_MIN_LENGTH="4",
            OTP_TTL_SECONDS="5",
            OTP_MAX_RESENDS="0",
            SMTP_PORT="-1",
        ):
            settings = get_settings()
            self.assertEqual(settings.login_max_attempts, 5)
            self.assertEqual(settings.login_window_seconds, 900)
            self.assertEqual(settings.login_lockout_seconds, 900)
            self.assertEqual(settings.password_min_length, 8)
            self.assertEqual(settings.otp_ttl_seconds, 300)
            self.assertEqual(settings.otp_max_resends, 3)
            self.assertEqual(settings.smtp_port, 587)


if __name__ == "__main__":
    unittest.main()
