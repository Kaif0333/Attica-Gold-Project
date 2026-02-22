import threading
import time

from app.settings import get_settings

settings = get_settings()

_lock = threading.Lock()
_attempts: dict[str, dict[str, float]] = {}


def _now() -> float:
    return time.time()


def _record_key(email: str, client_ip: str) -> str:
    return f"{email.strip().lower()}|{client_ip}"


def is_allowed(email: str, client_ip: str) -> tuple[bool, int]:
    key = _record_key(email, client_ip)
    now = _now()

    with _lock:
        record = _attempts.get(key)
        if not record:
            return True, 0

        locked_until = record.get("locked_until", 0.0)
        if locked_until > now:
            return False, int(locked_until - now)

        first_attempt = record.get("first_attempt", now)
        if now - first_attempt > settings.login_window_seconds:
            _attempts.pop(key, None)

    return True, 0


def register_failure(email: str, client_ip: str) -> tuple[bool, int]:
    key = _record_key(email, client_ip)
    now = _now()

    with _lock:
        record = _attempts.get(key)
        if not record or now - record.get("first_attempt", now) > settings.login_window_seconds:
            record = {
                "first_attempt": now,
                "failed_attempts": 0,
                "locked_until": 0.0,
            }
            _attempts[key] = record

        record["failed_attempts"] += 1
        if record["failed_attempts"] >= settings.login_max_attempts:
            lockout_until = now + settings.login_lockout_seconds
            record["locked_until"] = lockout_until
            record["failed_attempts"] = 0
            record["first_attempt"] = now
            return False, settings.login_lockout_seconds

    return True, 0


def register_success(email: str, client_ip: str) -> None:
    key = _record_key(email, client_ip)
    with _lock:
        _attempts.pop(key, None)


def clear_attempts_for_tests() -> None:
    with _lock:
        _attempts.clear()
