import hashlib
import hmac
import re
import secrets

from app.settings import get_settings

settings = get_settings()


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000,
    ).hex()
    return f"{salt}${digest}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    # Support existing plaintext values while migrating old records.
    if "$" not in hashed_password:
        return hmac.compare_digest(plain_password, hashed_password)

    salt, digest = hashed_password.split("$", 1)
    candidate = hashlib.pbkdf2_hmac(
        "sha256",
        plain_password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000,
    ).hex()
    return hmac.compare_digest(candidate, digest)


def validate_password_policy(password: str) -> tuple[bool, str]:
    if len(password) < settings.password_min_length:
        return False, f"Password must be at least {settings.password_min_length} characters."
    if not re.search(r"[A-Z]", password):
        return False, "Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must include at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must include at least one number."
    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "Password must include at least one special character."
    return True, ""


def generate_reset_token() -> str:
    return secrets.token_urlsafe(32)


def hash_reset_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
