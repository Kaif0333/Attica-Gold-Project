import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


def _load_env_file() -> None:
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_env_file()


def _as_bool(value: str, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _as_int(value: str, default: int) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    app_name: str
    environment: str
    database_url: str
    secret_key: str
    session_https_only: bool
    session_same_site: str
    docs_enabled: bool
    redoc_enabled: bool
    auto_run_migrations: bool
    log_level: str
    request_id_header: str
    login_max_attempts: int
    login_window_seconds: int
    login_lockout_seconds: int
    password_min_length: int
    reset_token_ttl_minutes: int
    expose_reset_token_in_response: bool
    otp_ttl_seconds: int
    expose_otp_in_response: bool
    otp_resend_cooldown_seconds: int
    otp_max_resends: int
    smtp_enabled: bool
    smtp_host: str
    smtp_port: int
    smtp_username: str
    smtp_password: str
    smtp_use_tls: bool
    smtp_sender_email: str
    smtp_sender_name: str
    admin_email: str
    admin_password: str


@lru_cache
def get_settings() -> Settings:
    environment = os.getenv("ENVIRONMENT", "development")
    docs_default = environment != "production"
    session_https_default = environment == "production"
    session_same_site_default = "strict" if environment == "production" else "lax"
    docs_enabled = _as_bool(os.getenv("DOCS_ENABLED"), default=docs_default)
    redoc_enabled = _as_bool(os.getenv("REDOC_ENABLED"), default=docs_default)
    auto_run_migrations = _as_bool(
        os.getenv("AUTO_RUN_MIGRATIONS"),
        default=environment != "production",
    )

    return Settings(
        app_name=os.getenv("APP_NAME", "Attica Gold Backend"),
        environment=environment,
        database_url=os.getenv("DATABASE_URL", "sqlite:///./attica_gold.db"),
        secret_key=os.getenv("ATTICA_SECRET_KEY", "attica-gold-secret-key"),
        session_https_only=_as_bool(
            os.getenv("SESSION_HTTPS_ONLY"),
            default=session_https_default,
        ),
        session_same_site=os.getenv("SESSION_SAMESITE", session_same_site_default).strip().lower(),
        docs_enabled=docs_enabled,
        redoc_enabled=redoc_enabled,
        auto_run_migrations=auto_run_migrations,
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        request_id_header=os.getenv("REQUEST_ID_HEADER", "X-Request-ID"),
        login_max_attempts=_as_int(os.getenv("LOGIN_MAX_ATTEMPTS"), default=5),
        login_window_seconds=_as_int(os.getenv("LOGIN_WINDOW_SECONDS"), default=900),
        login_lockout_seconds=_as_int(os.getenv("LOGIN_LOCKOUT_SECONDS"), default=900),
        password_min_length=_as_int(os.getenv("PASSWORD_MIN_LENGTH"), default=8),
        reset_token_ttl_minutes=_as_int(os.getenv("RESET_TOKEN_TTL_MINUTES"), default=30),
        expose_reset_token_in_response=_as_bool(
            os.getenv("EXPOSE_RESET_TOKEN_IN_RESPONSE"),
            default=environment != "production",
        ),
        otp_ttl_seconds=_as_int(os.getenv("OTP_TTL_SECONDS"), default=300),
        expose_otp_in_response=_as_bool(
            os.getenv("EXPOSE_OTP_IN_RESPONSE"),
            default=environment != "production",
        ),
        otp_resend_cooldown_seconds=_as_int(
            os.getenv("OTP_RESEND_COOLDOWN_SECONDS"),
            default=45,
        ),
        otp_max_resends=_as_int(os.getenv("OTP_MAX_RESENDS"), default=3),
        smtp_enabled=_as_bool(os.getenv("SMTP_ENABLED"), default=False),
        smtp_host=os.getenv("SMTP_HOST", ""),
        smtp_port=_as_int(os.getenv("SMTP_PORT"), default=587),
        smtp_username=os.getenv("SMTP_USERNAME", ""),
        smtp_password=os.getenv("SMTP_PASSWORD", ""),
        smtp_use_tls=_as_bool(os.getenv("SMTP_USE_TLS"), default=True),
        smtp_sender_email=os.getenv("SMTP_SENDER_EMAIL", ""),
        smtp_sender_name=os.getenv("SMTP_SENDER_NAME", "Attica Gold"),
        admin_email=os.getenv("ATTICA_ADMIN_EMAIL", ""),
        admin_password=os.getenv("ATTICA_ADMIN_PASSWORD", ""),
    )
