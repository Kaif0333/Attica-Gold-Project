import os
from dataclasses import dataclass
from functools import lru_cache


def _as_bool(value: str, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


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
    admin_email: str
    admin_password: str


@lru_cache
def get_settings() -> Settings:
    environment = os.getenv("ENVIRONMENT", "development")
    docs_default = environment != "production"
    docs_enabled = _as_bool(os.getenv("DOCS_ENABLED"), default=docs_default)
    redoc_enabled = _as_bool(os.getenv("REDOC_ENABLED"), default=docs_default)

    return Settings(
        app_name=os.getenv("APP_NAME", "Attica Gold Backend"),
        environment=environment,
        database_url=os.getenv("DATABASE_URL", "sqlite:///./attica_gold.db"),
        secret_key=os.getenv("ATTICA_SECRET_KEY", "attica-gold-secret-key"),
        session_https_only=_as_bool(os.getenv("SESSION_HTTPS_ONLY"), default=False),
        session_same_site=os.getenv("SESSION_SAMESITE", "lax"),
        docs_enabled=docs_enabled,
        redoc_enabled=redoc_enabled,
        admin_email=os.getenv("ATTICA_ADMIN_EMAIL", ""),
        admin_password=os.getenv("ATTICA_ADMIN_PASSWORD", ""),
    )
