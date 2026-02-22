from pathlib import Path

from alembic import command
from alembic.config import Config

from app.settings import get_settings


def run_migrations() -> None:
    settings = get_settings()
    alembic_ini = Path(__file__).resolve().parent.parent / "alembic.ini"

    config = Config(str(alembic_ini))
    config.set_main_option("sqlalchemy.url", settings.database_url)
    command.upgrade(config, "head")
