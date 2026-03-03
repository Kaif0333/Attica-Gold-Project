# Attica Gold Backend

FastAPI web application for appointment booking, OTP-based auth, inquiry management, and admin/staff operations.

## Tech Stack

- Python 3
- FastAPI + Uvicorn
- SQLAlchemy
- Alembic
- Jinja2 templates
- SQLite (default, configurable via `DATABASE_URL`)

## Quick Start (Windows / PowerShell)

1. Clone and enter the repo:
```powershell
git clone https://github.com/Kaif0333/Attica-Gold-Project.git
cd Attica-Gold-Project
```

2. Create and activate virtual environment:
```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```

3. Install dependencies:
```powershell
pip install -r requirements.txt
```

4. Create local env file:
```powershell
Copy-Item .env.example .env
```

5. Run the app:
```powershell
venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8001
```

Open:

- App: `http://127.0.0.1:8001`
- Swagger docs: `http://127.0.0.1:8001/docs`

## Environment Variables

Use `.env.example` as the source of truth. Key groups:

- App/runtime: `APP_NAME`, `ENVIRONMENT`, `DATABASE_URL`
- Session/security: `ATTICA_SECRET_KEY`, `SESSION_HTTPS_ONLY`, `SESSION_SAMESITE`
- Auth limits: `LOGIN_MAX_ATTEMPTS`, `LOGIN_WINDOW_SECONDS`, `LOGIN_LOCKOUT_SECONDS`
- OTP/reset: `OTP_TTL_SECONDS`, `OTP_MAX_RESENDS`, `RESET_TOKEN_TTL_MINUTES`
- SMTP: `SMTP_ENABLED`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`
- Bootstrap admin: `ATTICA_ADMIN_EMAIL`, `ATTICA_ADMIN_PASSWORD`

Production safeguards now enforced:

- `ATTICA_SECRET_KEY` must not be default.
- `SESSION_HTTPS_ONLY` must be enabled.

## Database and Migrations

By default, migrations auto-run on startup when `AUTO_RUN_MIGRATIONS=1`.

Manual migration command:
```powershell
venv\Scripts\python.exe -m alembic upgrade head
```

## Testing

Run all tests:
```powershell
venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py" -v
```

## Security Notes

- Do not commit `.env`.
- If credentials were ever exposed in `.env`, rotate them immediately.
- Keep `EXPOSE_OTP_IN_RESPONSE=0` and `EXPOSE_RESET_TOKEN_IN_RESPONSE=0` outside local development.

## Project Structure

```text
app/                 FastAPI application code
app/routers/         API routers (auth, health, v1 APIs)
alembic/             DB migrations
templates/           Jinja2 templates
static/              CSS/JS assets
tests/               Unit/integration tests
```
