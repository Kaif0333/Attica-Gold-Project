from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import or_
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from app.csrf import get_or_create_csrf_token, validate_csrf_token
from app.audit import log_event
from app.database import engine, get_db
from app.emailer import send_otp_email
from app.login_guard import is_allowed, register_failure, register_success
from app.migrations import run_migrations
from app.models import Appointment, AuditLog, User
from app.observability import configure_logging, request_logging_middleware
from app.routers import api_v1, auth, health
from app.security import (
    generate_otp_code,
    generate_reset_token,
    hash_password,
    hash_reset_token,
    validate_password_policy,
    verify_hashed_token,
    verify_password,
)
from app.settings import get_settings

settings = get_settings()
logger = configure_logging()
ALLOWED_ROLES = {"client", "staff", "admin"}

app = FastAPI(
    title=settings.app_name,
    docs_url="/docs" if settings.docs_enabled else None,
    redoc_url="/redoc" if settings.redoc_enabled else None,
)
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    same_site=settings.session_same_site,
    https_only=settings.session_https_only,
)

app.include_router(auth.router)
app.include_router(api_v1.router)
app.include_router(health.router)


def ensure_admin_user() -> None:
    admin_email = settings.admin_email
    admin_password = settings.admin_password
    if not admin_email or not admin_password:
        return

    with Session(engine) as db:
        admin = db.query(User).filter(User.email == admin_email).first()
        if admin:
            if admin.role != "admin":
                admin.role = "admin"
                db.commit()
            return

        user = User(
            email=admin_email,
            password=hash_password(admin_password),
            role="admin",
        )
        db.add(user)
        db.commit()
        log_event(
            db,
            event_type="ADMIN_BOOTSTRAP_CREATED",
            user_id=user.id,
            user_email=user.email,
            details="Admin user created from environment configuration.",
        )


def validate_runtime_configuration() -> None:
    if not settings.smtp_enabled:
        return

    missing = []
    if not settings.smtp_host:
        missing.append("SMTP_HOST")
    if not settings.smtp_sender_email:
        missing.append("SMTP_SENDER_EMAIL")
    if not settings.smtp_username:
        missing.append("SMTP_USERNAME")
    if not settings.smtp_password:
        missing.append("SMTP_PASSWORD")

    if missing:
        raise RuntimeError(
            "SMTP_ENABLED=1 but required SMTP settings are missing: " + ", ".join(missing)
        )


def set_flash(request: Request, message: str, category: str = "info") -> None:
    request.session["flash"] = {"message": message, "category": category}


def pop_flash(request: Request):
    return request.session.pop("flash", None)


def client_ip(request: Request) -> str:
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _set_pending_otp(request: Request, action: str, payload: dict) -> str | None:
    now_ts = int(datetime.now(timezone.utc).timestamp())
    otp_code = generate_otp_code()
    request.session["pending_otp"] = {
        "action": action,
        "payload": payload,
        "otp_hash": hash_reset_token(otp_code),
        "expires_ts": now_ts + settings.otp_ttl_seconds,
        "resend_count": 0,
        "resend_available_ts": now_ts + settings.otp_resend_cooldown_seconds,
    }
    return otp_code


def _get_pending_otp(request: Request):
    return request.session.get("pending_otp")


def _clear_pending_otp(request: Request) -> None:
    request.session.pop("pending_otp", None)


if settings.auto_run_migrations:
    run_migrations()
validate_runtime_configuration()
ensure_admin_user()


app.middleware("http")(request_logging_middleware(logger))


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    request_id = getattr(request.state, "request_id", "unknown")
    logger.exception(
        "Unhandled error request_id=%s method=%s path=%s",
        request_id,
        request.method,
        request.url.path,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "request_id": request_id},
    )


@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse("/dashboard", status_code=303)
    return templates.TemplateResponse(
        request,
        "home.html",
        {
            "flash": pop_flash(request),
        },
    )


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse("/dashboard", status_code=303)
    return templates.TemplateResponse(
        request,
        "login.html",
        {"flash": pop_flash(request), "csrf_token": get_or_create_csrf_token(request)},
    )


@app.get("/verify-otp", response_class=HTMLResponse)
def verify_otp_page(request: Request):
    pending = _get_pending_otp(request)
    if not pending:
        set_flash(request, "No OTP challenge in progress.", "error")
        return RedirectResponse("/login", status_code=303)

    return templates.TemplateResponse(
        request,
        "verify_otp.html",
        {
            "csrf_token": get_or_create_csrf_token(request),
            "target_email": pending.get("payload", {}).get("email", ""),
            "action": pending.get("action", "login"),
        },
    )


@app.post("/verify-otp")
def verify_otp(
    request: Request,
    otp_code: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    pending = _get_pending_otp(request)
    if not pending:
        set_flash(request, "No OTP challenge in progress.", "error")
        return RedirectResponse("/login", status_code=303)

    if not validate_csrf_token(request, csrf_token):
        return templates.TemplateResponse(
            request,
            "verify_otp.html",
            {
                "error": "Invalid security token. Please refresh and try again.",
                "csrf_token": get_or_create_csrf_token(request),
                "target_email": pending.get("payload", {}).get("email", ""),
                "action": pending.get("action", "login"),
            },
            status_code=403,
        )

    expires_ts = pending.get("expires_ts", 0)
    if int(datetime.now(timezone.utc).timestamp()) > int(expires_ts):
        _clear_pending_otp(request)
        set_flash(request, "OTP expired. Please try again.", "error")
        return RedirectResponse("/login", status_code=303)

    if not verify_hashed_token(otp_code, pending.get("otp_hash", "")):
        return templates.TemplateResponse(
            request,
            "verify_otp.html",
            {
                "error": "Invalid OTP code.",
                "csrf_token": get_or_create_csrf_token(request),
                "target_email": pending.get("payload", {}).get("email", ""),
                "action": pending.get("action", "login"),
            },
            status_code=400,
        )

    action = pending.get("action")
    payload = pending.get("payload", {})
    ip = client_ip(request)

    if action == "register":
        email = payload.get("email")
        password_hash = payload.get("password_hash")
        if not email or not password_hash:
            _clear_pending_otp(request)
            set_flash(request, "Invalid OTP payload. Please register again.", "error")
            return RedirectResponse("/register", status_code=303)

        existing_user = db.query(User).filter(User.email == email).first()
        if existing_user:
            _clear_pending_otp(request)
            set_flash(request, "Email already registered.", "error")
            return RedirectResponse("/login", status_code=303)

        new_user = User(email=email, password=password_hash, role="client")
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        log_event(db, "USER_REGISTERED", user_id=new_user.id, user_email=new_user.email, ip_address=ip)

        request.session["user_id"] = new_user.id
        request.session["user"] = new_user.email
        request.session["role"] = new_user.role
        _clear_pending_otp(request)
        set_flash(request, "Registration completed with OTP verification.", "success")
        return RedirectResponse("/dashboard", status_code=303)

    if action == "login":
        user_id = payload.get("user_id")
        email = payload.get("email")
        role = payload.get("role", "client")
        if not user_id or not email:
            _clear_pending_otp(request)
            set_flash(request, "Invalid OTP payload. Please login again.", "error")
            return RedirectResponse("/login", status_code=303)

        request.session["user_id"] = user_id
        request.session["user"] = email
        request.session["role"] = role
        _clear_pending_otp(request)
        log_event(db, "LOGIN_SUCCESS", user_id=user_id, user_email=email, ip_address=ip)
        set_flash(request, "Welcome back. OTP verification complete.", "success")
        return RedirectResponse("/dashboard", status_code=303)

    _clear_pending_otp(request)
    set_flash(request, "Unknown OTP action.", "error")
    return RedirectResponse("/login", status_code=303)


@app.post("/resend-otp")
def resend_otp(
    request: Request,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    pending = _get_pending_otp(request)
    if not pending:
        set_flash(request, "No OTP challenge in progress.", "error")
        return RedirectResponse("/login", status_code=303)

    if not validate_csrf_token(request, csrf_token):
        return templates.TemplateResponse(
            request,
            "verify_otp.html",
            {
                "error": "Invalid security token. Please refresh and try again.",
                "csrf_token": get_or_create_csrf_token(request),
                "target_email": pending.get("payload", {}).get("email", ""),
                "action": pending.get("action", "login"),
            },
            status_code=403,
        )

    now_ts = int(datetime.now(timezone.utc).timestamp())
    if now_ts > int(pending.get("expires_ts", 0)):
        _clear_pending_otp(request)
        set_flash(request, "OTP expired. Please try again.", "error")
        return RedirectResponse("/login", status_code=303)

    resend_count = int(pending.get("resend_count", 0))
    if resend_count >= settings.otp_max_resends:
        _clear_pending_otp(request)
        set_flash(request, "Maximum OTP resend attempts reached. Start again.", "error")
        return RedirectResponse("/login", status_code=303)

    resend_available_ts = int(pending.get("resend_available_ts", 0))
    if now_ts < resend_available_ts:
        wait_seconds = resend_available_ts - now_ts
        return templates.TemplateResponse(
            request,
            "verify_otp.html",
            {
                "error": f"Please wait {wait_seconds} seconds before requesting another OTP.",
                "csrf_token": get_or_create_csrf_token(request),
                "target_email": pending.get("payload", {}).get("email", ""),
                "action": pending.get("action", "login"),
            },
            status_code=429,
        )

    otp_code = generate_otp_code()
    pending["otp_hash"] = hash_reset_token(otp_code)
    pending["expires_ts"] = now_ts + settings.otp_ttl_seconds
    pending["resend_count"] = resend_count + 1
    pending["resend_available_ts"] = now_ts + settings.otp_resend_cooldown_seconds
    request.session["pending_otp"] = pending

    target_email = pending.get("payload", {}).get("email", "")
    action = pending.get("action", "login")
    try:
        if settings.smtp_enabled:
            send_otp_email(target_email, otp_code=otp_code, purpose=action)
    except Exception as exc:
        logger.exception("Failed to resend OTP email: %s", exc)
        return templates.TemplateResponse(
            request,
            "verify_otp.html",
            {
                "error": "Could not resend OTP email. Please try again later.",
                "csrf_token": get_or_create_csrf_token(request),
                "target_email": target_email,
                "action": action,
            },
            status_code=500,
        )

    return templates.TemplateResponse(
        request,
        "verify_otp.html",
        {
            "message": "A new OTP has been sent.",
            "csrf_token": get_or_create_csrf_token(request),
            "target_email": target_email,
            "action": action,
            "otp_preview": otp_code if settings.expose_otp_in_response else None,
        },
    )


@app.post("/login")
def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    if not validate_csrf_token(request, csrf_token):
        log_event(db, "LOGIN_CSRF_FAILED", user_email=email, ip_address=client_ip(request))
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "error": "Invalid security token. Please refresh and try again.",
                "csrf_token": get_or_create_csrf_token(request),
            },
            status_code=403,
        )

    ip = client_ip(request)
    allowed, retry_after = is_allowed(email=email, client_ip=ip)
    if not allowed:
        log_event(db, "LOGIN_BLOCKED", user_email=email, ip_address=ip, details="Rate limit lockout.")
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "error": f"Too many failed attempts. Try again in {retry_after} seconds.",
                "csrf_token": get_or_create_csrf_token(request),
            },
            status_code=429,
        )

    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password):
        still_open, lockout_for = register_failure(email=email, client_ip=ip)
        message = "Invalid credentials"
        status = 401
        if not still_open:
            message = f"Too many failed attempts. Try again in {lockout_for} seconds."
            status = 429
            log_event(db, "LOGIN_LOCKOUT", user_email=email, ip_address=ip)
        else:
            log_event(db, "LOGIN_FAILED", user_email=email, ip_address=ip)
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": message, "csrf_token": get_or_create_csrf_token(request)},
            status_code=status,
        )

    register_success(email=email, client_ip=ip)
    if not settings.smtp_enabled and not settings.expose_otp_in_response:
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "error": "OTP delivery is not configured. Contact support.",
                "csrf_token": get_or_create_csrf_token(request),
            },
            status_code=500,
        )
    otp_preview = _set_pending_otp(
        request,
        action="login",
        payload={"user_id": user.id, "email": user.email, "role": user.role or "client"},
    )
    try:
        pending = _get_pending_otp(request)
        if pending:
            send_otp_email(user.email, otp_code=otp_preview or "", purpose="login")
    except Exception as exc:
        logger.exception("Failed to send OTP email for login: %s", exc)
        log_event(db, "LOGIN_OTP_SEND_FAILED", user_id=user.id, user_email=user.email, ip_address=ip)
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "error": "Could not send OTP email. Please try again later.",
                "csrf_token": get_or_create_csrf_token(request),
            },
            status_code=500,
        )
    log_event(db, "LOGIN_OTP_ISSUED", user_id=user.id, user_email=user.email, ip_address=ip)
    return templates.TemplateResponse(
        request,
        "verify_otp.html",
        {
            "message": "Enter the OTP to complete login.",
            "csrf_token": get_or_create_csrf_token(request),
            "target_email": user.email,
            "action": "login",
            "otp_preview": otp_preview if settings.expose_otp_in_response else None,
        },
    )


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse("/dashboard", status_code=303)
    return templates.TemplateResponse(
        request,
        "register.html",
        {"flash": pop_flash(request), "csrf_token": get_or_create_csrf_token(request)},
    )


@app.post("/register")
def register(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    if not validate_csrf_token(request, csrf_token):
        return templates.TemplateResponse(
            request,
            "register.html",
            {
                "error": "Invalid security token. Please refresh and try again.",
                "csrf_token": get_or_create_csrf_token(request),
            },
            status_code=403,
        )

    password_ok, password_error = validate_password_policy(password)
    if not password_ok:
        return templates.TemplateResponse(
            request,
            "register.html",
            {"error": password_error, "csrf_token": get_or_create_csrf_token(request)},
            status_code=400,
        )

    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        return templates.TemplateResponse(
            request,
            "register.html",
            {"error": "Email already registered", "csrf_token": get_or_create_csrf_token(request)},
            status_code=400,
        )

    hashed_password = hash_password(password)
    if not settings.smtp_enabled and not settings.expose_otp_in_response:
        return templates.TemplateResponse(
            request,
            "register.html",
            {
                "error": "OTP delivery is not configured. Contact support.",
                "csrf_token": get_or_create_csrf_token(request),
            },
            status_code=500,
        )
    otp_preview = _set_pending_otp(
        request,
        action="register",
        payload={"email": email, "password_hash": hashed_password},
    )
    try:
        pending = _get_pending_otp(request)
        if pending:
            send_otp_email(email, otp_code=otp_preview or "", purpose="registration")
    except Exception as exc:
        logger.exception("Failed to send OTP email for registration: %s", exc)
        log_event(db, "REGISTER_OTP_SEND_FAILED", user_email=email, ip_address=client_ip(request))
        return templates.TemplateResponse(
            request,
            "register.html",
            {
                "error": "Could not send OTP email. Please try again later.",
                "csrf_token": get_or_create_csrf_token(request),
            },
            status_code=500,
        )
    log_event(db, "REGISTER_OTP_ISSUED", user_email=email, ip_address=client_ip(request))
    return templates.TemplateResponse(
        request,
        "verify_otp.html",
        {
            "message": "Enter the OTP to complete registration.",
            "csrf_token": get_or_create_csrf_token(request),
            "target_email": email,
            "action": "register",
            "otp_preview": otp_preview if settings.expose_otp_in_response else None,
        },
    )


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    user_email = request.session.get("user")
    user_role = request.session.get("role", "client")
    if not user_id or not user_email:
        return RedirectResponse("/login", status_code=303)

    appointments = (
        db.query(Appointment)
        .filter(
            or_(
                Appointment.user_id == user_id,
                Appointment.user_email == user_email,
            )
        )
        .order_by(Appointment.created_at.desc())
        .all()
    )

    total_appointments = len(appointments)
    latest_appointment = appointments[0] if appointments else None
    role_metrics = {
        "total_appointments": total_appointments,
        "latest_appointment_label": (
            f"{latest_appointment.date} at {latest_appointment.time}" if latest_appointment else "None"
        ),
    }

    if user_role in {"staff", "admin"}:
        all_appointments_count = db.query(Appointment).count()
        staff_count = db.query(User).filter(User.role == "staff").count()
        role_metrics["global_appointments"] = all_appointments_count
        role_metrics["staff_count"] = staff_count

    if user_role == "admin":
        total_users = db.query(User).count()
        admin_count = db.query(User).filter(User.role == "admin").count()
        role_metrics["total_users"] = total_users
        role_metrics["admin_count"] = admin_count

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "user_email": user_email,
            "user_role": user_role,
            "role_metrics": role_metrics,
            "appointments": appointments,
            "flash": pop_flash(request),
            "csrf_token": get_or_create_csrf_token(request),
        },
    )


@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=303)
    if request.session.get("role") != "admin":
        log_event(
            db,
            "ADMIN_ACCESS_DENIED",
            user_id=user_id,
            user_email=request.session.get("user"),
            ip_address=client_ip(request),
        )
        set_flash(request, "Admin access required.", "error")
        return RedirectResponse("/dashboard", status_code=303)

    users = db.query(User).order_by(User.id.desc()).all()
    appointments = db.query(Appointment).order_by(Appointment.created_at.desc()).all()
    audit_logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(100).all()
    return templates.TemplateResponse(
        request,
        "admin.html",
        {
            "users": users,
            "appointments": appointments,
            "audit_logs": audit_logs,
            "csrf_token": get_or_create_csrf_token(request),
            "flash": pop_flash(request),
        },
    )


@app.get("/admin/bootstrap-status")
def admin_bootstrap_status(request: Request, db: Session = Depends(get_db)):
    actor_id = request.session.get("user_id")
    actor_email = request.session.get("user")
    actor_role = request.session.get("role")
    ip = client_ip(request)

    if not actor_id:
        return RedirectResponse("/login", status_code=303)
    if actor_role != "admin":
        log_event(
            db,
            "ADMIN_BOOTSTRAP_STATUS_DENIED",
            user_id=actor_id,
            user_email=actor_email,
            ip_address=ip,
            details="Non-admin tried to view bootstrap status.",
        )
        set_flash(request, "Admin access required.", "error")
        return RedirectResponse("/dashboard", status_code=303)

    configured = bool(settings.admin_email and settings.admin_password)
    admin_user = None
    if settings.admin_email:
        admin_user = db.query(User).filter(User.email == settings.admin_email).first()

    return {
        "bootstrap_configured": configured,
        "bootstrap_email": settings.admin_email or None,
        "admin_user_exists": bool(admin_user),
        "admin_user_role": admin_user.role if admin_user else None,
    }


@app.post("/admin/users/{target_user_id}/role")
def update_user_role(
    request: Request,
    target_user_id: int,
    role: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    actor_id = request.session.get("user_id")
    actor_email = request.session.get("user")
    actor_role = request.session.get("role")
    ip = client_ip(request)

    if not actor_id:
        return RedirectResponse("/login", status_code=303)
    if actor_role != "admin":
        log_event(
            db,
            "ADMIN_ROLE_CHANGE_DENIED",
            user_id=actor_id,
            user_email=actor_email,
            ip_address=ip,
            details="Non-admin tried to change role.",
        )
        set_flash(request, "Admin access required.", "error")
        return RedirectResponse("/dashboard", status_code=303)

    if not validate_csrf_token(request, csrf_token):
        log_event(
            db,
            "ADMIN_ROLE_CHANGE_DENIED",
            user_id=actor_id,
            user_email=actor_email,
            ip_address=ip,
            details="Invalid CSRF token.",
        )
        set_flash(request, "Invalid security token. Please refresh and try again.", "error")
        return RedirectResponse("/admin", status_code=303)

    if role not in ALLOWED_ROLES:
        log_event(
            db,
            "ADMIN_ROLE_CHANGE_DENIED",
            user_id=actor_id,
            user_email=actor_email,
            ip_address=ip,
            details=f"Invalid role value: {role}",
        )
        set_flash(request, "Invalid role selected.", "error")
        return RedirectResponse("/admin", status_code=303)

    target_user = db.query(User).filter(User.id == target_user_id).first()
    if not target_user:
        set_flash(request, "Target user not found.", "error")
        return RedirectResponse("/admin", status_code=303)

    # Safety rule: do not allow self-demotion from admin in current session.
    if target_user.id == actor_id and role != "admin":
        log_event(
            db,
            "ADMIN_ROLE_CHANGE_DENIED",
            user_id=actor_id,
            user_email=actor_email,
            ip_address=ip,
            details="Self-demotion blocked.",
        )
        set_flash(request, "You cannot demote your own admin account.", "error")
        return RedirectResponse("/admin", status_code=303)

    previous_role = target_user.role
    if previous_role == "admin" and role != "admin":
        admin_count = db.query(User).filter(User.role == "admin").count()
        if admin_count <= 1:
            log_event(
                db,
                "ADMIN_ROLE_CHANGE_DENIED",
                user_id=actor_id,
                user_email=actor_email,
                ip_address=ip,
                details="Cannot demote last admin.",
            )
            set_flash(request, "At least one admin account must remain.", "error")
            return RedirectResponse("/admin", status_code=303)

    target_user.role = role
    db.commit()
    log_event(
        db,
        "ADMIN_ROLE_UPDATED",
        user_id=actor_id,
        user_email=actor_email,
        ip_address=ip,
        details=f"Changed user {target_user.email} role from {previous_role} to {role}.",
    )
    set_flash(request, "User role updated successfully.", "success")
    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/smtp-check")
def smtp_check(
    request: Request,
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    actor_id = request.session.get("user_id")
    actor_email = request.session.get("user")
    actor_role = request.session.get("role")
    ip = client_ip(request)

    if not actor_id:
        return RedirectResponse("/login", status_code=303)
    if actor_role != "admin":
        log_event(
            db,
            "SMTP_CHECK_DENIED",
            user_id=actor_id,
            user_email=actor_email,
            ip_address=ip,
            details="Non-admin tried SMTP check.",
        )
        set_flash(request, "Admin access required.", "error")
        return RedirectResponse("/dashboard", status_code=303)

    if not validate_csrf_token(request, csrf_token):
        log_event(
            db,
            "SMTP_CHECK_DENIED",
            user_id=actor_id,
            user_email=actor_email,
            ip_address=ip,
            details="Invalid CSRF token.",
        )
        set_flash(request, "Invalid security token. Please refresh and try again.", "error")
        return RedirectResponse("/admin", status_code=303)

    if not settings.smtp_enabled:
        set_flash(request, "SMTP is disabled. Set SMTP_ENABLED=1 in .env.", "error")
        return RedirectResponse("/admin", status_code=303)

    try:
        send_otp_email(
            to_email=actor_email,
            otp_code="123456",
            purpose="smtp connectivity test",
        )
        log_event(
            db,
            "SMTP_CHECK_SUCCESS",
            user_id=actor_id,
            user_email=actor_email,
            ip_address=ip,
            details="SMTP test email sent to admin.",
        )
        set_flash(request, f"SMTP test email sent to {actor_email}.", "success")
    except Exception as exc:
        logger.exception("SMTP test failed: %s", exc)
        log_event(
            db,
            "SMTP_CHECK_FAILED",
            user_id=actor_id,
            user_email=actor_email,
            ip_address=ip,
            details=str(exc),
        )
        set_flash(request, "SMTP test failed. Check SMTP credentials and host.", "error")

    return RedirectResponse("/admin", status_code=303)


@app.get("/forgot-password", response_class=HTMLResponse)
def forgot_password_page(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse("/dashboard", status_code=303)
    return templates.TemplateResponse(
        request,
        "forgot_password.html",
        {"csrf_token": get_or_create_csrf_token(request), "flash": pop_flash(request)},
    )


@app.post("/forgot-password", response_class=HTMLResponse)
def forgot_password(
    request: Request,
    email: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    if not validate_csrf_token(request, csrf_token):
        return templates.TemplateResponse(
            request,
            "forgot_password.html",
            {
                "error": "Invalid security token. Please refresh and try again.",
                "csrf_token": get_or_create_csrf_token(request),
            },
            status_code=403,
        )

    message = "If the account exists, reset instructions have been generated."
    reset_token = None
    user = db.query(User).filter(User.email == email).first()
    if user:
        raw_token = generate_reset_token()
        user.reset_token_hash = hash_reset_token(raw_token)
        user.reset_token_expires_at = datetime.now(timezone.utc) + timedelta(
            minutes=settings.reset_token_ttl_minutes
        )
        db.commit()
        log_event(
            db,
            "PASSWORD_RESET_TOKEN_ISSUED",
            user_id=user.id,
            user_email=user.email,
            ip_address=client_ip(request),
        )
        if settings.expose_reset_token_in_response:
            reset_token = raw_token

    return templates.TemplateResponse(
        request,
        "forgot_password.html",
        {
            "message": message,
            "reset_token": reset_token,
            "csrf_token": get_or_create_csrf_token(request),
        },
    )


@app.get("/reset-password", response_class=HTMLResponse)
def reset_password_page(request: Request, token: str = ""):
    if request.session.get("user_id"):
        return RedirectResponse("/dashboard", status_code=303)
    return templates.TemplateResponse(
        request,
        "reset_password.html",
        {"token": token, "csrf_token": get_or_create_csrf_token(request)},
    )


@app.post("/reset-password", response_class=HTMLResponse)
def reset_password(
    request: Request,
    token: str = Form(...),
    new_password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    if not validate_csrf_token(request, csrf_token):
        return templates.TemplateResponse(
            request,
            "reset_password.html",
            {
                "error": "Invalid security token. Please refresh and try again.",
                "token": token,
                "csrf_token": get_or_create_csrf_token(request),
            },
            status_code=403,
        )

    password_ok, password_error = validate_password_policy(new_password)
    if not password_ok:
        return templates.TemplateResponse(
            request,
            "reset_password.html",
            {
                "error": password_error,
                "token": token,
                "csrf_token": get_or_create_csrf_token(request),
            },
            status_code=400,
        )

    token_hash = hash_reset_token(token)
    user = db.query(User).filter(User.reset_token_hash == token_hash).first()
    if not user or not user.reset_token_expires_at:
        return templates.TemplateResponse(
            request,
            "reset_password.html",
            {
                "error": "Invalid or expired reset token.",
                "token": token,
                "csrf_token": get_or_create_csrf_token(request),
            },
            status_code=400,
        )

    now = datetime.now(timezone.utc)
    expires_at = user.reset_token_expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < now:
        return templates.TemplateResponse(
            request,
            "reset_password.html",
            {
                "error": "Invalid or expired reset token.",
                "token": token,
                "csrf_token": get_or_create_csrf_token(request),
            },
            status_code=400,
        )

    user.password = hash_password(new_password)
    user.reset_token_hash = None
    user.reset_token_expires_at = None
    db.commit()
    log_event(
        db,
        "PASSWORD_RESET_COMPLETED",
        user_id=user.id,
        user_email=user.email,
        ip_address=client_ip(request),
    )
    set_flash(request, "Password reset successful. Please login.", "success")
    return RedirectResponse("/login", status_code=303)


@app.post("/book-appointment")
def book_appointment(
    request: Request,
    date: str = Form(...),
    time: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    user_id = request.session.get("user_id")
    user_email = request.session.get("user")
    if not user_id or not user_email:
        return RedirectResponse("/login", status_code=303)
    if not validate_csrf_token(request, csrf_token):
        set_flash(request, "Invalid security token. Please refresh and try again.", "error")
        return RedirectResponse("/dashboard", status_code=303)

    try:
        datetime.strptime(date, "%Y-%m-%d")
        datetime.strptime(time, "%H:%M")
    except ValueError:
        set_flash(request, "Invalid date or time format.", "error")
        return RedirectResponse("/dashboard", status_code=303)

    appointment = Appointment(
        user_id=user_id,
        user_email=user_email,
        date=date,
        time=time,
    )
    db.add(appointment)
    db.commit()
    log_event(
        db,
        "APPOINTMENT_BOOKED",
        user_id=user_id,
        user_email=user_email,
        ip_address=client_ip(request),
        details=f"{date} {time}",
    )
    set_flash(request, "Appointment booked successfully.", "success")
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/logout")
def logout(request: Request):
    user_id = request.session.get("user_id")
    user_email = request.session.get("user")
    with Session(engine) as db:
        if user_id or user_email:
            log_event(
                db,
                "LOGOUT",
                user_id=user_id,
                user_email=user_email,
                ip_address=client_ip(request),
            )
    request.session.clear()
    set_flash(request, "You have been logged out.", "info")
    return RedirectResponse("/login", status_code=303)
