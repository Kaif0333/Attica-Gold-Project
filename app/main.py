from datetime import datetime

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import or_
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from app.database import engine, get_db
from app.migrations import run_migrations
from app.models import Appointment, User
from app.routers import auth
from app.security import hash_password, verify_password
from app.settings import get_settings

settings = get_settings()

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


def set_flash(request: Request, message: str, category: str = "info") -> None:
    request.session["flash"] = {"message": message, "category": category}


def pop_flash(request: Request):
    return request.session.pop("flash", None)


if settings.auto_run_migrations:
    run_migrations()
ensure_admin_user()


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response


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
        {"flash": pop_flash(request)},
    )


@app.post("/login")
def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password):
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Invalid credentials"},
            status_code=401,
        )

    request.session["user_id"] = user.id
    request.session["user"] = user.email
    request.session["role"] = user.role or "client"
    set_flash(request, "Welcome back.", "success")
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse("/dashboard", status_code=303)
    return templates.TemplateResponse(
        request,
        "register.html",
        {"flash": pop_flash(request)},
    )


@app.post("/register")
def register(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        return templates.TemplateResponse(
            request,
            "register.html",
            {"error": "Email already registered"},
            status_code=400,
        )

    if len(password) < 6:
        return templates.TemplateResponse(
            request,
            "register.html",
            {"error": "Password must be at least 6 characters"},
            status_code=400,
        )

    new_user = User(email=email, password=hash_password(password), role="client")
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    request.session["user_id"] = new_user.id
    request.session["user"] = new_user.email
    request.session["role"] = new_user.role
    set_flash(request, "Registration successful.", "success")
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    user_email = request.session.get("user")
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
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "user_email": user_email,
            "appointments": appointments,
            "flash": pop_flash(request),
        },
    )


@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse("/login", status_code=303)
    if request.session.get("role") != "admin":
        set_flash(request, "Admin access required.", "error")
        return RedirectResponse("/dashboard", status_code=303)

    users = db.query(User).order_by(User.id.desc()).all()
    appointments = db.query(Appointment).order_by(Appointment.created_at.desc()).all()
    return templates.TemplateResponse(
        request,
        "admin.html",
        {
            "users": users,
            "appointments": appointments,
            "flash": pop_flash(request),
        },
    )


@app.post("/book-appointment")
def book_appointment(
    request: Request,
    date: str = Form(...),
    time: str = Form(...),
    db: Session = Depends(get_db),
):
    user_id = request.session.get("user_id")
    user_email = request.session.get("user")
    if not user_id or not user_email:
        return RedirectResponse("/login", status_code=303)

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
    set_flash(request, "Appointment booked successfully.", "success")
    return RedirectResponse("/dashboard", status_code=303)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    set_flash(request, "You have been logged out.", "info")
    return RedirectResponse("/login", status_code=303)
