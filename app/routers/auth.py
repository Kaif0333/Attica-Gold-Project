from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.login_guard import is_allowed, register_failure, register_success
from app.models import User
from app.security import (
    generate_reset_token,
    hash_password,
    hash_reset_token,
    validate_password_policy,
    verify_password,
)
from app.settings import get_settings
from app import schemas

router = APIRouter(prefix="/auth", tags=["Authentication"])
settings = get_settings()


@router.post("/register", response_model=schemas.RegisterResponse, status_code=201)
def register(
    user_in: schemas.UserCreate,
    db: Session = Depends(get_db),
):
    password_ok, password_error = validate_password_policy(user_in.password)
    if not password_ok:
        raise HTTPException(status_code=400, detail=password_error)

    existing_user = db.query(User).filter(User.email == user_in.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        email=user_in.email,
        password=hash_password(user_in.password),
        role="client",
    )

    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Email already registered")
    db.refresh(user)

    return {"message": "User registered successfully", "user": user}


@router.post("/login", response_model=schemas.AuthMessage)
def login(
    request: Request,
    user_in: schemas.UserLogin,
    db: Session = Depends(get_db),
):
    client_ip = request.client.host if request.client and request.client.host else "unknown"
    allowed, retry_after = is_allowed(email=user_in.email, client_ip=client_ip)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed attempts. Try again in {retry_after} seconds",
        )

    user = db.query(User).filter(User.email == user_in.email).first()

    if not user or not verify_password(user_in.password, user.password):
        still_open, lockout_for = register_failure(email=user_in.email, client_ip=client_ip)
        if not still_open:
            raise HTTPException(
                status_code=429,
                detail=f"Too many failed attempts. Try again in {lockout_for} seconds",
            )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    register_success(email=user_in.email, client_ip=client_ip)
    return {"message": "Login successful"}


@router.post("/forgot-password", response_model=schemas.ForgotPasswordResponse)
def forgot_password(
    payload: schemas.ForgotPasswordRequest,
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.email == payload.email).first()
    token_for_response = None
    if user:
        raw_token = generate_reset_token()
        user.reset_token_hash = hash_reset_token(raw_token)
        user.reset_token_expires_at = datetime.now(timezone.utc) + timedelta(
            minutes=settings.reset_token_ttl_minutes
        )
        db.commit()
        if settings.expose_reset_token_in_response:
            token_for_response = raw_token

    return {
        "message": "If the account exists, reset instructions have been generated.",
        "reset_token": token_for_response,
    }


@router.post("/reset-password", response_model=schemas.AuthMessage)
def reset_password(
    payload: schemas.ResetPasswordRequest,
    db: Session = Depends(get_db),
):
    password_ok, password_error = validate_password_policy(payload.new_password)
    if not password_ok:
        raise HTTPException(status_code=400, detail=password_error)

    token_hash = hash_reset_token(payload.token)
    user = db.query(User).filter(User.reset_token_hash == token_hash).first()
    if not user or not user.reset_token_expires_at:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    now = datetime.now(timezone.utc)
    expires_at = user.reset_token_expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < now:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    user.password = hash_password(payload.new_password)
    user.reset_token_hash = None
    user.reset_token_expires_at = None
    db.commit()

    return {"message": "Password has been reset successfully"}
