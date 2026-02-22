from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.login_guard import is_allowed, register_failure, register_success
from app.models import User
from app.security import hash_password, verify_password
from app import schemas

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=schemas.RegisterResponse, status_code=201)
def register(
    user_in: schemas.UserCreate,
    db: Session = Depends(get_db),
):
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
