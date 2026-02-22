from fastapi import APIRouter

from app.routers import auth

router = APIRouter(prefix="/api/v1", tags=["API v1"])
router.include_router(auth.router)
