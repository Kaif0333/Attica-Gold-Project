import secrets

from fastapi import Request


def get_or_create_csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


def validate_csrf_token(request: Request, submitted_token: str) -> bool:
    session_token = request.session.get("csrf_token")
    if not session_token or not submitted_token:
        return False
    return secrets.compare_digest(session_token, submitted_token)
