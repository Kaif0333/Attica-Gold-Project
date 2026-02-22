from sqlalchemy.orm import Session

from app.models import AuditLog


def log_event(
    db: Session,
    event_type: str,
    user_id: int | None = None,
    user_email: str | None = None,
    ip_address: str | None = None,
    details: str | None = None,
) -> None:
    db.add(
        AuditLog(
            event_type=event_type,
            user_id=user_id,
            user_email=user_email,
            ip_address=ip_address,
            details=details,
        )
    )
    db.commit()
