from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String
from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    role = Column(String, nullable=False, default="client")
    reset_token_hash = Column(String, nullable=True)
    reset_token_expires_at = Column(DateTime, nullable=True)


class Appointment(Base):
    __tablename__ = "appointments"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=True)
    user_email = Column(String, index=True, nullable=False)
    status = Column(String, nullable=False, default="scheduled")
    date = Column(String, nullable=False)
    time = Column(String, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class AppointmentEvent(Base):
    __tablename__ = "appointment_events"

    id = Column(Integer, primary_key=True, index=True)
    appointment_id = Column(Integer, index=True, nullable=False)
    action = Column(String, index=True, nullable=False)
    actor_id = Column(Integer, index=True, nullable=True)
    actor_email = Column(String, index=True, nullable=True)
    actor_role = Column(String, nullable=True)
    note = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String, index=True, nullable=False)
    user_id = Column(Integer, index=True, nullable=True)
    user_email = Column(String, index=True, nullable=True)
    ip_address = Column(String, nullable=True)
    details = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


class Inquiry(Base):
    __tablename__ = "inquiries"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, index=True, nullable=False)
    phone = Column(String, nullable=True)
    city = Column(String, nullable=True)
    service = Column(String, nullable=True)
    message = Column(String, nullable=False)
    status = Column(String, nullable=False, default="new")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
