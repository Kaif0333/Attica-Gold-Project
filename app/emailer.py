import smtplib
from email.message import EmailMessage

from app.settings import get_settings


def send_otp_email(to_email: str, otp_code: str, purpose: str) -> None:
    settings = get_settings()
    if not settings.smtp_enabled:
        return

    if not settings.smtp_host or not settings.smtp_sender_email:
        raise RuntimeError("SMTP is enabled but SMTP_HOST/SMTP_SENDER_EMAIL are not configured.")

    subject = f"Attica Gold OTP for {purpose.title()}"
    message = EmailMessage()
    sender_display = f"{settings.smtp_sender_name} <{settings.smtp_sender_email}>"
    message["Subject"] = subject
    message["From"] = sender_display
    message["To"] = to_email
    message.set_content(
        "\n".join(
            [
                "Your Attica Gold one-time password (OTP):",
                "",
                otp_code,
                "",
                f"This OTP expires in {settings.otp_ttl_seconds} seconds.",
                "If you did not request this, please ignore this email.",
            ]
        )
    )

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as smtp:
        if settings.smtp_use_tls:
            smtp.starttls()
        if settings.smtp_username:
            smtp.login(settings.smtp_username, settings.smtp_password)
        smtp.send_message(message)


def _send_email(to_email: str, subject: str, lines: list[str]) -> None:
    settings = get_settings()
    if not settings.smtp_enabled:
        return
    if not settings.smtp_host or not settings.smtp_sender_email:
        raise RuntimeError("SMTP is enabled but SMTP_HOST/SMTP_SENDER_EMAIL are not configured.")

    message = EmailMessage()
    sender_display = f"{settings.smtp_sender_name} <{settings.smtp_sender_email}>"
    message["Subject"] = subject
    message["From"] = sender_display
    message["To"] = to_email
    message.set_content("\n".join(lines))

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as smtp:
        if settings.smtp_use_tls:
            smtp.starttls()
        if settings.smtp_username:
            smtp.login(settings.smtp_username, settings.smtp_password)
        smtp.send_message(message)


def send_inquiry_created_email(
    to_email: str,
    *,
    inquiry_id: int,
    name: str,
    email: str,
    phone: str | None,
    city: str | None,
    service: str | None,
    message: str,
) -> None:
    subject = f"New Inquiry #{inquiry_id} - {name}"
    lines = [
        "A new Attica inquiry was submitted.",
        "",
        f"Inquiry ID: {inquiry_id}",
        f"Name: {name}",
        f"Email: {email}",
        f"Phone: {phone or '-'}",
        f"City: {city or '-'}",
        f"Service: {service or 'general'}",
        "",
        "Message:",
        message,
        "",
        "Review and assign this inquiry from the admin console.",
    ]
    _send_email(to_email, subject, lines)


def send_inquiry_assignment_email(
    to_email: str,
    *,
    inquiry_id: int,
    name: str,
    email: str,
    city: str | None,
    service: str | None,
    note: str | None,
) -> None:
    subject = f"Inquiry Assigned #{inquiry_id} - {name}"
    lines = [
        "An inquiry has been assigned to your Attica staff/admin account.",
        "",
        f"Inquiry ID: {inquiry_id}",
        f"Name: {name}",
        f"Email: {email}",
        f"City: {city or '-'}",
        f"Service: {service or 'general'}",
        f"Admin Note: {note or '-'}",
        "",
        "Please review and update status from the staff/admin console.",
    ]
    _send_email(to_email, subject, lines)
