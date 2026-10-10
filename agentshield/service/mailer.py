import smtplib
import ssl
from email.message import EmailMessage

from agentshield.config import get_settings


class MailDeliveryError(RuntimeError):
    pass


def send_account_email(recipient: str, subject: str, link: str, action: str) -> None:
    settings = get_settings()
    if not settings.smtp_host or not settings.smtp_from_email:
        raise MailDeliveryError("Email delivery is not configured.")
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.smtp_from_email
    message["To"] = recipient
    message.set_content(
        f"{action}\n\nUse this one-time link before it expires:\n{link}\n\n"
        "If you did not request this, you can ignore this email."
    )
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as client:
            client.ehlo()
            if settings.smtp_starttls:
                client.starttls(context=ssl.create_default_context())
                client.ehlo()
            if settings.smtp_username:
                client.login(settings.smtp_username, settings.smtp_password)
            client.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        raise MailDeliveryError("Unable to deliver account email.") from exc
