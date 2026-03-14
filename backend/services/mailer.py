import asyncio
import os
import smtplib
from email.message import EmailMessage
from typing import List


def _send_email_sync(subject: str, body: str, recipients: List[str], attachment_name: str, attachment_content: str) -> None:
    host = os.getenv("SMTP_HOST", "")
    port = int(os.getenv("SMTP_PORT", "587") or 587)
    username = os.getenv("SMTP_USERNAME", "")
    password = os.getenv("SMTP_PASSWORD", "")
    sender = os.getenv("SMTP_SENDER", username)
    use_tls = os.getenv("SMTP_USE_TLS", "true").lower() == "true"

    if not host or not sender:
        raise RuntimeError("SMTP is not configured. Set SMTP_HOST and SMTP_SENDER (or SMTP_USERNAME).")

    if not recipients:
        raise RuntimeError("At least one recipient email is required")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg.set_content(body)
    msg.add_attachment(attachment_content.encode("utf-8"), maintype="text", subtype="csv", filename=attachment_name)

    debug = os.getenv("SMTP_DEBUG", "false").lower() == "true"

    # Try STARTTLS first (port 587), with proper EHLO ordering. If that fails
    # (connection closed or TLS error), attempt an SSL connection on port 465.
    try:
        with smtplib.SMTP(host, port, timeout=20) as server:
            if debug:
                server.set_debuglevel(1)
            server.ehlo()
            if use_tls:
                server.starttls()
                server.ehlo()
            if username:
                server.login(username, password)
            server.send_message(msg)
            return
    except Exception as e:
        # Try SSL fallback on 465 if STARTTLS approach failed
        try:
            ssl_port = 465
            with smtplib.SMTP_SSL(host, ssl_port, timeout=20) as server:
                if debug:
                    server.set_debuglevel(1)
                server.ehlo()
                if username:
                    server.login(username, password)
                server.send_message(msg)
                return
        except Exception:
            # Re-raise the original exception to preserve existing error handling
            raise


async def send_report_email(
    recipients: List[str],
    subject: str,
    body: str,
    attachment_name: str,
    attachment_content: str,
) -> None:
    await asyncio.to_thread(
        _send_email_sync,
        subject,
        body,
        recipients,
        attachment_name,
        attachment_content,
    )
