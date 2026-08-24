"""
Snarelytics — outbound email (OTP verification codes)

Uses plain SMTP rather than the Gmail/Outlook OAuth integrations, since
those are scoped for READING a user's inbox (to scan it), not sending mail
on the app's behalf — reusing them here would mean requesting a much
broader permission from whoever owns the "from" address than this feature
actually needs.

Configure via environment variables (works with a Gmail account + App
Password, an Outlook/Office365 account, or any transactional email
provider that exposes SMTP — SendGrid, Mailgun, Brevo, etc.):

    SMTP_HOST       e.g. smtp.gmail.com
    SMTP_PORT       e.g. 587
    SMTP_USER       the account/login SMTP authenticates as
    SMTP_PASSWORD   an App Password (NOT your normal account password —
                    Gmail and Outlook both require a separate app-specific
                    password for SMTP; your account password won't work)
    SMTP_FROM       optional — defaults to SMTP_USER

If these aren't set (e.g. local development before you've configured
anything), sending fails loudly in the log with the code included, so you
can still test the verification flow without a real mail account.
"""

import os
import smtplib
import logging
from email.mime.text import MIMEText

log = logging.getLogger("snarelytics.mailer")

SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER)


def is_configured():
    return bool(SMTP_HOST and SMTP_USER and SMTP_PASSWORD)


def send_email(to_addr: str, subject: str, body_text: str) -> bool:
    """Returns True if the email was sent, False otherwise (never raises —
    callers decide how to handle a failed send)."""
    if not is_configured():
        log.warning(
            "SMTP not configured (set SMTP_HOST/SMTP_USER/SMTP_PASSWORD env vars) — "
            f"email to {to_addr} was NOT sent. Message content:\n{body_text}"
        )
        return False

    msg = MIMEText(body_text)
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = to_addr

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM, [to_addr], msg.as_string())
        return True
    except Exception as e:
        log.error(f"Failed to send email to {to_addr}: {e}")
        return False


def send_otp_email(to_addr: str, username: str, code: str) -> bool:
    subject = "Your Snarelytics verification code"
    body = (
        f"Hi {username},\n\n"
        f"Your Snarelytics verification code is: {code}\n\n"
        f"This code expires in 10 minutes. If you didn't request this, "
        f"you can safely ignore this email.\n\n"
        f"— Snarelytics"
    )
    return send_email(to_addr, subject, body)
