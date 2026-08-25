"""
Snarelytics — outbound email (OTP codes, password resets)

IMPORTANT: Render's free tier blocks all outbound SMTP traffic (ports 25,
465, 587) to prevent spam abuse — this is a platform-wide restriction, not
something fixable with different SMTP credentials. So this sends over
plain HTTPS instead, via Resend's API (https://resend.com) — free tier is
3,000 emails/month, no credit card required, and no domain verification
needed if you send from their shared onboarding@resend.dev address (fine
for a project like this; verify your own domain later if you want emails
to come from your own name).

Configure via one environment variable:

    RESEND_API_KEY   from resend.com/api-keys after creating a free account

Local development (or any host that doesn't block SMTP) can still use the
old SMTP path by setting SMTP_HOST/SMTP_USER/SMTP_PASSWORD instead — this
module tries Resend first, falls back to SMTP if RESEND_API_KEY isn't set,
and falls back further to just logging the message if neither is configured.
"""

import os
import smtplib
import logging
import requests
from email.mime.text import MIMEText

log = logging.getLogger("snarelytics.mailer")

RESEND_API_KEY = os.environ.get("RESEND_API_KEY")
RESEND_FROM = os.environ.get("RESEND_FROM", "Snarelytics <onboarding@resend.dev>")

SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER)


def is_configured():
    return bool(RESEND_API_KEY) or bool(SMTP_HOST and SMTP_USER and SMTP_PASSWORD)


def _send_via_resend(to_addr: str, subject: str, body_text: str) -> bool:
    try:
        r = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
            json={
                "from": RESEND_FROM,
                "to": [to_addr],
                "subject": subject,
                "text": body_text,
            },
            timeout=10,
        )
        if r.status_code >= 400:
            log.error(f"Resend API error sending to {to_addr}: {r.status_code} {r.text}")
            return False
        return True
    except Exception as e:
        log.error(f"Resend API request failed for {to_addr}: {e}")
        return False


def _send_via_smtp(to_addr: str, subject: str, body_text: str) -> bool:
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
        log.error(f"SMTP send failed for {to_addr}: {e}")
        return False


def send_email(to_addr: str, subject: str, body_text: str) -> bool:
    """Returns True if the email was sent, False otherwise (never raises —
    callers decide how to handle a failed send)."""
    if RESEND_API_KEY:
        return _send_via_resend(to_addr, subject, body_text)
    if SMTP_HOST and SMTP_USER and SMTP_PASSWORD:
        return _send_via_smtp(to_addr, subject, body_text)

    log.warning(
        "No email method configured (set RESEND_API_KEY, or SMTP_HOST/SMTP_USER/"
        f"SMTP_PASSWORD for local dev) — email to {to_addr} was NOT sent. "
        f"Message content:\n{body_text}"
    )
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


def send_password_reset_email(to_addr: str, username: str, code: str) -> bool:
    subject = "Your Snarelytics password reset code"
    body = (
        f"Hi {username},\n\n"
        f"Your password reset code is: {code}\n\n"
        f"This code expires in 10 minutes. If you didn't request a password "
        f"reset, you can safely ignore this email — your password hasn't been "
        f"changed.\n\n"
        f"— Snarelytics"
    )
    return send_email(to_addr, subject, body)
