"""
Snarelytics — Generic IMAP provider (covers Yahoo, iCloud, Zoho, or any
IMAP-accessible mailbox)

Unlike Gmail and Outlook, most consumer IMAP providers — Yahoo included —
don't offer a practical OAuth flow for third-party apps like this one.
The standard, widely-supported alternative is IMAP login using an
account-specific "app password" (a second password generated specifically
for third-party apps, separate from the account's real login password).

This is written against the same EmailProvider interface as Gmail and
Outlook — the poller has no idea this one doesn't use OAuth at all.

Security note: unlike OAuth tokens (which are scoped and revocable),
an IMAP app password is a real credential with mailbox access. It is
stored in the local database the same way OAuth tokens are (see the
"known limitation, disclosed" note in SETUP_GMAIL.md — the same caveat
applies here, arguably more so since this is a real password rather
than a scoped, revocable token).
"""

import re
import imaplib
import email
from email.header import decode_header

from .base import EmailProvider

# Folder-name defaults for well-known IMAP hosts. IMAP doesn't standardize
# folder names, so different providers call their Spam/Junk folder
# different things — this is what lets "Connect Yahoo" pre-fill a sane
# default without the user having to know IMAP internals.
KNOWN_HOST_PRESETS = {
    "yahoo":   {"host": "imap.mail.yahoo.com", "port": 993, "spam_folder": "Bulk Mail", "trash_folder": "Trash"},
    "icloud":  {"host": "imap.mail.me.com",    "port": 993, "spam_folder": "Junk",      "trash_folder": "Deleted Messages"},
    "zoho":    {"host": "imap.zoho.com",       "port": 993, "spam_folder": "Spam",      "trash_folder": "Trash"},
    "aol":     {"host": "imap.aol.com",        "port": 993, "spam_folder": "Spam",      "trash_folder": "Trash"},
}
QUARANTINE_FOLDER_NAME = "Snarelytics Quarantine"


class IMAPProvider(EmailProvider):
    provider_name = "imap"

    def __init__(self, account_row, get_db):
        super().__init__(account_row, get_db)
        self._conn = None

    def ensure_fresh_credentials(self):
        # There's no token to refresh here — IMAP login happens fresh each
        # poll cycle using the stored app password. If the password has
        # been revoked on the provider's side, this will raise cleanly and
        # the shared poller's per-account try/except will log it and move on.
        self._conn = imaplib.IMAP4_SSL(self.account["imap_host"], self.account["imap_port"])
        self._conn.login(self.account["username"], self.account["app_password"])
        self._ensure_quarantine_folder()

    def _ensure_quarantine_folder(self):
        typ, folders = self._conn.list()
        existing = any(QUARANTINE_FOLDER_NAME.encode() in f for f in (folders or []) if f)
        if not existing:
            self._conn.create(QUARANTINE_FOLDER_NAME)

    def _folder_name(self, folder):
        return "INBOX" if folder == "inbox" else self.account["spam_folder"]

    def list_new_message_ids(self, folder, is_first_poll):
        typ, _ = self._conn.select(self._folder_name(folder), readonly=False)
        if typ != "OK":
            return []  # folder doesn't exist on this account (e.g. no Spam folder) — skip quietly

        criteria = "ALL"
        if is_first_poll:
            from datetime import datetime, timedelta
            since = (datetime.utcnow() - timedelta(days=1)).strftime("%d-%b-%Y")
            criteria = f"SINCE {since}"

        typ, data = self._conn.uid("search", None, criteria)
        if typ != "OK" or not data or not data[0]:
            return []
        return data[0].split()  # list of UID bytes, most recent last

    def fetch_normalized_message(self, msg_id):
        typ, data = self._conn.uid("fetch", msg_id, "(RFC822)")
        if typ != "OK" or not data or not data[0]:
            return {"sender": "", "subject": "", "body": "", "raw_headers": ""}

        raw_bytes = data[0][1]
        msg = email.message_from_bytes(raw_bytes)

        subject = self._decode_mime_header(msg.get("Subject", ""))
        sender = self._decode_mime_header(msg.get("From", ""))
        raw_headers = "\n".join(f"{k}: {v}" for k, v in msg.items())
        body = self._extract_body(msg)

        return {"sender": sender, "subject": subject, "body": body, "raw_headers": raw_headers}

    def quarantine_message(self, msg_id, folder):
        self._conn.select(self._folder_name(folder), readonly=False)
        self._conn.uid("copy", msg_id, QUARANTINE_FOLDER_NAME)
        self._conn.uid("store", msg_id, "+FLAGS", "(\\Deleted)")
        self._conn.expunge()

    def delete_message(self, msg_id):
        # The message currently lives in the Quarantine folder (that's
        # where quarantine_message() already put it) — select that, not
        # the original inbox/spam folder, then copy to Trash and expunge
        # from Quarantine. Falls back to a direct expunge (no Trash copy)
        # if this account's provider doesn't have a usable Trash folder.
        self._conn.select(QUARANTINE_FOLDER_NAME, readonly=False)
        trash_folder = self.account["trash_folder"] if self.account["trash_folder"] else None
        if trash_folder:
            try:
                self._conn.uid("copy", msg_id, trash_folder)
            except Exception:
                pass  # Trash folder name wrong/missing for this account — still expunge below
        self._conn.uid("store", msg_id, "+FLAGS", "(\\Deleted)")
        self._conn.expunge()

    def __del__(self):
        # Best-effort cleanup — a new provider instance is created fresh
        # each poll cycle (see poller.py), so connections shouldn't pile up
        # even without this, but closing cleanly is good IMAP citizenship.
        try:
            if self._conn:
                self._conn.logout()
        except Exception:
            pass

    @staticmethod
    def _decode_mime_header(raw):
        if not raw:
            return ""
        parts = decode_header(raw)
        decoded = ""
        for text, enc in parts:
            if isinstance(text, bytes):
                decoded += text.decode(enc or "utf-8", errors="ignore")
            else:
                decoded += text
        return decoded

    @staticmethod
    def _extract_body(msg):
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                disp = str(part.get("Content-Disposition", ""))
                if ctype == "text/plain" and "attachment" not in disp:
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        return part.get_payload(decode=True).decode(charset, errors="ignore")
                    except Exception:
                        continue
            # No plain-text part found — fall back to stripped HTML
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        html = part.get_payload(decode=True).decode(charset, errors="ignore")
                        return re.sub(r"<[^>]+>", " ", html)
                    except Exception:
                        continue
            return ""
        else:
            charset = msg.get_content_charset() or "utf-8"
            try:
                payload = msg.get_payload(decode=True).decode(charset, errors="ignore")
            except Exception:
                return ""
            if msg.get_content_type() == "text/html":
                return re.sub(r"<[^>]+>", " ", payload)
            return payload
