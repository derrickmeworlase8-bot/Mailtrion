"""
Snarelytics — Gmail provider

Implements EmailProvider against the Gmail API. This is a direct,
behavior-preserving extraction of what used to live inline in
gmail_integration.py's polling loop — refactored into the shared
provider interface so Outlook and IMAP providers can be added later
without duplicating (or diverging from) this logic.
"""

import os
import re
import base64
import json
from datetime import datetime

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleRequest
from googleapiclient.discovery import build

from .base import EmailProvider
from paths import DEFAULT_GOOGLE_CLIENT_SECRETS

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
]
QUARANTINE_LABEL_NAME = "Snarelytics/Quarantine"
CLIENT_SECRETS_FILE = os.environ.get("GOOGLE_CLIENT_SECRETS", DEFAULT_GOOGLE_CLIENT_SECRETS)

# Maps Snarelytics's logical folder names to Gmail's own query syntax and
# the system label that should be removed once a message is quarantined.
_FOLDER_CONFIG = {
    "inbox": {"query": "in:inbox", "remove_label": "INBOX", "max_results": 25},
    "spam":  {"query": "in:spam",  "remove_label": "SPAM",  "max_results": 15},
}

_client_config_cache = {}


def _load_client_config():
    if not _client_config_cache:
        # On a hosted deployment (Render, etc.) you generally can't put a
        # secrets file on disk permanently — the filesystem resets on every
        # redeploy. So: prefer GOOGLE_CLIENT_SECRETS_JSON (the whole JSON
        # file's content, pasted as one environment variable) if it's set;
        # fall back to reading an actual file for local development, where
        # a file on disk is simple and persists fine.
        raw_json = os.environ.get("GOOGLE_CLIENT_SECRETS_JSON")
        if raw_json:
            _client_config_cache.update(json.loads(raw_json))
        else:
            with open(CLIENT_SECRETS_FILE) as f:
                _client_config_cache.update(json.load(f))
    return _client_config_cache


def _client_id():
    return _load_client_config()["web"]["client_id"]


def _client_secret():
    return _load_client_config()["web"]["client_secret"]


class GmailProvider(EmailProvider):
    provider_name = "gmail"

    def __init__(self, account_row, get_db):
        super().__init__(account_row, get_db)
        self._service = None
        self._quarantine_label_id = None

    def _credentials(self):
        return Credentials(
            token=self.account["access_token"],
            refresh_token=self.account["refresh_token"],
            token_uri="https://oauth2.googleapis.com/token",
            client_id=_client_id(),
            client_secret=_client_secret(),
            scopes=SCOPES,
        )

    def ensure_fresh_credentials(self):
        creds = self._credentials()
        if creds.expired and creds.refresh_token:
            creds.refresh(GoogleRequest())
            conn = self.get_db()
            conn.execute(
                "UPDATE gmail_accounts SET access_token=?, token_expiry=? WHERE id=?",
                (creds.token, creds.expiry.isoformat() if creds.expiry else None, self.account["id"]),
            )
            conn.commit()
            conn.close()
        self._service = build("gmail", "v1", credentials=creds)
        self._quarantine_label_id = self._ensure_quarantine_label()

    def _ensure_quarantine_label(self):
        labels = self._service.users().labels().list(userId="me").execute().get("labels", [])
        for l in labels:
            if l["name"] == QUARANTINE_LABEL_NAME:
                return l["id"]
        created = self._service.users().labels().create(
            userId="me",
            body={"name": QUARANTINE_LABEL_NAME, "labelListVisibility": "labelShow", "messageListVisibility": "show"},
        ).execute()
        return created["id"]

    def list_new_message_ids(self, folder, is_first_poll):
        cfg = _FOLDER_CONFIG[folder]
        query = f"{cfg['query']} newer_than:1d" if is_first_poll else cfg["query"]
        results = self._service.users().messages().list(
            userId="me", q=query, maxResults=cfg["max_results"]).execute()
        return [m["id"] for m in results.get("messages", [])]

    def fetch_normalized_message(self, msg_id):
        full = self._service.users().messages().get(userId="me", id=msg_id, format="full").execute()
        headers = full["payload"]["headers"]
        return {
            "sender": self._header(headers, "From"),
            "subject": self._header(headers, "Subject"),
            "body": self._decode_body(full["payload"]),
            "raw_headers": "\n".join(f"{h['name']}: {h['value']}" for h in headers),
        }

    def quarantine_message(self, msg_id, folder):
        remove_label = _FOLDER_CONFIG[folder]["remove_label"]
        self._service.users().messages().modify(
            userId="me", id=msg_id,
            body={"addLabelIds": [self._quarantine_label_id], "removeLabelIds": [remove_label]},
        ).execute()

    def delete_message(self, msg_id):
        # .trash() moves to Gmail's Trash (auto-purged after 30 days) —
        # covered by the gmail.modify scope already granted. Immediate,
        # unrecoverable deletion requires the much broader
        # https://mail.google.com/ scope, which isn't worth requesting
        # just for this — Trash achieves the same practical outcome
        # (the message leaves the Inbox and the Quarantine view).
        self._service.users().messages().trash(userId="me", id=msg_id).execute()

    @staticmethod
    def _header(headers, name):
        for h in headers:
            if h["name"].lower() == name.lower():
                return h["value"]
        return ""

    @staticmethod
    def _decode_body(payload):
        def walk(part):
            mime = part.get("mimeType", "")
            data = part.get("body", {}).get("data")
            if mime == "text/plain" and data:
                return base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
            for sub in part.get("parts", []) or []:
                r = walk(sub)
                if r:
                    return r
            if mime == "text/html" and data:
                html = base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
                return re.sub(r"<[^>]+>", " ", html)
            return None
        return walk(payload) or ""
