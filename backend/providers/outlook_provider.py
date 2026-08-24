"""
PhishGuard AI — Outlook / Microsoft 365 provider

Implements EmailProvider against the Microsoft Graph API, using MSAL for
the OAuth token lifecycle. Written against the exact same interface as
GmailProvider — the poller (poller.py) doesn't know or care that this is
a different service.

Graph API notes for anyone maintaining this later:
  - "junkemail" is Outlook's well-known folder ID for Spam — Microsoft's
    name for it, not ours.
  - $select=internetMessageHeaders on a message returns the raw MIME
    headers (including Authentication-Results), which is what lets
    SPF/DKIM/DMARC parsing work identically to Gmail — Graph exposes
    this directly, no extra parsing needed to get there.
  - Quarantining is a real folder move (POST .../messages/{id}/move),
    not a label swap like Gmail — Outlook doesn't have Gmail-style labels.
"""

import os
import re
import json
import requests
import msal

from .base import EmailProvider
from paths import DEFAULT_OUTLOOK_SECRETS_FILE

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
SCOPES = ["Mail.ReadWrite", "User.Read"]  # offline_access is implicit for MSAL confidential clients
QUARANTINE_FOLDER_NAME = "PhishGuard Quarantine"

OUTLOOK_SECRETS_FILE = os.environ.get("OUTLOOK_SECRETS_FILE", DEFAULT_OUTLOOK_SECRETS_FILE)

# Maps PhishGuard's logical folder names to Outlook's well-known folder IDs.
_FOLDER_CONFIG = {
    "inbox": {"well_known": "inbox", "max_results": 25},
    "spam":  {"well_known": "junkemail", "max_results": 15},
}

_secrets_cache = {}


def _load_secrets():
    if not _secrets_cache:
        with open(OUTLOOK_SECRETS_FILE) as f:
            _secrets_cache.update(json.load(f))
    return _secrets_cache


def _client_id():
    return _load_secrets()["client_id"]


def _client_secret():
    return _load_secrets()["client_secret"]


def _tenant():
    # "common" allows both work/school AND personal Microsoft accounts
    # (outlook.com, hotmail.com, live.com) to sign in — the right default
    # for a tool meant to work with any Outlook-family address.
    return _load_secrets().get("tenant", "common")


def _authority():
    return f"https://login.microsoftonline.com/{_tenant()}"


def build_msal_app():
    return msal.ConfidentialClientApplication(
        _client_id(), authority=_authority(), client_credential=_client_secret()
    )


class OutlookProvider(EmailProvider):
    provider_name = "outlook"

    def __init__(self, account_row, get_db):
        super().__init__(account_row, get_db)
        self._access_token = None
        self._quarantine_folder_id = None

    def ensure_fresh_credentials(self):
        app_ = build_msal_app()
        result = app_.acquire_token_by_refresh_token(
            self.account["refresh_token"], scopes=SCOPES
        )
        if "access_token" not in result:
            raise RuntimeError(
                f"Outlook token refresh failed: {result.get('error_description', result)}"
            )
        self._access_token = result["access_token"]

        # MSAL issues a new refresh token on every refresh in most cases —
        # persist it, or the next poll cycle would fail with a stale one.
        new_refresh = result.get("refresh_token", self.account["refresh_token"])
        conn = self.get_db()
        conn.execute(
            "UPDATE outlook_accounts SET access_token=?, refresh_token=? WHERE id=?",
            (self._access_token, new_refresh, self.account["id"]),
        )
        conn.commit()
        conn.close()

        self._quarantine_folder_id = self._ensure_quarantine_folder()

    def _headers(self):
        return {"Authorization": f"Bearer {self._access_token}", "Content-Type": "application/json"}

    def _ensure_quarantine_folder(self):
        r = requests.get(f"{GRAPH_BASE}/me/mailFolders", headers=self._headers(),
                          params={"$filter": f"displayName eq '{QUARANTINE_FOLDER_NAME}'"})
        r.raise_for_status()
        existing = r.json().get("value", [])
        if existing:
            return existing[0]["id"]
        created = requests.post(f"{GRAPH_BASE}/me/mailFolders", headers=self._headers(),
                                 json={"displayName": QUARANTINE_FOLDER_NAME})
        created.raise_for_status()
        return created.json()["id"]

    def list_new_message_ids(self, folder, is_first_poll):
        cfg = _FOLDER_CONFIG[folder]
        params = {"$top": cfg["max_results"], "$select": "id", "$orderby": "receivedDateTime desc"}
        if is_first_poll:
            from datetime import datetime, timedelta, timezone
            since = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            params["$filter"] = f"receivedDateTime ge {since}"
        r = requests.get(f"{GRAPH_BASE}/me/mailFolders/{cfg['well_known']}/messages",
                          headers=self._headers(), params=params)
        r.raise_for_status()
        return [m["id"] for m in r.json().get("value", [])]

    def fetch_normalized_message(self, msg_id):
        r = requests.get(
            f"{GRAPH_BASE}/me/messages/{msg_id}",
            headers=self._headers(),
            params={"$select": "subject,from,body,internetMessageHeaders"},
        )
        r.raise_for_status()
        m = r.json()

        sender = ""
        if m.get("from") and m["from"].get("emailAddress"):
            sender = m["from"]["emailAddress"].get("address", "")

        body_field = m.get("body", {})
        body_content = body_field.get("content", "")
        if body_field.get("contentType", "").lower() == "html":
            body_content = re.sub(r"<[^>]+>", " ", body_content)

        raw_headers = "\n".join(
            f"{h['name']}: {h['value']}" for h in m.get("internetMessageHeaders", [])
        )

        return {
            "sender": sender,
            "subject": m.get("subject", ""),
            "body": body_content,
            "raw_headers": raw_headers,
        }

    def quarantine_message(self, msg_id, folder):
        r = requests.post(
            f"{GRAPH_BASE}/me/messages/{msg_id}/move",
            headers=self._headers(),
            json={"destinationId": self._quarantine_folder_id},
        )
        r.raise_for_status()

    def delete_message(self, msg_id):
        # A standard Graph DELETE on a message moves it to Deleted Items
        # rather than purging it instantly — same "soft delete" behavior
        # as Gmail's trash(), kept consistent across providers.
        r = requests.delete(f"{GRAPH_BASE}/me/messages/{msg_id}", headers=self._headers())
        r.raise_for_status()
