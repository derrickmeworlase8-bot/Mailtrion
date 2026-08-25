"""
Snarelytics — Gmail OAuth routes

Same structure applies to every provider: handles the Gmail-specific
OAuth connect/callback/status/disconnect web routes only. The actual
"check for new mail, scan it, quarantine if phishing" logic lives in
poller.py (provider-agnostic) and providers/gmail_provider.py (the Gmail-
specific implementation of that logic). The background scheduler that
drives polling is started once, centrally, in app.py — not here — since
multiple providers share one poll cycle rather than each running its own.

Design choice: polling (not Pub/Sub push) for Phase 1. Push requires a
public HTTPS endpoint, a GCP Pub/Sub topic, and a watch() renewal every
7 days — real infra overhead for a project at this stage. Polling every
60-120s is functionally equivalent for a demo and far easier to run and
debug locally. Swap in push later as a documented "v2" upgrade.

Setup required (see SETUP_GMAIL.md):
  1. Create a Google Cloud project, enable the Gmail API
  2. Create an OAuth 2.0 Client ID (type: Web application)
  3. Download the client secret JSON, save as client_secret.json
  4. Add http://localhost:5000/auth/gmail/callback as an authorized redirect URI
  5. pip install -r requirements.txt (adds google-auth-oauthlib, google-api-python-client, apscheduler)
"""

import os
from datetime import datetime

# Google's OAuth libraries refuse to complete a token exchange over plain
# HTTP by default (they enforce HTTPS). This setup deliberately uses
# http://localhost for local development — setting up real TLS certs for a
# local dev server isn't worth it here. This env var is the standard,
# documented way to allow that for local/dev use.
# IMPORTANT: never set this in a real production deployment reachable over
# the network — only safe because this only ever talks to localhost.
os.environ.setdefault("OAUTHLIB_INSECURE_TRANSPORT", "1")

# Google occasionally returns a slightly different (usually reduced) scope
# than what was requested — e.g. if the returned scope order differs, or a
# permission was partially granted. By default oauthlib treats any mismatch
# as a fatal error and aborts the whole token exchange. This tells it to
# accept whatever scope was actually granted instead of failing outright.
os.environ.setdefault("OAUTHLIB_RELAX_TOKEN_SCOPE", "1")

from flask import request, jsonify, redirect
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

from providers.gmail_provider import SCOPES, CLIENT_SECRETS_FILE

REDIRECT_URI = os.environ.get("GOOGLE_REDIRECT_URI", "http://localhost:5000/auth/gmail/callback")

# state -> Snarelytics bearer token, so the callback knows which logged-in
# user initiated the OAuth flow. In-memory, matching the existing TOKENS
# pattern in app.py (fine for a single-instance dev/demo deployment).
_STATE_TO_PG_TOKEN = {}


def _get_flow(state=None):
    return Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES,
        redirect_uri=REDIRECT_URI, state=state
    )


def register_gmail_routes(app, get_token, get_db, audit, TOKENS, perform_scan):
    """Call this once from app.py after the Flask app is created."""

    @app.route("/auth/gmail/connect", methods=["GET"])
    def gmail_connect():
        token = request.args.get("token") or get_token()
        if not token or token not in TOKENS:
            return jsonify({"error": "Authentication required. Pass your Snarelytics token as ?token="}), 401
        if TOKENS[token].get("role") not in ("admin", "user"):
            return jsonify({"error": "You don't have permission to connect a mailbox."}), 403

        flow = _get_flow()
        auth_url, state = flow.authorization_url(
            access_type="offline", include_granted_scopes="true", prompt="consent"
        )
        _STATE_TO_PG_TOKEN[state] = token
        return redirect(auth_url)

    @app.route("/auth/gmail/callback", methods=["GET"])
    def gmail_callback():
        state = request.args.get("state")
        pg_token = _STATE_TO_PG_TOKEN.pop(state, None)
        if not pg_token or pg_token not in TOKENS:
            return jsonify({"error": "Session expired, please reconnect from Snarelytics"}), 400
        user = TOKENS[pg_token]

        flow = _get_flow(state=state)
        flow.fetch_token(authorization_response=request.url)
        creds = flow.credentials

        service = build("gmail", "v1", credentials=creds)
        profile = service.users().getProfile(userId="me").execute()
        gmail_address = profile["emailAddress"]

        conn = get_db()
        conn.execute("""INSERT INTO gmail_accounts
            (user_id, gmail_address, access_token, refresh_token, token_expiry, connected_at, is_active)
            VALUES (?,?,?,?,?,?,1)
            ON CONFLICT(gmail_address) DO UPDATE SET
                access_token=excluded.access_token,
                refresh_token=excluded.refresh_token,
                token_expiry=excluded.token_expiry,
                is_active=1""",
            (user["id"], gmail_address, creds.token, creds.refresh_token,
             creds.expiry.isoformat() if creds.expiry else None,
             datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()

        audit(user["id"], user["username"], "GMAIL_CONNECTED", f"gmail={gmail_address}")
        # Send the user back into the app UI instead of leaving them on a bare JSON page
        return redirect("/?gmail_connected=" + gmail_address)

    @app.route("/auth/gmail/status", methods=["GET"])
    def gmail_status():
        token = get_token()
        if not token or token not in TOKENS:
            return jsonify({"error": "Authentication required"}), 401
        user = TOKENS[token]

        conn = get_db()
        rows = conn.execute("""SELECT id, gmail_address, connected_at, last_polled_at, is_active
            FROM gmail_accounts WHERE user_id=?""", (user["id"],)).fetchall()
        conn.close()
        return jsonify({"accounts": [dict(r) for r in rows]})

    @app.route("/auth/gmail/disconnect/<int:account_id>", methods=["DELETE"])
    def gmail_disconnect(account_id):
        token = get_token()
        if not token or token not in TOKENS:
            return jsonify({"error": "Authentication required"}), 401
        if TOKENS[token].get("role") not in ("admin", "user"):
            return jsonify({"error": "You don't have permission to disconnect a mailbox."}), 403
        user = TOKENS[token]

        conn = get_db()
        conn.execute("UPDATE gmail_accounts SET is_active=0 WHERE id=? AND user_id=?",
                     (account_id, user["id"]))
        # Also clear anything currently quarantined from this account — once
        # disconnected, Snarelytics no longer has credentials to manage those
        # messages in the real mailbox anyway, so leaving them listed here
        # would be misleading. Scan history that was already released/not
        # quarantined is left alone, only the active quarantine queue clears.
        cleared = conn.execute(
            "DELETE FROM scans WHERE provider='gmail' AND account_id=? AND is_quarantined=1",
            (account_id,)).rowcount
        conn.commit()
        conn.close()
        audit(user["id"], user["username"], "GMAIL_DISCONNECTED",
              f"account_id={account_id} cleared_quarantine_items={cleared}")
        return jsonify({"message": "Gmail account disconnected", "cleared_quarantine_items": cleared})
