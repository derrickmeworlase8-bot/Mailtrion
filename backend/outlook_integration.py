"""
Snarelytics — Outlook OAuth routes

Same structure as gmail_integration.py: handles the Outlook-specific
OAuth connect/callback/status/disconnect web routes only. The actual
"check for new mail, scan it, quarantine if phishing" logic lives in
poller.py (shared) and providers/outlook_provider.py (Outlook-specific).

Setup required (see SETUP_OUTLOOK.md):
  1. Register an app in the Azure Portal (Microsoft Entra ID > App registrations)
  2. Add http://localhost:5000/auth/outlook/callback as a Web redirect URI
  3. Grant delegated Microsoft Graph permissions: Mail.ReadWrite, User.Read
  4. Create a client secret
  5. Save client_id, client_secret, and tenant into outlook_secret.json
"""

import os
import requests
import logging
from datetime import datetime

from flask import request, jsonify, redirect

from providers.outlook_provider import build_msal_app, SCOPES, GRAPH_BASE
from crypto_utils import encrypt_value

log = logging.getLogger(__name__)

REDIRECT_URI = os.environ.get("OUTLOOK_REDIRECT_URI", "http://localhost:5000/auth/outlook/callback")

# state -> Snarelytics bearer token, same pattern as the Gmail flow.
_STATE_TO_PG_TOKEN = {}


def register_outlook_routes(app, get_token, get_db, audit, TOKENS, perform_scan):
    """Call this once from app.py after the Flask app is created."""

    @app.route("/auth/outlook/connect", methods=["GET"])
    def outlook_connect():
        token = request.args.get("token") or get_token()
        if not token or token not in TOKENS:
            return jsonify({"error": "Authentication required. Pass your Snarelytics token as ?token="}), 401

        msal_app = build_msal_app()
        # Mint our own state token to correlate the callback with the
        # Snarelytics user who initiated this — same pattern as the Gmail flow.
        state = os.urandom(16).hex()
        auth_url = msal_app.get_authorization_request_url(
            scopes=SCOPES, redirect_uri=REDIRECT_URI, prompt="select_account", state=state
        )
        _STATE_TO_PG_TOKEN[state] = token
        return redirect(auth_url)

    @app.route("/auth/outlook/callback", methods=["GET"])
    def outlook_callback():
        state = request.args.get("state")
        code = request.args.get("code")
        pg_token = _STATE_TO_PG_TOKEN.pop(state, None)
        if not pg_token or pg_token not in TOKENS:
            return jsonify({"error": "Session expired, please reconnect from Snarelytics"}), 400
        user = TOKENS[pg_token]

        if not code:
            return jsonify({"error": f"Microsoft sign-in failed: {request.args.get('error_description', 'no code returned')}"}), 400

        msal_app = build_msal_app()
        result = msal_app.acquire_token_by_authorization_code(
            code, scopes=SCOPES, redirect_uri=REDIRECT_URI
        )
        if "access_token" not in result:
            return jsonify({"error": f"Token exchange failed: {result.get('error_description', result)}"}), 400

        access_token = result["access_token"]
        refresh_token = result.get("refresh_token", "")

        # Get the connected account's own address — prefer Graph's /me
        # (most reliable for both work/school and personal accounts) over
        # trusting the ID token claims alone.
        me = requests.get(f"{GRAPH_BASE}/me", headers={"Authorization": f"Bearer {access_token}"})
        me.raise_for_status()
        me_json = me.json()
        email_address = me_json.get("mail") or me_json.get("userPrincipalName")
        if not email_address:
            return jsonify({"error": "Could not determine the connected account's email address"}), 400

        conn = get_db()
        conn.execute("""INSERT INTO outlook_accounts
            (user_id, email_address, access_token, refresh_token, connected_at, is_active)
            VALUES (?,?,?,?,?,1)
            ON CONFLICT(email_address) DO UPDATE SET
                access_token=excluded.access_token,
                refresh_token=excluded.refresh_token,
                is_active=1""",
            (user["id"], email_address, encrypt_value(access_token), encrypt_value(refresh_token),
             datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()

        audit(user["id"], user["username"], "OUTLOOK_CONNECTED", f"outlook={email_address}")

        if os.environ.get("OUTLOOK_WEBHOOK_ENABLED") == "1":
            try:
                from push_notifications import start_outlook_subscription
                conn2 = get_db()
                account_row = conn2.execute(
                    "SELECT * FROM outlook_accounts WHERE email_address=?", (email_address,)).fetchone()
                conn2.close()
                start_outlook_subscription(dict(account_row), get_db)
            except Exception as e:
                log.warning(f"[outlook-push] initial subscription failed for {email_address} "
                            f"({e}) — 90s polling still covers this account")

        return redirect("/?outlook_connected=" + email_address)

    @app.route("/auth/outlook/status", methods=["GET"])
    def outlook_status():
        token = get_token()
        if not token or token not in TOKENS:
            return jsonify({"error": "Authentication required"}), 401
        user = TOKENS[token]

        conn = get_db()
        rows = conn.execute("""SELECT id, email_address, connected_at, last_polled_at, is_active
            FROM outlook_accounts WHERE user_id=?""", (user["id"],)).fetchall()
        conn.close()
        return jsonify({"accounts": [dict(r) for r in rows]})

    @app.route("/auth/outlook/disconnect/<int:account_id>", methods=["DELETE"])
    def outlook_disconnect(account_id):
        token = get_token()
        if not token or token not in TOKENS:
            return jsonify({"error": "Authentication required"}), 401
        user = TOKENS[token]

        conn = get_db()
        conn.execute("UPDATE outlook_accounts SET is_active=0 WHERE id=? AND user_id=?",
                     (account_id, user["id"]))
        cleared = conn.execute(
            "DELETE FROM scans WHERE provider='outlook' AND account_id=? AND is_quarantined=1",
            (account_id,)).rowcount
        conn.commit()
        conn.close()
        audit(user["id"], user["username"], "OUTLOOK_DISCONNECTED",
              f"account_id={account_id} cleared_quarantine_items={cleared}")
        return jsonify({"message": "Outlook account disconnected", "cleared_quarantine_items": cleared})
