"""
Mailtrion — IMAP (Yahoo and other IMAP providers) routes

Unlike Gmail and Outlook, this isn't an OAuth redirect flow — most
consumer IMAP providers (Yahoo included) don't offer a practical OAuth
path for third-party apps. Instead, the user submits their email, an
app-specific password, and (usually pre-filled) IMAP connection details
directly to Mailtrion, which tests the login before saving anything.

Always registered — IMAP needs no server-side app registration or
credentials file the way Gmail/Outlook do, so there's no "not configured"
state for this one.
"""

import os
import imaplib
import logging
from datetime import datetime

from flask import request, jsonify

from providers.imap_provider import KNOWN_HOST_PRESETS
from crypto_utils import encrypt_value

log = logging.getLogger(__name__)


def register_imap_routes(app, get_token, get_db, audit, TOKENS, perform_scan):
    """Call this once from app.py after the Flask app is created."""

    @app.route("/auth/imap/presets", methods=["GET"])
    def imap_presets():
        # Lets the frontend pre-fill host/port/folder names when the user
        # picks "Yahoo" from a dropdown, without hardcoding that knowledge
        # into the frontend itself.
        return jsonify({"presets": KNOWN_HOST_PRESETS})

    @app.route("/auth/imap/connect", methods=["POST"])
    def imap_connect():
        token = get_token()
        if not token or token not in TOKENS:
            return jsonify({"error": "Authentication required"}), 401
        user = TOKENS[token]

        data = request.get_json() or {}
        provider_label = data.get("provider_label", "imap").strip()
        username = data.get("username", "").strip()
        app_password = data.get("app_password", "")
        imap_host = data.get("imap_host", "").strip()
        imap_port = int(data.get("imap_port", 993))
        spam_folder = data.get("spam_folder", "Spam").strip()
        trash_folder = data.get("trash_folder", "Trash").strip()

        if not username or not app_password or not imap_host:
            return jsonify({"error": "Email, app password, and IMAP host are all required"}), 400

        # Test the login BEFORE saving anything — a wrong password or host
        # should never end up silently sitting in the accounts table.
        try:
            test_conn = imaplib.IMAP4_SSL(imap_host, imap_port)
            test_conn.login(username, app_password)
            test_conn.logout()
        except Exception as e:
            return jsonify({"error": f"Could not connect: {e}. Check the email, app password, "
                                      f"host, and port, then try again."}), 400

        conn = get_db()
        conn.execute("""INSERT INTO imap_accounts
            (user_id, provider_label, username, app_password, imap_host, imap_port,
             spam_folder, trash_folder, connected_at, is_active)
            VALUES (?,?,?,?,?,?,?,?,?,1)
            ON CONFLICT(username) DO UPDATE SET
                app_password=excluded.app_password,
                imap_host=excluded.imap_host,
                imap_port=excluded.imap_port,
                spam_folder=excluded.spam_folder,
                trash_folder=excluded.trash_folder,
                is_active=1""",
            (user["id"], provider_label, username, encrypt_value(app_password), imap_host, imap_port,
             spam_folder, trash_folder, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()

        audit(user["id"], user["username"], "IMAP_CONNECTED", f"imap={username} ({provider_label})")

        # Start this account's IDLE watcher immediately rather than waiting
        # for the next app restart — start_all_watchers() is a no-op for
        # any account that already has a live thread, so this is safe to
        # call repeatedly.
        if os.environ.get("IMAP_IDLE_ENABLED", "1") == "1":
            try:
                import idle_watcher
                from app import parse_auth_results
                idle_watcher.start_all_watchers(get_db, perform_scan, parse_auth_results)
            except Exception as e:
                log.warning(f"[imap-idle] could not start watcher for {username} immediately "
                            f"({e}) — will pick it up on next app restart; 90s polling covers it meanwhile")

        return jsonify({"message": f"{username} connected successfully"})

    @app.route("/auth/imap/status", methods=["GET"])
    def imap_status():
        token = get_token()
        if not token or token not in TOKENS:
            return jsonify({"error": "Authentication required"}), 401
        user = TOKENS[token]

        conn = get_db()
        rows = conn.execute("""SELECT id, provider_label, username, imap_host, connected_at,
            last_polled_at, is_active FROM imap_accounts WHERE user_id=?""", (user["id"],)).fetchall()
        conn.close()
        # Deliberately excludes app_password from the response — never
        # send stored credentials back to the client, even to the account
        # owner's own logged-in session.
        return jsonify({"accounts": [dict(r) for r in rows]})

    @app.route("/auth/imap/disconnect/<int:account_id>", methods=["DELETE"])
    def imap_disconnect(account_id):
        token = get_token()
        if not token or token not in TOKENS:
            return jsonify({"error": "Authentication required"}), 401
        user = TOKENS[token]

        conn = get_db()
        conn.execute("UPDATE imap_accounts SET is_active=0 WHERE id=? AND user_id=?",
                     (account_id, user["id"]))
        cleared = conn.execute(
            "DELETE FROM scans WHERE provider='imap' AND account_id=? AND is_quarantined=1",
            (account_id,)).rowcount
        conn.commit()
        conn.close()
        audit(user["id"], user["username"], "IMAP_DISCONNECTED",
              f"account_id={account_id} cleared_quarantine_items={cleared}")

        # Stop this account's IDLE watcher thread rather than leaving it
        # running against a credential that's about to be inert.
        try:
            import idle_watcher
            idle_watcher.stop_watcher(account_id)
        except Exception:
            pass

        return jsonify({"message": "Account disconnected", "cleared_quarantine_items": cleared})
