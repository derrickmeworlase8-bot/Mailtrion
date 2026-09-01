"""
Snarelytics — push-based detection for Gmail and Outlook (Approach B).

This is the OAuth-account half of the push/poll hybrid design: Gmail's
watch() + Cloud Pub/Sub, and Microsoft Graph's change notifications, both
let the provider notify Snarelytics the instant new mail arrives instead
of Snarelytics having to ask every 90 seconds. IMAP's equivalent lives in
idle_watcher.py — this module only covers the two OAuth providers.

IMPORTANT — this needs configuration only the deploying institution can
do, and is entirely optional:
  - Gmail push requires a Google Cloud Pub/Sub topic that grants Gmail's
    push service account permission to publish to it, pointed at this
    server's public /webhooks/gmail URL. Set GMAIL_PUBSUB_TOPIC to enable.
  - Outlook push requires the Graph app registration (already needed for
    OAuth login) plus a reachable HTTPS /webhooks/outlook URL — Graph
    validates that URL synchronously when a subscription is created, so
    this cannot be enabled against localhost. Set OUTLOOK_WEBHOOK_ENABLED=1
    plus PUBLIC_BASE_URL to enable.
  - Neither is required to run Snarelytics. Unset, both stay off and the
    90-second poller alone continues covering every Gmail/Outlook account,
    exactly as it did before this module existed. See SETUP_PUSH.md.
"""

import base64
import json
import logging
import os
from datetime import datetime, timedelta

from flask import request, jsonify

log = logging.getLogger(__name__)


# ─────────────────────────── Gmail (Pub/Sub) ────────────────────────────

def start_gmail_watch(account_row, get_db):
    """Registers (or renews) a Gmail watch() for one account. Gmail
    delivers a Pub/Sub message to the configured topic on every mailbox
    change; the topic's push subscription then calls our /webhooks/gmail
    endpoint. Watches expire after 7 days — this must be re-called before
    then, which renew_gmail_watches_job does daily."""
    from providers.gmail_provider import GmailProvider
    provider = GmailProvider(account_row, get_db)
    provider.ensure_fresh_credentials()

    topic = os.environ.get("GMAIL_PUBSUB_TOPIC")
    result = provider._service.users().watch(userId="me", body={
        "topicName": topic,
        "labelIds": ["INBOX", "SPAM"],
    }).execute()

    conn = get_db()
    conn.execute(
        "UPDATE gmail_accounts SET history_id=?, watch_expiration=? WHERE id=?",
        (result["historyId"],
         datetime.utcfromtimestamp(int(result["expiration"]) / 1000).isoformat(),
         account_row["id"])
    )
    conn.commit(); conn.close()
    log.info(f"[gmail-push] watch registered for account_id={account_row['id']}, "
             f"expires {result['expiration']}")


def renew_gmail_watches_job(get_db):
    """Scheduled daily. Gmail watches last 7 days — renewing every 24h
    keeps a wide safety margin rather than cutting it close."""
    conn = get_db()
    accounts = conn.execute("SELECT * FROM gmail_accounts WHERE is_active=1").fetchall()
    conn.close()
    for account_row in accounts:
        try:
            start_gmail_watch(dict(account_row), get_db)
        except Exception as e:
            log.warning(f"[gmail-push] watch renewal failed for account_id={account_row['id']} "
                        f"({e}) — 90s poller still covers this account meanwhile")


def register_push_routes(app, get_db, perform_scan, parse_auth_results, audit):
    @app.route("/webhooks/gmail", methods=["POST"])
    def gmail_webhook():
        # Pub/Sub push message envelope: {"message": {"data": "<base64 JSON>", ...}}
        envelope = request.get_json(silent=True) or {}
        message = envelope.get("message", {})
        data_b64 = message.get("data", "")
        if not data_b64:
            return "", 204

        try:
            payload = json.loads(base64.b64decode(data_b64).decode())
        except Exception as e:
            log.warning(f"[gmail-push] malformed webhook payload: {e}")
            return "", 204

        email_address = payload.get("emailAddress")
        if not email_address:
            return "", 204

        conn = get_db()
        account_row = conn.execute(
            "SELECT * FROM gmail_accounts WHERE gmail_address=? AND is_active=1",
            (email_address,)).fetchone()
        conn.close()
        if not account_row:
            return "", 204  # notification for an account we no longer have — ignore, not an error

        log.info(f"[gmail-push] change notified for {email_address} — scanning now")
        try:
            from poller import _poll_account
            from providers.gmail_provider import GmailProvider
            _poll_account(account_row, "gmail_accounts", GmailProvider, get_db, perform_scan, parse_auth_results)
        except Exception as e:
            # Never let a webhook failure surface as an error to Google — that
            # can cause Pub/Sub to back off retries. Log and move on; the 90s
            # poller will still pick this account up on its own next cycle.
            log.error(f"[gmail-push] scan-on-notify failed for {email_address}: {e}")

        return "", 204  # Pub/Sub push expects a fast 2xx with no meaningful body


# ────────────────────────── Outlook (Graph) ──────────────────────────────

def _outlook_headers(access_token):
    return {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}


def start_outlook_subscription(account_row, get_db):
    """Creates (or renews) a Microsoft Graph change-notification
    subscription for one account. Mail subscriptions max out at ~3 days —
    renew_outlook_subscriptions_job runs every 12h to stay well inside that."""
    import requests
    import secrets as secrets_mod
    from providers.outlook_provider import OutlookProvider

    provider = OutlookProvider(account_row, get_db)
    provider.ensure_fresh_credentials()
    access_token = provider._access_token

    base_url = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
    if not base_url:
        raise RuntimeError("PUBLIC_BASE_URL must be set to enable Outlook push notifications")

    client_state = secrets_mod.token_hex(16)
    expiration = (datetime.utcnow() + timedelta(hours=60)).isoformat() + "Z"

    body = {
        "changeType": "created",
        "notificationUrl": f"{base_url}/webhooks/outlook",
        "resource": "me/mailFolders('inbox')/messages",
        "expirationDateTime": expiration,
        "clientState": client_state,
    }
    resp = requests.post(f"https://graph.microsoft.com/v1.0/subscriptions",
                          headers=_outlook_headers(access_token), json=body, timeout=15)
    resp.raise_for_status()
    result = resp.json()

    conn = get_db()
    conn.execute(
        "UPDATE outlook_accounts SET subscription_id=?, subscription_expires=?, webhook_client_state=? WHERE id=?",
        (result["id"], result["expirationDateTime"], client_state, account_row["id"])
    )
    conn.commit(); conn.close()
    log.info(f"[outlook-push] subscription registered for account_id={account_row['id']}, "
             f"expires {result['expirationDateTime']}")


def renew_outlook_subscriptions_job(get_db):
    """Scheduled every 12h. Recreates the subscription outright rather than
    calling Graph's PATCH-to-renew endpoint — simpler, and self-healing if
    a subscription was ever deleted or expired outright."""
    conn = get_db()
    accounts = conn.execute("SELECT * FROM outlook_accounts WHERE is_active=1").fetchall()
    conn.close()
    for account_row in accounts:
        try:
            start_outlook_subscription(dict(account_row), get_db)
        except Exception as e:
            log.warning(f"[outlook-push] subscription renewal failed for account_id={account_row['id']} "
                        f"({e}) — 90s poller still covers this account meanwhile")


def register_outlook_push_routes(app, get_db, perform_scan, parse_auth_results, audit):
    @app.route("/webhooks/outlook", methods=["POST"])
    def outlook_webhook():
        # Graph's subscription-creation handshake: it POSTs a validationToken
        # as a query param and expects it echoed back as plain text within
        # 10 seconds, before it will actually create the subscription.
        validation_token = request.args.get("validationToken")
        if validation_token:
            return validation_token, 200, {"Content-Type": "text/plain"}

        envelope = request.get_json(silent=True) or {}
        for notif in envelope.get("value", []):
            client_state = notif.get("clientState")
            subscription_id = notif.get("subscriptionId")

            conn = get_db()
            account_row = conn.execute(
                "SELECT * FROM outlook_accounts WHERE subscription_id=? AND is_active=1",
                (subscription_id,)).fetchone()
            conn.close()
            if not account_row:
                continue

            # Reject anything whose clientState doesn't match what we set at
            # subscription time — this is what stops a forged POST to this
            # endpoint from triggering a scan cycle for an account it has no
            # business touching.
            if client_state != account_row["webhook_client_state"]:
                log.warning(f"[outlook-push] clientState mismatch for subscription_id={subscription_id} — ignoring")
                continue

            log.info(f"[outlook-push] change notified for account_id={account_row['id']} — scanning now")
            try:
                from poller import _poll_account
                from providers.outlook_provider import OutlookProvider
                _poll_account(account_row, "outlook_accounts", OutlookProvider, get_db, perform_scan, parse_auth_results)
            except Exception as e:
                log.error(f"[outlook-push] scan-on-notify failed for account_id={account_row['id']}: {e}")

        return "", 202
