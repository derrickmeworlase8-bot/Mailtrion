"""
Mailtrion — shared polling loop.

This is the one piece of code that actually walks "connected accounts,
check for new mail, scan it, quarantine if phishing" — written once
against the EmailProvider interface, so it works identically for Gmail,
and for Outlook/IMAP once those providers are added. Nothing here knows
anything provider-specific; all of that lives inside each provider class.
"""

import logging
from datetime import datetime

from providers import REGISTRY
from providers.base import POLLED_FOLDERS

log = logging.getLogger(__name__)


def poll_all_accounts(get_db, perform_scan, parse_auth_results):
    """Call once per scheduler tick. Polls every active account across every registered provider."""
    for provider_name, (table_name, provider_class) in REGISTRY.items():
        conn = get_db()
        accounts = conn.execute(f"SELECT * FROM {table_name} WHERE is_active=1").fetchall()
        conn.close()

        for account_row in accounts:
            try:
                _poll_account(account_row, table_name, provider_class, get_db, perform_scan, parse_auth_results)
            except Exception as e:
                # One broken account should never take down polling for
                # every other connected account, on this or any provider.
                keys = account_row.keys()
                identifier = (account_row["gmail_address"] if "gmail_address" in keys
                              else account_row["email_address"] if "email_address" in keys
                              else account_row["id"])
                log.error(f"[{provider_name}] poll failed for {identifier}: {e}")


def _poll_account(account_row, table_name, provider_class, get_db, perform_scan, parse_auth_results):
    provider = provider_class(account_row, get_db)
    provider.ensure_fresh_credentials()
    is_first_poll = not account_row["last_polled_at"]

    for folder in POLLED_FOLDERS:
        for msg_id in provider.list_new_message_ids(folder, is_first_poll):
            conn = get_db()
            already = conn.execute(
                "SELECT 1 FROM scans WHERE gmail_message_id=?", (msg_id,)).fetchone()
            conn.close()
            if already:
                continue

            msg = provider.fetch_normalized_message(msg_id)
            auth = parse_auth_results(msg["raw_headers"])

            result, _ = perform_scan(
                msg["body"], msg["sender"], msg["subject"], auth, account_row["user_id"],
                source=f"{provider.provider_name}-{folder}", gmail_message_id=msg_id,
                provider=provider.provider_name, account_id=account_row["id"],
            )

            if result.get("is_phishing"):
                provider.quarantine_message(msg_id, folder)

    conn = get_db()
    conn.execute(f"UPDATE {table_name} SET last_polled_at=? WHERE id=?",
                 (datetime.utcnow().isoformat(), account_row["id"]))
    conn.commit()
    conn.close()
