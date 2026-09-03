"""
Mailtrion — IMAP IDLE watcher (push-based detection for IMAP accounts).

This is "Approach B" from the design discussion: instead of only waking
up every 90 seconds to ask "anything new?", each active IMAP account gets
a persistent connection that the mail server itself notifies the instant
new mail arrives (the IMAP IDLE command, RFC 2177). Detection latency for
IMAP accounts then drops to seconds rather than being bounded by the poll
interval — while the existing 90-second poller in poller.py keeps running
unchanged as the reconciliation backstop for anything an IDLE connection
missed (e.g. because it silently dropped and hasn't reconnected yet).

Design notes:
  - One background thread per active IMAP account. At "hundreds to low
    thousands" of mailboxes this is a real resource cost worth watching —
    it's the honest tradeoff named in the original approach A vs B
    comparison (more moving parts, more connections to manage) in
    exchange for faster detection.
  - Python's imaplib has no built-in IDLE support, so this sends the IDLE
    command and reads the tagged/untagged responses directly.
  - On any error (network drop, provider closing the idle connection,
    which most providers do periodically) the thread reconnects with a
    backoff instead of dying — a dead watcher thread should never be a
    silent failure mode, since the 90s poller is the safety net but
    shouldn't be the ONLY thing running for accounts that were supposed
    to have push detection.
  - When new mail is signalled, it calls straight into the existing
    `_poll_account` logic from poller.py — the exact same idempotent
    scan path the 90s poller already uses — so there's only ever one
    place that actually fetches, scores, and quarantines a message.
"""

import imaplib
import logging
import socket
import threading
import time

from crypto_utils import decrypt_value

log = logging.getLogger(__name__)

IDLE_TIMEOUT_SECONDS = 25 * 60   # most providers cap IDLE at ~29 min; refresh before that
RECONNECT_BACKOFF_SECONDS = [5, 15, 30, 60, 120]  # capped exponential backoff

_watcher_threads = {}   # account_id -> Thread
_stop_flags = {}        # account_id -> threading.Event


def start_all_watchers(get_db, perform_scan, parse_auth_results):
    """Called once at startup (and can be re-called after new IMAP accounts
    connect) to spin up one IDLE watcher thread per active IMAP account
    that hasn't already got one running."""
    conn = get_db()
    accounts = conn.execute("SELECT * FROM imap_accounts WHERE is_active=1").fetchall()
    conn.close()

    for account_row in accounts:
        account_id = account_row["id"]
        if account_id in _watcher_threads and _watcher_threads[account_id].is_alive():
            continue
        stop_flag = threading.Event()
        _stop_flags[account_id] = stop_flag
        t = threading.Thread(
            target=_watch_account,
            args=(dict(account_row), get_db, perform_scan, parse_auth_results, stop_flag),
            daemon=True,
            name=f"imap-idle-{account_id}",
        )
        _watcher_threads[account_id] = t
        t.start()
        log.info(f"[imap-idle] started watcher for account_id={account_id}")


def stop_watcher(account_id):
    """Called when an IMAP account is disconnected — stops its thread
    rather than leaving it running against a dead/revoked credential."""
    if account_id in _stop_flags:
        _stop_flags[account_id].set()


def _watch_account(account, get_db, perform_scan, parse_auth_results, stop_flag):
    backoff_index = 0
    while not stop_flag.is_set():
        try:
            _idle_cycle(account, get_db, perform_scan, parse_auth_results, stop_flag)
            backoff_index = 0  # clean cycle completed — reset backoff
        except Exception as e:
            delay = RECONNECT_BACKOFF_SECONDS[min(backoff_index, len(RECONNECT_BACKOFF_SECONDS) - 1)]
            log.warning(f"[imap-idle] account_id={account['id']} dropped ({e}); "
                        f"reconnecting in {delay}s — 90s poller still covers this account meanwhile")
            backoff_index += 1
            stop_flag.wait(delay)


def _idle_cycle(account, get_db, perform_scan, parse_auth_results, stop_flag):
    conn = imaplib.IMAP4_SSL(account["imap_host"], account["imap_port"])
    conn.login(account["username"], decrypt_value(account["app_password"]))
    conn.select("INBOX")

    tag = conn._new_tag().decode()
    conn.send(f"{tag} IDLE\r\n".encode())
    initial = conn.readline()
    if b"+ idling" not in initial and b"+ ok" not in initial.lower():
        raise RuntimeError(f"Server refused IDLE: {initial!r}")

    conn.sock.settimeout(IDLE_TIMEOUT_SECONDS)
    new_mail_signalled = False
    start = time.time()

    try:
        while time.time() - start < IDLE_TIMEOUT_SECONDS and not stop_flag.is_set():
            try:
                line = conn.readline()
            except socket.timeout:
                break  # timed out waiting — refresh the IDLE below, this is normal
            if not line:
                break
            # Untagged EXISTS/RECENT responses are the server telling us
            # the mailbox changed — that's the actual "push" signal.
            if b"EXISTS" in line or b"RECENT" in line:
                new_mail_signalled = True
                break
    finally:
        try:
            conn.send(b"DONE\r\n")
            conn.readline()
        except Exception:
            pass
        try:
            conn.logout()
        except Exception:
            pass

    if new_mail_signalled:
        log.info(f"[imap-idle] new mail signalled for account_id={account['id']} — scanning now")
        from poller import _poll_account
        # Re-fetch the current row rather than reusing the possibly-stale
        # `account` dict this thread started with (e.g. last_polled_at).
        db_conn = get_db()
        fresh_row = db_conn.execute("SELECT * FROM imap_accounts WHERE id=?", (account["id"],)).fetchone()
        db_conn.close()
        if fresh_row and fresh_row["is_active"]:
            from providers.imap_provider import IMAPProvider
            _poll_account(fresh_row, "imap_accounts", IMAPProvider, get_db, perform_scan, parse_auth_results)
