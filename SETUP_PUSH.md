# Setup: Push-Based Scanning (Tier 3 / "Approach B")

By default, Snarelytics scans every connected mailbox on a 90-second
poll (`MAIL_POLL_INTERVAL`, `backend/poller.py`). This is always on and
needs zero configuration — it's the safety net every account has,
regardless of anything below.

This document covers the **optional, additive** layer on top of that:
push-based detection, so new mail can be scanned within seconds instead
of waiting for the next poll tick. Nothing here is required to run
Snarelytics — skip this entirely and the 90s poller alone still covers
every account correctly.

---

## IMAP accounts — already on, nothing to configure

IMAP push (via the IMAP IDLE command) is **on by default** the moment an
IMAP account connects — no external setup needed, since it just uses the
same IMAP credentials already stored for that account.

To turn it off (e.g. very constrained free-tier RAM, where one extra
persistent connection per mailbox matters):

```
IMAP_IDLE_ENABLED=0
```

## Gmail accounts — requires a Google Cloud Pub/Sub topic

Gmail push notifications work through Google Cloud Pub/Sub, not a direct
webhook. Setup:

1. In Google Cloud Console (the same project as your existing Gmail
   OAuth client), enable the **Cloud Pub/Sub API**.
2. Create a Pub/Sub **topic**, e.g. `snarelytics-gmail-push`.
3. Grant publish rights on that topic to Gmail's push service account:
   `gmail-api-push@system.gserviceaccount.com` (role: **Pub/Sub Publisher**).
4. Create a **push subscription** on that topic, with the endpoint URL
   set to `https://<your-deployed-domain>/webhooks/gmail`.
5. Set the environment variable:
   ```
   GMAIL_PUBSUB_TOPIC=projects/<your-project-id>/topics/snarelytics-gmail-push
   ```
6. Restart the app. New Gmail connections register a watch immediately;
   existing connected accounts pick it up on the next daily renewal job,
   or restart the app to register them right away.

**Free tier note:** Pub/Sub's free tier (10GB/month) comfortably covers
"hundreds to low thousands" of mailboxes at normal mail volume — see the
cost breakdown discussed earlier in the project's design conversation.

**If this isn't configured:** `GMAIL_PUBSUB_TOPIC` stays unset, the
`/webhooks/gmail` route is never registered, and Gmail accounts are
covered by 90s polling only — exactly as before this feature existed.

## Outlook accounts — requires a public HTTPS URL

Microsoft Graph validates your webhook URL synchronously when a
subscription is created, so **this cannot be enabled against
`localhost`** — it needs your actual deployed domain.

1. Set:
   ```
   OUTLOOK_WEBHOOK_ENABLED=1
   PUBLIC_BASE_URL=https://<your-deployed-domain>
   ```
2. Restart the app. New Outlook connections register a subscription
   immediately; existing accounts pick it up on the next 12-hourly
   renewal job, or restart the app to register them right away.

Graph mail subscriptions expire after ~3 days maximum — the renewal job
recreates them every 12 hours, well inside that window.

**If this isn't configured:** Outlook accounts are covered by 90s
polling only, exactly as before this feature existed.

---

## What happens if a push mechanism fails

Every push path here is wrapped so a failure only ever logs a warning
and falls back to polling — it never crashes the app or silently stops
scanning an account:

- IMAP IDLE connection drops → reconnects with backoff; 90s poller
  covers the account in the meantime.
- Gmail watch expires or fails to renew → logged; 90s poller is
  unaffected and keeps running regardless.
- Outlook subscription expires or fails to renew → same.

This is deliberate: push is a latency improvement layered on top of a
correctness guarantee (the poller), not a replacement for it.
