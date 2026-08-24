# Snarelytics — Gmail Integration Setup

This adds automated ingestion: Snarelytics polls a connected Gmail inbox,
scans new mail through the existing detection pipeline, and moves anything
flagged "Phishing" into a `Snarelytics/Quarantine` Gmail label automatically.
No copy-paste required.

## 1. Google Cloud Console setup

1. Go to https://console.cloud.google.com/ and create a new project (or use an existing one).
2. **Enable the Gmail API**: APIs & Services → Library → search "Gmail API" → Enable.
3. **Configure the OAuth consent screen**: APIs & Services → OAuth consent screen.
   - User type: External (unless you have a Google Workspace org)
   - Add your own Gmail address as a **test user** (required while the app is unpublished —
     unpublished apps only work for accounts you explicitly add here)
   - Scopes: you don't need to add scopes here manually; they're requested in code
4. **Create credentials**: APIs & Services → Credentials → Create Credentials → OAuth client ID
   - Application type: **Web application**
   - Authorized redirect URIs: add `http://localhost:5000/auth/gmail/callback`
   - Click Create, then **Download JSON**
5. Rename the downloaded file to `client_secret.json` and place it in the same
   directory as `app.py`.

## 2. Install dependencies

```bash
pip install -r requirements.txt
```

## 3. Run Snarelytics as usual

```bash
python app.py
```

You should see in the logs: `Gmail integration enabled (polling every 90s)`.
If `client_secret.json` is missing, Snarelytics still runs fine — it just logs
a warning and skips the Gmail routes, so this won't break your existing setup.

## 4. Connect a Gmail account

1. Log in to Snarelytics normally (`/auth/login`) and grab your bearer token.
2. Visit in a browser: `http://localhost:5000/auth/gmail/connect?token=YOUR_TOKEN`
3. Complete the Google consent screen (you'll see a warning that the app is
   "unverified" — this is expected for a project not submitted for Google's
   verification review; click Advanced → Go to Snarelytics to proceed).
4. On success you'll see a JSON confirmation with your connected Gmail address.

From this point, Snarelytics polls that inbox every 90 seconds (configurable
via the `GMAIL_POLL_INTERVAL` env var) and scans new mail automatically.

## 5. Check connection status / disconnect

- `GET /auth/gmail/status` — list connected accounts for the logged-in user
- `DELETE /auth/gmail/disconnect/<account_id>` — revoke a connection

## 6. Where scans show up

Gmail-sourced scans land in the same `scans` table and the same `/quarantine`,
`/stats`, `/report/pdf`, `/report/excel` endpoints as manual scans — they're
tagged with `source = "gmail"` and `gmail_message_id` so you can filter or
report on them separately if you want (e.g. "automated vs. manually
submitted" in your dissertation write-up).

## Notes on the architecture decision

Polling (not Gmail push/Pub-Sub) was chosen for Phase 1 because push requires
a public HTTPS endpoint, a GCP Pub/Sub topic, and renewing the mailbox `watch()`
subscription every 7 days — real infrastructure that adds risk of silent
failure for a project at this stage. Polling every 60–120s is functionally
indistinguishable from push for demo purposes and is far easier to build,
run locally, and debug. This is worth stating explicitly if you present this
as "v1 architecture, with event-driven push as a documented v2 upgrade" —
it shows you evaluated the tradeoff deliberately rather than not knowing push existed.

## Known limitations to disclose (be upfront about these in write-ups/demos)

- Tokens are stored in the local SQLite DB unencrypted — fine for a personal
  project/demo, **not** production-ready. Flag this as a known limitation or
  add field-level encryption (e.g. `cryptography.fernet`) before deploying
  beyond your own test account.
- The `TOKENS` dict (Snarelytics's own session store) is in-memory and clears
  on restart — same limitation the original app already had, unrelated to Gmail.
- Because the app is an "unverified" Google OAuth app, only Google accounts
  you've added as test users can connect. Submitting for verification is a
  separate process (and unnecessary for a portfolio project).
