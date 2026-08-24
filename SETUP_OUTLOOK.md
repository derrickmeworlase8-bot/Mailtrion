# Snarelytics — Outlook / Microsoft 365 Integration Setup

This adds automated ingestion for Outlook, Microsoft 365, and personal
Microsoft accounts (outlook.com, hotmail.com, live.com) — the same kind of
automated polling + quarantine Snarelytics already does for Gmail, just
talking to Microsoft's Graph API instead.

## 1. Azure Portal setup

1. Go to https://portal.azure.com/ and sign in (a free Microsoft account works).
2. Search for **"App registrations"** in the top search bar, and open it.
3. Click **New registration**.
   - Name: `Snarelytics` (or anything — only used for your own reference)
   - Supported account types: **"Accounts in any organizational directory
     and personal Microsoft accounts"** — this is the option that allows
     both work/school *and* personal Outlook/Hotmail addresses to connect.
     If you only ever need work/school accounts, a narrower option is fine,
     but the broad option is the safest default.
   - Redirect URI: platform **Web**, value
     `http://localhost:5000/auth/outlook/callback`
   - Click **Register**.
4. On the app's **Overview** page, copy the **Application (client) ID** —
   you'll need this in step 3 below.
5. Go to **Certificates & secrets** (left sidebar) → **New client secret**.
   - Add a description, choose an expiry (24 months is fine for a project)
   - Click **Add**, then **immediately copy the "Value" column** — Azure
     only shows this once; if you navigate away before copying it, you'll
     have to create a new secret.
6. Go to **API permissions** (left sidebar) → **Add a permission** →
   **Microsoft Graph** → **Delegated permissions**. Add:
   - `Mail.ReadWrite`
   - `User.Read`
   Click **Add permissions**. (You do **not** need admin consent for these
   — they're standard delegated permissions any signed-in user can grant
   to themselves.)

## 2. Install dependencies

```bash
pip install -r requirements.txt
```

(This adds `msal` and `requests` if they aren't already installed.)

## 3. Create `outlook_secret.json`

In the same folder as `app.py` (`backend/`), create a file named exactly
`outlook_secret.json`:

```json
{
  "client_id": "PASTE_YOUR_APPLICATION_CLIENT_ID_HERE",
  "client_secret": "PASTE_YOUR_CLIENT_SECRET_VALUE_HERE",
  "tenant": "common"
}
```

Leave `"tenant": "common"` as-is unless you specifically want to restrict
this to a single organization's accounts only.

## 4. Run Snarelytics as usual

```bash
python app.py
```

You should see in the logs: `Outlook integration enabled`. If
`outlook_secret.json` is missing or malformed, Snarelytics still runs fine
— it just logs a warning and skips the Outlook routes, exactly like the
Gmail integration does when unconfigured.

## 5. Connect an Outlook account

1. Log in to Snarelytics, go to **Email integrations** in the sidebar.
2. Click **+ Connect Outlook account** under the Outlook panel.
3. Sign in with the Microsoft account you want to connect, and approve
   the requested permissions.
4. You'll be redirected back into Snarelytics with a confirmation.

From this point, Snarelytics polls that account's Inbox and Junk Email
folders every ~90 seconds (same interval as Gmail, shared setting —
`MAIL_POLL_INTERVAL` env var) and quarantines anything scored phishing
into a folder named **"Snarelytics Quarantine"**.

## Notes on how this differs from Gmail

- **Quarantine mechanism**: Gmail uses labels; Outlook doesn't have an
  equivalent, so quarantining here is a real folder *move* instead —
  functionally the same end result (the message leaves the Inbox/Junk
  view and lands somewhere reviewable), just a different underlying
  mechanism specific to how Outlook organizes mail.
- **Personal vs. work accounts**: Microsoft's identity platform treats
  personal Microsoft accounts and Azure AD (work/school) accounts
  somewhat differently under the hood — `"tenant": "common"` is what
  allows both to work through the same app registration without you
  needing to build two separate integrations.
- **SPF/DKIM/DMARC**: no code differences from Gmail — Microsoft Graph
  exposes the raw `Authentication-Results` header the same way Gmail
  does, so the exact same parsing logic in `app.py` works unmodified
  across both providers.
