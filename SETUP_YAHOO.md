# Snarelytics — Yahoo / Other IMAP Account Setup

Yahoo (and most other consumer IMAP providers) don't offer a practical
OAuth sign-in flow for independent third-party apps the way Gmail and
Outlook do. The standard, well-supported alternative is an **app
password** — a second, separate password generated specifically for
apps like this one, instead of using your real account password.

No developer account, no cloud console, no app registration — this is
the simplest of the three integrations to set up.

## 1. Generate a Yahoo app password

1. Go to https://login.yahoo.com/account/security and sign in.
2. Make sure **2-step verification** is turned on — Yahoo requires this
   before it will let you generate app passwords. If it's off, turn it
   on first (you'll need a phone number or authenticator app).
3. Find **"Generate app password"** (sometimes listed as **"Manage app
   passwords"**) on the same Account Security page.
4. Give it a name (e.g. "Snarelytics") and generate it.
5. **Copy the generated password immediately** — Yahoo shows it once.
   It'll look like a random string of characters, not your normal
   password.

## 2. Connect it in Snarelytics

1. Log in to Snarelytics, go to **Email integrations** in the sidebar.
2. Under **Yahoo / Other (IMAP)**, click **+ Connect Yahoo / IMAP account**.
3. Provider dropdown: select **Yahoo** — this pre-fills the correct
   server settings (`imap.mail.yahoo.com`, port `993`, spam folder
   `Bulk Mail`, trash folder `Trash`) automatically.
4. Enter your Yahoo email address.
5. Paste the **app password** you generated in step 1 — not your normal
   Yahoo password.
6. Click **Test & Connect**. Snarelytics tries logging in immediately
   before saving anything — if something's wrong (wrong password, 2FA
   not enabled, etc.), you'll see the actual error right away rather
   than a silent failure later.

Once connected, polling works exactly the same as Gmail and Outlook —
Inbox and Spam ("Bulk Mail") checked every ~90 seconds, phishing moved
to a "Snarelytics Quarantine" folder automatically.

## Connecting other IMAP providers (iCloud, Zoho, AOL, or any other)

The same form works for any IMAP-accessible mailbox:

- Pick a preset from the dropdown if your provider is listed (iCloud,
  Zoho, AOL), or select **Other** to enter server details manually.
- You'll generally still need an app-specific password, not your normal
  account password — this is standard practice across most providers
  once they support two-factor authentication (iCloud calls it an
  "app-specific password" in the same place as Apple ID security
  settings; Zoho and AOL have their own equivalents in account security
  settings).
- If your provider isn't listed and you're not sure of the IMAP host,
  a quick web search for "**[provider name] IMAP settings**" will have it
  — it's standard, publicly documented information for every provider.

## Security note (read this before connecting)

Unlike Gmail/Outlook's OAuth tokens — which are scoped, revocable, and
never include your actual password — an IMAP app password is stored
directly in Snarelytics's local database so it can reconnect on every
polling cycle. This is:

- **Safer than your real password** — if it's ever compromised, you can
  revoke just that one app password from your account's security
  settings without changing your main login.
- **Still a real credential**, so treat the local database file
  (`phishguard.db`) with the same care you would any file containing
  passwords — this is the same disclosed limitation noted for OAuth
  tokens in `SETUP_GMAIL.md`, arguably more important here since this
  is a literal password rather than a scoped token.
