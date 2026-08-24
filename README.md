# PhishGuard AI

AI-based phishing email detection and risk assessment system, with automated
Gmail ingestion (Phase 1).

## Quick start (Windows)

Double-click **`start.bat`**. It will:
1. Create a Python virtual environment in `backend\venv` (first run only)
2. Install all dependencies
3. Start the server at http://localhost:5000

First run will take a few minutes (installing scikit-learn, etc.). After
that, `start.bat` starts up in seconds.

**Requires Python 3.10+** installed and on PATH — get it from
https://www.python.org/downloads/ (check "Add python.exe to PATH" during install).

## Project structure

```
phishguard-ai/
├── start.bat              ← double-click this to run everything
├── SETUP_GMAIL.md         ← Google Cloud setup for automated Gmail scanning
├── phishguard.db          ← SQLite database (users, scans, audit log)
├── data/
│   └── training_data.txt  ← phishing/legit labeled training samples
├── models/
│   ├── model.pkl           ← pretrained GradientBoostingClassifier
│   └── vec.pkl              ← pretrained TF-IDF vectorizer
├── uploads/                ← .eml file uploads land here
├── reports/                ← generated PDF/Excel reports land here
├── frontend/
│   └── index.html          ← the PhishGuard UI (served automatically at http://localhost:5000)
└── backend/
    ├── app.py              ← main Flask application
    ├── paths.py             ← shared path resolution (makes the app portable — see below)
    ├── gmail_integration.py← Gmail OAuth routes
    ├── outlook_integration.py← Outlook/Microsoft 365 OAuth routes
    ├── imap_integration.py  ← Yahoo/IMAP connection routes (form-based, not OAuth)
    ├── poller.py            ← provider-agnostic polling loop (works with any EmailProvider)
    ├── providers/
    │   ├── base.py             ← EmailProvider interface — implement this to add a new mail service
    │   ├── gmail_provider.py   ← Gmail's implementation of that interface
    │   ├── outlook_provider.py ← Outlook's implementation of that interface
    │   └── imap_provider.py    ← Generic IMAP implementation (Yahoo, iCloud, Zoho, AOL, ...)
    └── requirements.txt
```

## Portability

The app resolves all its paths (database, models, uploads, credential
files) relative to wherever the running code actually lives — never the
current working directory, and never a hardcoded path. This means the
entire `phishguard-ai` folder can be copied anywhere — a different
folder, a USB drive, or a different machine entirely — and it keeps
working with its own local data. See `backend/paths.py` for details.
This is also what makes the standalone packaged version (see below)
genuinely portable to a machine with no Python installed at all.

## Security notes (read this if presenting/publishing this project)

As of this version, the server:
- **Binds to `127.0.0.1` only** — not reachable from any other device on your
  network, only from this machine
- **Runs via `waitress`** (a production-grade WSGI server) instead of Flask's
  development server, with debug mode off by default
- Development mode (hot reload, interactive debugger) is still available by
  setting `PHISHGUARD_DEV=1` before running — **never leave that on** for
  anything other than active development, since the debugger allows arbitrary
  code execution to anything that can reach it

## Multi-provider architecture

Mail ingestion is built around a common `EmailProvider` interface
(`backend/providers/base.py`) so new providers can be added without
touching the scan pipeline or the polling loop — only a new class
implementing four methods (`ensure_fresh_credentials`,
`list_new_message_ids`, `fetch_normalized_message`, `quarantine_message`)
is needed. Gmail (`gmail_provider.py`) and Outlook/Microsoft 365
(`outlook_provider.py`) are both implemented this way, sharing one
poller and one detection pipeline — a Yahoo/generic-IMAP provider can be
added the same way later without touching either existing provider.

The backend now serves `frontend/index.html` directly at `/`, so once
`start.bat` is running, just open **http://localhost:5000** in your browser —
no separate step to open the HTML file.

### About the pretrained model

`models/model.pkl` and `models/vec.pkl` are your already-trained classifier
and vectorizer — the app loads these on startup instead of retraining from
scratch, so it's ready to scan immediately. They were trained with
scikit-learn 1.9.0, which is why `requirements.txt` is pinned to that exact
version — an older scikit-learn (like the 1.5.1 originally listed) will
throw compatibility warnings or fail to unpickle them correctly. If you ever
want to retrain from scratch instead, delete both `.pkl` files and hit the
`/retrain` endpoint (admin only) — `app.py` will rebuild them from
`data/training_data.txt`.

## Default login

On first run, a default admin account is created:
- Email: `admin@phishguard.org`
- Password: `Admin@2024`

**Change this password after first login** — it's hardcoded in `app.py` for
initial setup convenience only.

## Manual scanning (works immediately, no setup needed)

`POST /analyze-email` with email content — via the API directly, or through
whatever frontend you're pointing at this backend.

## Automated email scanning (optional, needs a one-time setup per provider)

PhishGuard can automatically scan a connected inbox in the background —
no manual copy-paste needed. Three providers are supported:

- **Gmail** — see `SETUP_GMAIL.md` (Google Cloud OAuth)
- **Outlook / Microsoft 365** (including personal outlook.com/hotmail.com
  accounts) — see `SETUP_OUTLOOK.md` (Azure Portal OAuth)
- **Yahoo / other IMAP providers** — see `SETUP_YAHOO.md` (app password,
  no developer account needed — the simplest of the three)

Each is independent — set up one, some, or none. If skipped, `start.bat`
still runs the app fine; Gmail/Outlook log a warning and disable that
provider's OAuth routes, while IMAP is always available since it needs
no server-side app registration. Connect accounts from the **Email
integrations** page in the sidebar once set up.

When a quarantined email is deleted from the PhishGuard UI, it is also
deleted from the real mailbox it came from (moved to that provider's own
Trash/Deleted Items — reversible for a window, same as clicking delete
in any normal email client), not just removed from PhishGuard's own
records.

## Building a standalone desktop app (no Python required to run it)

`start.bat` requires Python installed — great for development, not ideal
for handing the app to someone else or presenting it as a finished
product. Two build scripts turn PhishGuard into a real, portable desktop
app that runs with **no Python installation needed on the machine it
runs on**:

- **`build_exe.bat`** — packages the Python backend into a standalone
  `PhishGuard.exe` using PyInstaller. Produces `backend\dist\PhishGuard\`,
  a complete folder that runs on its own.
- **`build_standalone_app.bat`** — runs the above, then wraps it in a
  real Electron desktop app with a proper Windows installer (Start Menu
  shortcut, uninstaller) and a portable single-folder option. This is
  the one to run if you want the finished, presentable app.

Both must be run **on Windows** — PyInstaller and Electron both build
for whatever OS they're run on, they don't cross-compile. Each script
takes several minutes (mostly downloading build tooling on first run).

**The result is genuinely portable**: copy the built app folder to a
USB drive or a completely different Windows machine with zero Python or
Node.js installed, and it runs correctly — every path it needs (database,
models, credential files) resolves relative to wherever the `.exe`
itself is sitting, never a hardcoded location. See `backend/paths.py`
for exactly how this works.

**What still needs internet, even in the standalone build**: connecting
to Gmail/Outlook/Yahoo and the actual mail-polling every ~90 seconds —
that's inherent to the feature (it's reaching real mail servers), not
something packaging changes. What packaging *does* remove is the app's
dependency on internet access just to start up — language-processing
data that used to download on first run is now bundled in, so a fresh
copy of the app boots correctly even completely offline; it simply
won't be able to check mail until it's back online, same as any email
client.

## Troubleshooting

- **"Python was not found"** — install Python and make sure "Add to PATH" was
  checked during install, then reopen the terminal / re-run `start.bat`.
- **pip install fails on a package** — usually a network/proxy issue; check
  your internet connection and retry `start.bat`.
- **Port 5000 already in use** — close whatever else is using it, or edit the
  last line of `backend/app.py` (`app.run(..., port=5000)`) to a different port.
