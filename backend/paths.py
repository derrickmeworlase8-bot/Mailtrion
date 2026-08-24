r"""
PhishGuard AI — shared path resolution.

Every file that needs to find the database, models, uploads, or a
credentials file imports from here instead of computing paths itself.
This is what makes the app genuinely portable — to a different folder,
a USB drive, or (once packaged) a different machine entirely with no
Python installed.

Three things matter for portability:

1. Paths must be computed relative to where the CODE lives, never the
   current working directory — a bare filename like "client_secret.json"
   silently breaks if the app is ever launched from a different working
   directory (e.g. a desktop shortcut with a different "Start in" folder).

2. Once packaged into a standalone executable (PyInstaller), __file__
   no longer points somewhere stable — PyInstaller extracts the app into
   a temporary directory at runtime. Read-only bundled assets (the
   frontend, the shipped default models/db, NLTK data) are anchored to
   wherever the actual .exe file sits, so the whole app folder can be
   copied anywhere — including a different machine.

3. Anything the app WRITES to at runtime (the live database, uploaded
   .eml files, generated reports, retrained models, downloaded NLTK
   data) must NOT be anchored next to the .exe once packaged. Installers
   commonly place the app under C:\Program Files, which Windows locks
   down against writes from a non-admin process — writing there fails
   with PermissionError (WinError 5) on every launch. Writable data
   instead goes under the current user's per-user data folder
   (%LOCALAPPDATA%\PhishGuard AI), which is always writable and is the
   standard place Windows apps keep their own data. On first run, any
   bundled defaults (pretrained model, starter db) are copied there
   once; after that the app only touches the per-user copy.
"""

import os
import sys
import shutil

FROZEN = getattr(sys, "frozen", False)

if FROZEN:
    # Packaged executable: read-only bundled assets live next to the
    # .exe itself, not PyInstaller's internal temp extraction directory.
    APP_DIR = os.path.dirname(sys.executable)
    PROJECT_ROOT = APP_DIR

    # Writable data goes under the current user's per-user app-data
    # folder instead — never inside the (possibly read-only) install
    # location. LOCALAPPDATA is always set and always writable by the
    # logged-in user, with no admin rights required.
    WRITABLE_ROOT = os.path.join(
        os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
        "PhishGuard AI",
    )
else:
    # Normal development: this file lives in backend/, so APP_DIR is
    # backend/ and PROJECT_ROOT is one level up — matches the existing
    # project layout (data/, models/, phishguard.db at the root, backend/
    # holding the code). Nothing to separate out in dev mode.
    APP_DIR = os.path.dirname(os.path.abspath(__file__))
    PROJECT_ROOT = os.path.dirname(APP_DIR)
    WRITABLE_ROOT = PROJECT_ROOT

# Read-only bundled defaults — only ever read from, never written to.
# Safe to leave next to the .exe even under Program Files.
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")
_BUNDLED_MODEL_DIR = os.path.join(PROJECT_ROOT, "models")
_BUNDLED_DB_PATH = os.path.join(PROJECT_ROOT, "phishguard.db")
_BUNDLED_NLTK_DATA_DIR = os.path.join(PROJECT_ROOT, "nltk_data")

# Writable data — the app creates/modifies files here at runtime.
MODEL_DIR = os.path.join(WRITABLE_ROOT, "models")
DB_PATH = os.path.join(WRITABLE_ROOT, "phishguard.db")
UPLOAD_DIR = os.path.join(WRITABLE_ROOT, "uploads")
REPORT_DIR = os.path.join(WRITABLE_ROOT, "reports")
NLTK_DATA_DIR = os.path.join(WRITABLE_ROOT, "nltk_data")

# Credential files live next to the running code (APP_DIR) — backend/ in
# dev, the executable's own folder once packaged — matching what
# SETUP_GMAIL.md / SETUP_OUTLOOK.md instruct the user to do. These are
# placed there manually by the person setting up OAuth, not written by
# the app itself at runtime, so they're fine to read from APP_DIR even
# under Program Files.
DEFAULT_GOOGLE_CLIENT_SECRETS = os.path.join(APP_DIR, "client_secret.json")
DEFAULT_OUTLOOK_SECRETS_FILE = os.path.join(APP_DIR, "outlook_secret.json")

for _d in (DATA_DIR, MODEL_DIR, UPLOAD_DIR, REPORT_DIR, NLTK_DATA_DIR):
    os.makedirs(_d, exist_ok=True)


def _seed_once():
    """
    On first run in a packaged build, copy the bundled pretrained model,
    starter database, and NLTK data into the writable per-user folder
    if they're not already there. Subsequent runs are no-ops (the
    per-user copy already exists and is what the app uses from then on
    -- including after a /retrain, which overwrites the per-user copy
    only, leaving the bundled originals untouched).
    """
    if not FROZEN:
        return

    for fname in ("model.pkl", "vec.pkl"):
        src = os.path.join(_BUNDLED_MODEL_DIR, fname)
        dst = os.path.join(MODEL_DIR, fname)
        if os.path.exists(src) and not os.path.exists(dst):
            shutil.copy2(src, dst)

    if os.path.exists(_BUNDLED_DB_PATH) and not os.path.exists(DB_PATH):
        shutil.copy2(_BUNDLED_DB_PATH, DB_PATH)

    if os.path.isdir(_BUNDLED_NLTK_DATA_DIR) and not os.listdir(NLTK_DATA_DIR):
        shutil.copytree(_BUNDLED_NLTK_DATA_DIR, NLTK_DATA_DIR, dirs_exist_ok=True)


_seed_once()
