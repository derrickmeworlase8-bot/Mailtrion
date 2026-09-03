"""
Mailtrion — encryption at rest for stored account credentials.

Gmail/Outlook OAuth tokens and IMAP app passwords are real credentials
with mailbox access. They must never sit in the database as plaintext —
this module is the one place that encrypts them before every INSERT/UPDATE
and decrypts them before every use, using Fernet (AES-128 in CBC mode with
HMAC authentication) from the `cryptography` package.

Key management:
  - Set ENCRYPTION_KEY as a persistent environment variable (render.yaml
    generates one automatically on first deploy — see the ENCRYPTION_KEY
    entry there). This key must stay the same across restarts, or every
    previously-stored credential becomes undecryptable and every connected
    mail account breaks.
  - If ENCRYPTION_KEY isn't set (e.g. first local run), a key is generated
    for this process only and printed once to the log, the same pattern
    already used for ADMIN_PASSWORD in app.py. Copy it into a real
    environment variable before restarting.
"""

import os
import base64
import hashlib
import logging
from cryptography.fernet import Fernet, InvalidToken

log = logging.getLogger(__name__)


def _derive_fernet_key(raw: str) -> bytes:
    """
    Turns an arbitrary string into a valid Fernet key (32 url-safe base64
    bytes). Fernet.generate_key() already produces something in exactly
    that format, but ENCRYPTION_KEY may instead come from Render's
    render.yaml `generateValue`, a hand-typed passphrase, or anything else
    an operator pastes in — none of which are guaranteed to already be
    valid Fernet keys. Hashing first means any non-empty string works and
    always derives the same key deterministically, so this only ever needs
    to run once per actual key value.
    """
    digest = hashlib.sha256(raw.encode()).digest()
    return base64.urlsafe_b64encode(digest)


def _load_key():
    raw = os.environ.get("ENCRYPTION_KEY")
    if raw:
        return _derive_fernet_key(raw)

    generated = Fernet.generate_key()
    log.warning(
        "═══ No ENCRYPTION_KEY set — generated one for THIS RUN ONLY ═══\n"
        f"    ENCRYPTION_KEY={generated.decode()}\n"
        "    Set this as a persistent environment variable (Render dashboard,\n"
        "    or your local .env) before restarting — otherwise every restart\n"
        "    gets a new key and can no longer decrypt previously stored\n"
        "    account credentials, breaking every connected mailbox.\n"
        "═══════════════════════════════════════════════════════════════"
    )
    return _derive_fernet_key(generated.decode())


_cipher = Fernet(_load_key())


def encrypt_value(plaintext):
    """Encrypts a string for storage. None passes through unchanged."""
    if plaintext is None:
        return None
    return _cipher.encrypt(plaintext.encode()).decode()


def decrypt_value(stored):
    """
    Decrypts a value previously written with encrypt_value(). If `stored`
    isn't valid Fernet ciphertext — e.g. a legacy plaintext row saved
    before encryption-at-rest was added — it's returned unchanged so old
    connected accounts keep working rather than breaking outright. The
    startup migration in app.py sweeps these up and re-encrypts them on
    the next boot, so this fallback path is only ever hit once per row.
    """
    if stored is None:
        return None
    try:
        return _cipher.decrypt(stored.encode()).decode()
    except (InvalidToken, ValueError):
        return stored


def looks_encrypted(stored):
    """True if `stored` is valid Fernet ciphertext (used by the migration
    to decide whether a row still needs encrypting)."""
    if stored is None:
        return True
    try:
        _cipher.decrypt(stored.encode())
        return True
    except (InvalidToken, ValueError):
        return False
