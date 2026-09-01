"""
Snarelytics - Complete Backend
AI-Based Phishing Email Detection and Risk Assessment System
for Organizational Email Security

Features:
- User Authentication + RBAC (admin / standard user)
- SPF, DKIM, DMARC header parsing
- Gradient Boosting ML classifier + TF-IDF
- 20+ engineered NLP features
- Quarantine management
- PDF & Excel report export
- Audit logging
- .eml file parsing
- Full REST API

Author: Derek - BTech Cybersecurity Final Year Project
"""

import os, re, json, pickle, logging, hashlib, sqlite3, email, email.policy, secrets, uuid
from datetime import datetime, timedelta
from urllib.parse import urlparse
from functools import wraps

from paths import (
    APP_DIR, PROJECT_ROOT, DATA_DIR, MODEL_DIR, DB_PATH, UPLOAD_DIR,
    REPORT_DIR, FRONTEND_DIR, DEFAULT_GOOGLE_CLIENT_SECRETS, DEFAULT_OUTLOOK_SECRETS_FILE,
    NLTK_DATA_DIR,
)
BASE_DIR = APP_DIR  # kept as an alias — some existing code below still refers to BASE_DIR

import nltk
nltk.data.path.insert(0, NLTK_DATA_DIR)  # check the bundled copy before anything else
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import mailer
from crypto_utils import encrypt_value, decrypt_value, looks_encrypted
import relational_signal
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import (precision_score, recall_score,
                              f1_score, roc_auc_score, classification_report)

# ── Optional report libs (graceful fallback) ──────────────────────────────────
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                     Table, TableStyle)
    from reportlab.lib.styles import getSampleStyleSheet
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

try:
    import openpyxl
    EXCEL_AVAILABLE = True
except ImportError:
    EXCEL_AVAILABLE = False

# ── NLTK ──────────────────────────────────────────────────────────────────────
# Check for already-present data (bundled with the packaged app — see
# build_exe.bat) before attempting any network download. This is what
# lets the standalone executable run fully offline on a machine with no
# internet access, rather than failing at startup because it can't reach
# nltk's download servers.
def _ensure_nltk_data(package, path_check):
    try:
        nltk.data.find(path_check)
    except LookupError:
        try:
            nltk.download(package, quiet=True, download_dir=NLTK_DATA_DIR)
        except Exception as e:
            log.warning(f"Could not download NLTK '{package}' data and it wasn't found "
                        f"bundled locally either ({e}). Text preprocessing quality may be "
                        f"reduced. See paths.NLTK_DATA_DIR to bundle it manually offline.")

_ensure_nltk_data("punkt", "tokenizers/punkt")
_ensure_nltk_data("stopwords", "corpora/stopwords")
_ensure_nltk_data("wordnet", "corpora/wordnet")
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
STOP_WORDS  = set(stopwords.words("english"))
LEMMATIZER  = WordNetLemmatizer()

# ── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "phishguard-secret-2024-derek-btech")

# Cap request size so a large upload can't exhaust server memory/disk on a
# public deployment. 15MB comfortably covers any real .eml file.
app.config["MAX_CONTENT_LENGTH"] = 15 * 1024 * 1024

# In-memory token store (maps token -> user info)
TOKENS = {}

# In-memory login-attempt tracker for brute-force throttling (see /auth/login).
# Fast repeated guessing (LOGIN_MAX_ATTEMPTS within LOGIN_WINDOW_SECONDS)
# triggers a much longer LOGIN_LOCKOUT_SECONDS lockout — short window to
# actually catch an automated guesser, long lockout so it isn't worth
# retrying quickly. Change LOGIN_MAX_ATTEMPTS to 3 for a stricter threshold.
LOGIN_ATTEMPTS = {}       # email -> list of recent failed-attempt timestamps
LOGIN_LOCKOUTS = {}       # email -> datetime the lockout ends
LOGIN_MAX_ATTEMPTS = 3
LOGIN_WINDOW_SECONDS = 60
LOGIN_LOCKOUT_SECONDS = 60 * 60  # 1 hour

# OTP email-verification settings.
OTP_EXPIRY_MINUTES = 10
OTP_MAX_VERIFY_ATTEMPTS = 5   # wrong-code guesses allowed before requiring a resend
OTP_RESEND_COOLDOWN_SECONDS = 60
OTP_RESEND_LAST_SENT = {}     # email -> datetime of last OTP send (cooldown)


def _generate_and_send_otp(conn, user_row):
    """Generates a fresh OTP, stores it against the user, and emails it.
    Returns True if the email actually sent, False if it only logged
    (SMTP not configured) — the caller decides what to tell the frontend."""
    code = f"{secrets.randbelow(1000000):06d}"
    expires = (datetime.utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES)).isoformat()
    conn.execute(
        "UPDATE users SET otp_code=?, otp_expires=?, otp_attempts=0 WHERE id=?",
        (code, expires, user_row["id"])
    )
    conn.commit()
    return mailer.send_otp_email(user_row["email"], user_row["username"], code)

CORS(app, supports_credentials=True,
     resources={r"/*": {"origins": "*"}})

@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "File too large (max 15MB)."}), 413

@app.after_request
def add_cors(response):
    response.headers["Access-Control-Allow-Origin"]  = request.headers.get("Origin","*")
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response

@app.route("/", defaults={"path": ""}, methods=["OPTIONS"])
@app.route("/<path:path>", methods=["OPTIONS"])
def options_handler(path):
    return jsonify({}), 200

@app.route("/", methods=["GET"])
def serve_frontend():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        return send_file(index_path)
    return jsonify({"status": "Snarelytics backend running",
                    "note": "frontend/index.html not found"}), 200

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════════════════
# DATABASE
# ══════════════════════════════════════════════════════════════════════════════

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Users
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    UNIQUE NOT NULL,
            email         TEXT    UNIQUE NOT NULL,
            password_hash TEXT    NOT NULL,
            role          TEXT    DEFAULT 'user',
            created_at    TEXT,
            last_login    TEXT,
            is_active     INTEGER DEFAULT 1
        )""")

    # Scans
    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id       TEXT UNIQUE,
            user_id       INTEGER,
            sender        TEXT,
            subject       TEXT,
            email_hash    TEXT,
            verdict       TEXT,
            risk_score    INTEGER,
            risk_level    TEXT,
            confidence    REAL,
            factors       TEXT,
            keywords      TEXT,
            safe_signals  TEXT,
            urls_found    TEXT,
            spf_result    TEXT,
            dkim_result   TEXT,
            dmarc_result  TEXT,
            explanation   TEXT,
            is_quarantined INTEGER DEFAULT 0,
            quarantine_note TEXT,
            released      INTEGER DEFAULT 0,
            created_at    TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )""")

    # Audit log
    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER,
            username    TEXT,
            action      TEXT,
            details     TEXT,
            ip_address  TEXT,
            created_at  TEXT
        )""")

    # Model metrics
    c.execute("""
        CREATE TABLE IF NOT EXISTS model_metrics (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            accuracy   REAL,
            precision  REAL,
            recall     REAL,
            f1         REAL,
            auc        REAL,
            trained_at TEXT
        )""")

    # Gmail connected accounts (Phase 1 — automated ingestion)
    c.execute("""
        CREATE TABLE IF NOT EXISTS gmail_accounts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         INTEGER NOT NULL,
            gmail_address   TEXT UNIQUE NOT NULL,
            access_token    TEXT NOT NULL,
            refresh_token   TEXT NOT NULL,
            token_expiry    TEXT,
            last_history_id TEXT,
            connected_at    TEXT,
            last_polled_at  TEXT,
            is_active       INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )""")

    # Outlook / Microsoft 365 connected accounts (Phase B — multi-provider)
    c.execute("""
        CREATE TABLE IF NOT EXISTS outlook_accounts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         INTEGER NOT NULL,
            email_address   TEXT UNIQUE NOT NULL,
            access_token    TEXT NOT NULL,
            refresh_token   TEXT NOT NULL,
            connected_at    TEXT,
            last_polled_at  TEXT,
            is_active       INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )""")

    # Generic IMAP connected accounts (Phase C — Yahoo and other IMAP-only
    # providers, which don't offer a practical OAuth flow for third-party
    # apps). Uses a stored app password instead of an OAuth token — see
    # the security note in providers/imap_provider.py.
    c.execute("""
        CREATE TABLE IF NOT EXISTS imap_accounts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         INTEGER NOT NULL,
            provider_label  TEXT NOT NULL,
            username        TEXT UNIQUE NOT NULL,
            app_password    TEXT NOT NULL,
            imap_host       TEXT NOT NULL,
            imap_port       INTEGER NOT NULL DEFAULT 993,
            spam_folder     TEXT NOT NULL DEFAULT 'Spam',
            trash_folder    TEXT DEFAULT 'Trash',
            connected_at    TEXT,
            last_polled_at  TEXT,
            is_active       INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )""")

    # Sender-receiver relational signal — see relational_signal.py. Scoped
    # per-organization so one institution's sender history never leaks
    # into another's risk scoring.
    c.execute("""
        CREATE TABLE IF NOT EXISTS sender_reputation (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            organization    TEXT NOT NULL,
            sender_domain   TEXT NOT NULL,
            total_seen      INTEGER DEFAULT 0,
            phishing_count  INTEGER DEFAULT 0,
            first_seen      TEXT,
            last_seen       TEXT,
            UNIQUE(organization, sender_domain)
        )""")

    conn.commit()

    # ── Lightweight migration for existing DBs (adds columns if missing) ──────
    existing_cols = {row[1] for row in c.execute("PRAGMA table_info(scans)").fetchall()}
    if "source" not in existing_cols:
        c.execute("ALTER TABLE scans ADD COLUMN source TEXT DEFAULT 'manual'")
        log.info("Migration: added scans.source")
    if "gmail_message_id" not in existing_cols:
        c.execute("ALTER TABLE scans ADD COLUMN gmail_message_id TEXT")
        log.info("Migration: added scans.gmail_message_id")
    if "provider" not in existing_cols:
        c.execute("ALTER TABLE scans ADD COLUMN provider TEXT")
        log.info("Migration: added scans.provider")
    if "account_id" not in existing_cols:
        c.execute("ALTER TABLE scans ADD COLUMN account_id INTEGER")
        log.info("Migration: added scans.account_id")
    # Analyst feedback loop — lets an analyst mark a flagged email as a
    # false positive, so the correction is captured (for future retraining
    # and for showing reviewers the system improves from real usage)
    # instead of only ever being silently released from quarantine.
    if "analyst_feedback" not in existing_cols:
        c.execute("ALTER TABLE scans ADD COLUMN analyst_feedback TEXT")
        log.info("Migration: added scans.analyst_feedback")
    if "feedback_by" not in existing_cols:
        c.execute("ALTER TABLE scans ADD COLUMN feedback_by TEXT")
        log.info("Migration: added scans.feedback_by")
    if "feedback_at" not in existing_cols:
        c.execute("ALTER TABLE scans ADD COLUMN feedback_at TEXT")
        log.info("Migration: added scans.feedback_at")
    conn.commit()

    # ── Migration: email verification (OTP) columns on users ──────────────────
    existing_user_cols = {row[1] for row in c.execute("PRAGMA table_info(users)").fetchall()}
    if "is_verified" not in existing_user_cols:
        # Existing accounts (created before this feature existed) are grandfathered
        # in as already-verified, so nobody who could already log in gets locked out.
        c.execute("ALTER TABLE users ADD COLUMN is_verified INTEGER DEFAULT 1")
        log.info("Migration: added users.is_verified")
    if "otp_code" not in existing_user_cols:
        c.execute("ALTER TABLE users ADD COLUMN otp_code TEXT")
        log.info("Migration: added users.otp_code")
    if "otp_expires" not in existing_user_cols:
        c.execute("ALTER TABLE users ADD COLUMN otp_expires TEXT")
        log.info("Migration: added users.otp_expires")
    if "otp_attempts" not in existing_user_cols:
        c.execute("ALTER TABLE users ADD COLUMN otp_attempts INTEGER DEFAULT 0")
        log.info("Migration: added users.otp_attempts")
    if "reset_code" not in existing_user_cols:
        c.execute("ALTER TABLE users ADD COLUMN reset_code TEXT")
        log.info("Migration: added users.reset_code")
    if "reset_expires" not in existing_user_cols:
        c.execute("ALTER TABLE users ADD COLUMN reset_expires TEXT")
        log.info("Migration: added users.reset_expires")
    if "reset_attempts" not in existing_user_cols:
        c.execute("ALTER TABLE users ADD COLUMN reset_attempts INTEGER DEFAULT 0")
        log.info("Migration: added users.reset_attempts")
    # Institution/organization — the field that makes the admin view a real
    # multi-tenant oversight tool (per-institution activity) rather than one
    # flat user list. Free-text rather than a separate table for now: simple,
    # and good enough at "hundreds to low thousands of accounts, a handful
    # of institutions" scale.
    if "organization" not in existing_user_cols:
        c.execute("ALTER TABLE users ADD COLUMN organization TEXT DEFAULT 'Unassigned'")
        log.info("Migration: added users.organization")
    conn.commit()

    # ── Migration: push-notification columns (Tier 3, optional) ────────────────
    existing_gmail_cols = {row[1] for row in c.execute("PRAGMA table_info(gmail_accounts)").fetchall()}
    if "history_id" not in existing_gmail_cols:
        c.execute("ALTER TABLE gmail_accounts ADD COLUMN history_id TEXT")
        log.info("Migration: added gmail_accounts.history_id")
    if "watch_expiration" not in existing_gmail_cols:
        c.execute("ALTER TABLE gmail_accounts ADD COLUMN watch_expiration TEXT")
        log.info("Migration: added gmail_accounts.watch_expiration")

    existing_outlook_cols = {row[1] for row in c.execute("PRAGMA table_info(outlook_accounts)").fetchall()}
    if "subscription_id" not in existing_outlook_cols:
        c.execute("ALTER TABLE outlook_accounts ADD COLUMN subscription_id TEXT")
        log.info("Migration: added outlook_accounts.subscription_id")
    if "subscription_expires" not in existing_outlook_cols:
        c.execute("ALTER TABLE outlook_accounts ADD COLUMN subscription_expires TEXT")
        log.info("Migration: added outlook_accounts.subscription_expires")
    if "webhook_client_state" not in existing_outlook_cols:
        c.execute("ALTER TABLE outlook_accounts ADD COLUMN webhook_client_state TEXT")
        log.info("Migration: added outlook_accounts.webhook_client_state")
    conn.commit()

    # ── Migration: role rename 'user' -> 'analyst' ─────────────────────────────
    # Two roles only, per the reviewer's requested change: Admin and Analyst.
    # Existing rows created before this rename still say 'user' — bring them
    # forward every startup (idempotent; a no-op once nothing matches).
    renamed = c.execute("UPDATE users SET role='analyst' WHERE role='user'").rowcount
    conn.commit()
    if renamed:
        log.info(f"Migration: renamed role 'user' -> 'analyst' for {renamed} account(s)")

    # ── Migration: encrypt any legacy plaintext credentials ───────────────────
    # Rows written before encryption-at-rest was added are still plaintext.
    # Sweep them once at startup: anything that isn't valid Fernet ciphertext
    # gets encrypted in place. Safe to run every boot — already-encrypted
    # rows are left untouched.
    _migrate_credential_encryption(conn, c)

    # Create default admin if no users
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        # A fixed default password here would mean every deployment of this
        # code shares the same admin login — anyone who has seen this source
        # file could log into any instance. Instead: read it from an env var
        # if the operator set one (ADMIN_PASSWORD on Render, etc.), otherwise
        # generate a random one and print it ONCE to the startup log — the
        # operator must go retrieve it from there before anyone else does.
        admin_password = os.environ.get("ADMIN_PASSWORD")
        generated = admin_password is None
        if generated:
            admin_password = secrets.token_urlsafe(12)

        c.execute("""INSERT INTO users
            (username,email,password_hash,role,created_at)
            VALUES (?,?,?,?,?)""",
            ("admin","admin@phishguard.org",
             generate_password_hash(admin_password),
             "admin", datetime.utcnow().isoformat()))
        conn.commit()
        if generated:
            log.warning(
                f"═══ Default admin created — SAVE THIS NOW, it will not be shown again ═══\n"
                f"    email:    admin@phishguard.org\n"
                f"    password: {admin_password}\n"
                f"    Log in once and change it, or set ADMIN_PASSWORD as an env var "
                f"before first run to choose your own.\n"
                f"══════════════════════════════════════════════════════════════════════"
            )
        else:
            log.info("Default admin created using ADMIN_PASSWORD from environment.")

    conn.close()
    log.info("Database initialised")


def _migrate_credential_encryption(conn, c):
    """One-time (per legacy row) sweep: encrypts any OAuth token or IMAP
    app password that's still sitting in the database as plaintext,
    because it was written before encryption-at-rest was added. Safe to
    call on every startup — already-encrypted rows are left untouched."""
    creds_to_check = [
        ("gmail_accounts",   ["access_token", "refresh_token"]),
        ("outlook_accounts", ["access_token", "refresh_token"]),
        ("imap_accounts",    ["app_password"]),
    ]
    for table, columns in creds_to_check:
        rows = c.execute(f"SELECT id, {', '.join(columns)} FROM {table}").fetchall()
        for row in rows:
            row_id = row[0]
            updates = {}
            for i, col in enumerate(columns, start=1):
                value = row[i]
                if value is not None and not looks_encrypted(value):
                    updates[col] = encrypt_value(value)
            if updates:
                set_clause = ", ".join(f"{col}=?" for col in updates)
                c.execute(f"UPDATE {table} SET {set_clause} WHERE id=?",
                          (*updates.values(), row_id))
                log.info(f"Migration: encrypted legacy plaintext credential(s) in {table} id={row_id}")
    conn.commit()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def audit(user_id, username, action, details=""):
    conn = get_db()
    conn.execute("""INSERT INTO audit_log
        (user_id,username,action,details,ip_address,created_at)
        VALUES (?,?,?,?,?,?)""",
        (user_id, username, action, details,
         request.remote_addr if request else "",
         datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

# ══════════════════════════════════════════════════════════════════════════════
# AUTH HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def get_token():
    auth = request.headers.get("Authorization","")
    if auth.startswith("Bearer "):
        return auth[7:]
    return request.args.get("token","")

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token()
        if not token or token not in TOKENS:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token()
        if not token or token not in TOKENS:
            return jsonify({"error": "Authentication required"}), 401
        if TOKENS[token].get("role") != "admin":
            return jsonify({"error": "Administrator privileges required"}), 403
        return f(*args, **kwargs)
    return decorated


def current_user():
    token = get_token()
    if token and token in TOKENS:
        return TOKENS[token]
    return {"id": None, "username": "unknown", "role": "analyst"}

# ══════════════════════════════════════════════════════════════════════════════
# PHISHING KNOWLEDGE
# ══════════════════════════════════════════════════════════════════════════════

PHISHING_KWS = [
    "verify your account","confirm your identity","urgent action required",
    "click here immediately","account will be suspended","update your payment",
    "winner","congratulations","free gift","limited time offer",
    "act now","password expired","security alert","unusual activity",
    "wire transfer","western union","gift card","bitcoin",
    "prize","lottery","inheritance","beneficiary",
    "click the link below","dear customer","dear user","dear account holder",
    "kindly","revert back","do the needful","suspended","deactivated",
    "locked","blocked","unauthorized","claim your reward","you have been selected"
]

SAFE_SIGNALS = [
    "unsubscribe","privacy policy","terms of service",
    "copyright","all rights reserved","contact us",
    "manage preferences","view in browser"
]

SUSPICIOUS_TLDS = {".tk",".ml",".ga",".cf",".gq",".xyz",
                   ".top",".click",".download",".zip"}

URGENCY_PATTERNS = [
    r"within\s+\d+\s+hours?", r"expires?\s+in\s+\d+", r"immediately",
    r"urgent", r"asap", r"right now", r"act\s+now"
]

# ══════════════════════════════════════════════════════════════════════════════
# EMAIL HEADER AUTHENTICATION PARSING (SPF / DKIM / DMARC)
# ══════════════════════════════════════════════════════════════════════════════

def parse_auth_results(raw_headers: str) -> dict:
    """
    Parse Authentication-Results header for SPF, DKIM, DMARC outcomes.
    Returns dict with keys spf, dkim, dmarc each being pass/fail/neutral/none.
    """
    result = {"spf": "none", "dkim": "none", "dmarc": "none"}
    # Authentication-Results: header
    ar_match = re.search(
        r"Authentication-Results:[^\n]+(?:\n\s+[^\n]+)*",
        raw_headers, re.IGNORECASE)
    if ar_match:
        ar = ar_match.group(0).lower()
        for proto in ("spf","dkim","dmarc"):
            m = re.search(rf"{proto}=(\w+)", ar)
            if m:
                result[proto] = m.group(1)
        return result

    # Received-SPF header fallback
    spf_match = re.search(r"Received-SPF:\s*(\w+)", raw_headers, re.IGNORECASE)
    if spf_match:
        result["spf"] = spf_match.group(1).lower()

    # DKIM-Signature presence
    if re.search(r"DKIM-Signature:", raw_headers, re.IGNORECASE):
        result["dkim"] = "present"

    return result


def auth_risk_score(auth: dict) -> int:
    """Return extra risk points based on auth failures."""
    score = 0
    if auth["spf"]   not in ("pass","neutral","none"):   score += 15
    if auth["dkim"]  not in ("pass","present","none"):   score += 10
    if auth["dmarc"] not in ("pass","bestguesspass","none"): score += 10
    return score

# ══════════════════════════════════════════════════════════════════════════════
# NLP & FEATURE ENGINEERING
# ══════════════════════════════════════════════════════════════════════════════

def preprocess_text(text: str) -> str:
    text = text.lower()
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"https?://\S+", " urltoken ", text)
    text = re.sub(r"[^a-z\s]", " ", text)
    tokens = [LEMMATIZER.lemmatize(t)
              for t in text.split()
              if t not in STOP_WORDS and len(t) > 2]
    return " ".join(tokens)


def extract_urls(text: str) -> list:
    return re.findall(r"https?://[^\s<>\"'()]+", text)


def is_suspicious_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace("www.","")
        if any(domain.endswith(t) for t in SUSPICIOUS_TLDS): return True
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}", domain):     return True
        if domain.count(".") > 3:                             return True
        shorteners = {"bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","short.io"}
        if domain in shorteners:                              return True
    except Exception:
        pass
    return False


def count_urgency(text: str) -> int:
    return sum(1 for p in URGENCY_PATTERNS if re.search(p, text.lower()))


def engineer_features(body: str, sender: str="", subject: str="",
                      auth: dict=None) -> dict:
    if auth is None:
        auth = {"spf":"none","dkim":"none","dmarc":"none"}

    full = f"{subject} {sender} {body}".lower()
    urls = extract_urls(body)
    susp_urls = [u for u in urls if is_suspicious_url(u)]
    words = body.split()

    sender_domain = sender.split("@")[-1].lower() if "@" in sender else ""
    free_email = 1 if any(d in sender_domain
                          for d in ["gmail","yahoo","hotmail","outlook"]) else 0
    domain_mismatch = 1 if (
        sender_domain and
        any(b in full for b in ["paypal","amazon","google","microsoft","apple","bank"]) and
        not any(b in sender_domain for b in ["paypal","amazon","google","microsoft","apple"])
    ) else 0

    spf_fail  = 1 if auth["spf"]   in ("fail","softfail","permerror") else 0
    dkim_fail = 1 if auth["dkim"]  in ("fail","permerror")            else 0
    dmarc_fail= 1 if auth["dmarc"] in ("fail","reject","quarantine")  else 0

    return {
        "num_urls":            len(urls),
        "num_suspicious_urls": len(susp_urls),
        "phish_kw_count":      sum(1 for k in PHISHING_KWS if k in full),
        "safe_kw_count":       sum(1 for k in SAFE_SIGNALS if k in full),
        "urgency_count":       count_urgency(full),
        "word_count":          len(words),
        "exclamation_count":   body.count("!"),
        "question_count":      body.count("?"),
        "caps_ratio":          round(sum(1 for c in body if c.isupper())/max(len(body),1),3),
        "free_email_sender":   free_email,
        "domain_mismatch":     domain_mismatch,
        "subject_caps_ratio":  round(sum(1 for c in subject if c.isupper())/max(len(subject),1),3),
        "subject_exclamation": subject.count("!"),
        "has_money_terms":     1 if re.search(r"\$[\d,]+|free money|wire transfer|bitcoin",full) else 0,
        "has_attachment_ref":  1 if re.search(r"attach|download|open the file",full) else 0,
        "has_login_request":   1 if re.search(r"log\s?in|sign\s?in|verify|confirm|validate",full) else 0,
        "has_html":            1 if re.search(r"<[a-z]+",body.lower()) else 0,
        "spf_fail":            spf_fail,
        "dkim_fail":           dkim_fail,
        "dmarc_fail":          dmarc_fail,
        "auth_failures":       spf_fail + dkim_fail + dmarc_fail,
    }

# ══════════════════════════════════════════════════════════════════════════════
# .EML FILE PARSING
# ══════════════════════════════════════════════════════════════════════════════

def parse_eml(raw_bytes: bytes) -> dict:
    """Parse a raw .eml file and return body, sender, subject, raw_headers."""
    try:
        msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
        sender  = msg.get("From","")
        subject = msg.get("Subject","")
        raw_headers = str(msg)[:4000]

        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                if ct == "text/plain":
                    body += part.get_content() or ""
                elif ct == "text/html" and not body:
                    body += re.sub(r"<[^>]+>"," ", part.get_content() or "")
        else:
            body = msg.get_content() or ""

        return {"sender": sender, "subject": subject,
                "body": body, "raw_headers": raw_headers, "ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ══════════════════════════════════════════════════════════════════════════════
# ML MODEL
# ══════════════════════════════════════════════════════════════════════════════

def load_training_data():
    samples = []
    txt = os.path.join(DATA_DIR, "training_data.txt")
    if os.path.exists(txt):
        with open(txt) as f:
            for line in f:
                if "," in line:
                    lbl, text = line.strip().split(",",1)
                    try: samples.append((text.strip(), int(lbl.strip())))
                    except ValueError: pass

    builtin = [
        # Phishing
        ("Dear customer your PayPal account has been limited click here to verify your identity immediately",1),
        ("URGENT your bank account has been suspended verify now to avoid permanent closure",1),
        ("Congratulations you have been selected winner claim your free prize click here",1),
        ("Your password has expired update your login credentials within 24 hours",1),
        ("Dear user unusual activity detected confirm your details to restore access",1),
        ("You have received an inheritance fund contact us urgently",1),
        ("ALERT your Netflix subscription will be cancelled update payment information immediately",1),
        ("Security alert someone logged into your account verify now",1),
        ("Your tax refund is pending confirm your bank account details to receive it",1),
        ("Free gift card offer limited time only claim your Amazon card by clicking below",1),
        ("Your Microsoft account will be deactivated verify your email within 48 hours urgently",1),
        ("Kindly revert with your banking details to process the wire transfer urgently",1),
        ("Act now your Apple ID has been used to sign in from another country verify immediately",1),
        ("Dear beneficiary your compensation package has been fully approved contact us",1),
        ("You have won the international lottery contact our agent to claim your prize",1),
        ("Your account shows suspicious login attempts click here to secure your account now",1),
        ("FINAL WARNING update your payment method or your account will be permanently deleted",1),
        ("Verify your social security number to avoid legal action from the IRS",1),
        ("Your DHL package is on hold pay customs fee via the link to release delivery",1),
        ("We detected a virus on your device call our toll free number to remove it now",1),
        ("Dear valued customer your credit card has been blocked verify details to unblock",1),
        ("Your email storage is full upgrade now or lose all your emails permanently",1),
        ("Urgent your payroll account needs verification log in now to avoid disruption",1),
        ("Exclusive buy bitcoin now and triple your investment in 48 hours guaranteed",1),
        ("Click here to receive your COVID relief fund payment limited slots government approved",1),
        ("Your online banking session expired click the link to log in and verify now",1),
        ("We noticed unauthorized access your account has been flagged verify immediately",1),
        ("Your reward points are about to expire redeem them now by clicking the link",1),
        ("Dear account holder update your billing information within hours or service terminated",1),
        ("You have a pending wire transfer click here to approve the transaction immediately",1),
        # Safe
        ("Hi team the quarterly report is attached please review and share feedback by Friday",0),
        ("Your order has been shipped and will arrive within 3 to 5 business days",0),
        ("Thank you for registering please confirm your email by clicking the verification link",0),
        ("The weekly team meeting is scheduled for Thursday at 2pm please add to your calendar",0),
        ("Hi John just following up on the proposal we discussed last week let me know thoughts",0),
        ("Your subscription has been renewed successfully your next billing date is next month",0),
        ("Welcome to our newsletter you can unsubscribe at any time using the link at bottom",0),
        ("The project deadline has been moved to next Monday please update tasks accordingly",0),
        ("Your support ticket has been received our team will respond within 24 hours",0),
        ("Reminder your annual performance review is scheduled for next week prepare your report",0),
        ("Here is the invoice for your recent purchase please find details attached",0),
        ("We are pleased to inform you your job application has moved to interview stage",0),
        ("Your flight booking confirmation is attached please check in online 24 hours before",0),
        ("The board meeting minutes have been uploaded to the shared drive please review",0),
        ("Hi Sarah please find the research paper you requested attached hope it helps",0),
        ("Your password was successfully changed if you did not make this change contact support",0),
        ("Thank you for your payment your account is now in good standing view receipt in portal",0),
        ("The new company policy document is attached please read and acknowledge by end of week",0),
        ("We are conducting system maintenance this Saturday from 2am to 4am brief downtime",0),
        ("Your annual report is now available in your member dashboard log in to view statement",0),
        ("Please join us for the company anniversary celebration on Friday evening all staff welcome",0),
        ("Your recent donation to the charity has been processed thank you for generous contribution",0),
        ("The software update is now available please install it for the latest security patches",0),
        ("Hi team as discussed in our last meeting here is the updated project timeline for review",0),
        ("Your library book is due for return in 3 days please renew online or visit local branch",0),
        ("Dear colleague the office will be closed on Monday for the public holiday",0),
        ("The client presentation has been rescheduled to 2:30pm on Wednesday update your calendars",0),
        ("Your medical appointment is confirmed for next Tuesday at 10am arrive 15 minutes early",0),
        ("Thank you for completing the survey your feedback is valuable for improving our services",0),
        ("The IT department will perform server upgrades this weekend please save all your work",0),
        ("Your parking permit renewal is due next month please submit the renewal form to facilities",0),
    ]
    samples.extend(builtin)
    log.info(f"Total training samples: {len(samples)}")
    return samples


def build_model():
    samples = load_training_data()
    texts  = [preprocess_text(s[0]) for s in samples]
    labels = [s[1] for s in samples]

    X_tr, X_te, y_tr, y_te = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels)

    vec = TfidfVectorizer(ngram_range=(1,3), max_features=5000,
                          sublinear_tf=True, min_df=1)
    X_tr_v = vec.fit_transform(X_tr)
    X_te_v = vec.transform(X_te)

    clf = GradientBoostingClassifier(n_estimators=200, learning_rate=0.1,
                                     max_depth=4, random_state=42)
    clf.fit(X_tr_v, y_tr)

    y_pred  = clf.predict(X_te_v)
    y_proba = clf.predict_proba(X_te_v)[:,1]

    metrics = {
        "accuracy":  round(float(np.mean(np.array(y_pred)==np.array(y_te))),4),
        "precision": round(float(precision_score(y_te,y_pred,zero_division=0)),4),
        "recall":    round(float(recall_score(y_te,y_pred,zero_division=0)),4),
        "f1":        round(float(f1_score(y_te,y_pred,zero_division=0)),4),
        "auc":       round(float(roc_auc_score(y_te,y_proba)),4) if len(set(y_te))>1 else 0.0,
    }
    log.info(f"Model: acc={metrics['accuracy']} f1={metrics['f1']} auc={metrics['auc']}")
    log.info(f"\n{classification_report(y_te,y_pred,target_names=['Safe','Phishing'])}")

    with open(os.path.join(MODEL_DIR,"model.pkl"),"wb") as f: pickle.dump(clf,f)
    with open(os.path.join(MODEL_DIR,"vec.pkl"),"wb")   as f: pickle.dump(vec,f)

    conn = get_db()
    conn.execute("INSERT INTO model_metrics (accuracy,precision,recall,f1,auc,trained_at) VALUES (?,?,?,?,?,?)",
        (metrics["accuracy"],metrics["precision"],metrics["recall"],
         metrics["f1"],metrics["auc"],datetime.utcnow().isoformat()))
    conn.commit(); conn.close()
    return clf, vec, metrics


def load_model():
    mp = os.path.join(MODEL_DIR,"model.pkl")
    vp = os.path.join(MODEL_DIR,"vec.pkl")
    if os.path.exists(mp) and os.path.exists(vp):
        with open(mp,"rb") as f: clf=pickle.load(f)
        with open(vp,"rb") as f: vec=pickle.load(f)
        log.info("Loaded saved model")
        return clf, vec
    return build_model()[:2]

# ══════════════════════════════════════════════════════════════════════════════
# RISK SCORING & XAI
# ══════════════════════════════════════════════════════════════════════════════

def compute_risk(proba: float, features: dict, auth: dict) -> int:
    base  = proba * 65
    bonus = 0
    bonus += min(20, features["phish_kw_count"]      * 5)
    bonus += min(15, features["num_suspicious_urls"]  * 10)
    bonus += min(8,  features["urgency_count"]        * 3)
    bonus += 8  if features["domain_mismatch"]    else 0
    bonus += 6  if features["has_login_request"]  else 0
    bonus += 5  if features["has_money_terms"]    else 0
    bonus += auth_risk_score(auth)
    bonus -= min(8, features["safe_kw_count"] * 3)
    return max(0, min(100, int(round(base + bonus))))


def score_to_verdict(score: int):
    if score >= 75: return "Phishing",   "Critical"
    if score >= 50: return "Suspicious", "High"
    if score >= 25: return "Suspicious", "Medium"
    return "Safe", "Low"


def get_factors(features: dict, auth: dict) -> list:
    factors = []
    if features["phish_kw_count"] > 0:
        factors.append({"name":"Phishing keywords",
                        "weight":min(100,features["phish_kw_count"]*20),
                        "impact":"negative"})
    if features["num_suspicious_urls"] > 0:
        factors.append({"name":"Suspicious URLs",
                        "weight":min(100,features["num_suspicious_urls"]*35),
                        "impact":"negative"})
    if features["urgency_count"] > 0:
        factors.append({"name":"Urgency language",
                        "weight":min(100,features["urgency_count"]*25),
                        "impact":"negative"})
    if features["domain_mismatch"]:
        factors.append({"name":"Domain mismatch","weight":80,"impact":"negative"})
    if features["has_login_request"]:
        factors.append({"name":"Login/verify request","weight":55,"impact":"negative"})
    if features["has_money_terms"]:
        factors.append({"name":"Financial lure","weight":65,"impact":"negative"})
    if auth["spf"] in ("fail","softfail"):
        factors.append({"name":"SPF failed","weight":60,"impact":"negative"})
    if auth["dkim"] in ("fail",):
        factors.append({"name":"DKIM failed","weight":50,"impact":"negative"})
    if auth["dmarc"] in ("fail","reject","quarantine"):
        factors.append({"name":"DMARC failed","weight":55,"impact":"negative"})
    if features["safe_kw_count"] > 0:
        factors.append({"name":"Trust signals present",
                        "weight":min(100,features["safe_kw_count"]*25),
                        "impact":"positive"})
    factors.sort(key=lambda x:(0 if x["impact"]=="negative" else 1,-x["weight"]))
    return factors[:6]


def explain(verdict,score,factors,phish_kws,susp_urls,auth):
    top = factors[0]["name"] if factors else "multiple signals"
    url_note = f" with {len(susp_urls)} suspicious URL(s)" if susp_urls else ""
    auth_note = ""
    fails = [k for k,v in auth.items() if v in ("fail","softfail","reject","quarantine","permerror")]
    if fails: auth_note = f" Authentication failures detected: {', '.join(f.upper() for f in fails)}."
    if verdict == "Phishing":
        s = f"High-confidence phishing detected (score {score}/100) driven by {top}{url_note}.{auth_note}"
        if phish_kws: s += f" Key phrases: \"{phish_kws[0]}\"."
    elif verdict == "Suspicious":
        s = f"Email flagged as suspicious (score {score}/100) due to {top}{url_note}.{auth_note} Manual review recommended."
    else:
        s = f"Email appears safe (score {score}/100). No significant phishing indicators detected."
    return s

# ══════════════════════════════════════════════════════════════════════════════
# AUTH ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/auth/register", methods=["POST"])
def register():
    d = request.get_json()
    username = (d.get("username","")).strip()
    em       = (d.get("email","")).strip().lower()
    pw       = d.get("password","")
    role     = "analyst"
    # Optional at signup — an institution can also assign/correct this later
    # from the admin Users panel. Falls back to the same 'Unassigned' default
    # new columns get, so grouping in the admin view never breaks on a blank.
    organization = (d.get("organization","") or "").strip() or "Unassigned"

    if not username or not em or not pw:
        return jsonify({"error":"All fields required"}), 400
    if len(pw) < 8:
        return jsonify({"error":"Password must be at least 8 characters"}), 400

    conn = get_db()
    try:
        conn.execute("""INSERT INTO users (username,email,password_hash,role,organization,created_at,is_verified)
            VALUES (?,?,?,?,?,?,0)""",
            (username, em, generate_password_hash(pw), role, organization,
             datetime.utcnow().isoformat()))
        conn.commit()
        audit(None, username, "REGISTER", f"New user registered: {em}")

        user = conn.execute("SELECT * FROM users WHERE email=?", (em,)).fetchone()
        emailed = _generate_and_send_otp(conn, user)

        if emailed:
            return jsonify({
                "message": "Account created. Check your email for a 6-digit verification code.",
                "email": em
            }), 201
        else:
            # SMTP isn't configured on this deployment — the code went to the
            # server log instead. Say so plainly rather than pretending an
            # email was sent when it wasn't.
            return jsonify({
                "message": "Account created, but the verification email could not be sent "
                           "(email sending isn't configured on this server yet). "
                           "Contact the administrator to verify your account.",
                "email": em,
                "email_sent": False
            }), 201
    except sqlite3.IntegrityError:
        return jsonify({
            "error": "An account with this email or username already exists.",
            "account_exists": True
        }), 409
    finally:
        conn.close()


@app.route("/auth/forgot-password", methods=["POST"])
def forgot_password():
    d = request.get_json()
    em = (d.get("email","")).strip().lower()
    if not em:
        return jsonify({"error": "Email is required"}), 400

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email=? AND is_active=1", (em,)).fetchone()

    # Same response whether or not the account exists, so this can't be used
    # to check which emails are registered on the system.
    if not user:
        conn.close()
        return jsonify({"message": "If that account exists, a reset code was sent to its email."}), 200

    code = f"{secrets.randbelow(1000000):06d}"
    expires = (datetime.utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES)).isoformat()
    conn.execute(
        "UPDATE users SET reset_code=?, reset_expires=?, reset_attempts=0 WHERE id=?",
        (code, expires, user["id"])
    )
    conn.commit()
    mailer.send_password_reset_email(user["email"], user["username"], code)
    audit(user["id"], user["username"], "PASSWORD_RESET_REQUESTED", f"Reset code sent to {em}")
    conn.close()
    return jsonify({"message": "If that account exists, a reset code was sent to its email."}), 200


@app.route("/auth/reset-password", methods=["POST"])
def reset_password():
    d = request.get_json()
    em = (d.get("email","")).strip().lower()
    code = (d.get("code","")).strip()
    new_pw = d.get("new_password","")

    if not em or not code or not new_pw:
        return jsonify({"error": "Email, code, and new password are all required"}), 400
    if len(new_pw) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email=?", (em,)).fetchone()

    if not user or not user["reset_code"] or not user["reset_expires"]:
        conn.close()
        return jsonify({"error": "Invalid or expired reset code"}), 400

    if datetime.utcnow() > datetime.fromisoformat(user["reset_expires"]):
        conn.close()
        return jsonify({"error": "Reset code expired. Request a new one."}), 400

    if user["reset_attempts"] >= OTP_MAX_VERIFY_ATTEMPTS:
        conn.close()
        return jsonify({"error": "Too many incorrect attempts. Request a new reset code."}), 429

    if code != user["reset_code"]:
        conn.execute("UPDATE users SET reset_attempts = reset_attempts + 1 WHERE id=?", (user["id"],))
        conn.commit()
        conn.close()
        return jsonify({"error": "Incorrect code"}), 400

    conn.execute(
        "UPDATE users SET password_hash=?, reset_code=NULL, reset_expires=NULL, reset_attempts=0 WHERE id=?",
        (generate_password_hash(new_pw), user["id"])
    )
    conn.commit()
    audit(user["id"], user["username"], "PASSWORD_RESET", f"{em} reset their password")
    conn.close()
    return jsonify({"message": "Password reset. You can now sign in with your new password."}), 200


@app.route("/auth/verify-otp", methods=["POST"])
def verify_otp():
    d = request.get_json()
    em   = (d.get("email","")).strip().lower()
    code = (d.get("code","")).strip()

    if not em or not code:
        return jsonify({"error": "Email and code are required"}), 400

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email=?", (em,)).fetchone()

    if not user:
        conn.close()
        return jsonify({"error": "Invalid email or code"}), 400

    if user["is_verified"]:
        conn.close()
        return jsonify({"message": "Account already verified. You can log in."}), 200

    if not user["otp_code"] or not user["otp_expires"]:
        conn.close()
        return jsonify({"error": "No verification code pending. Request a new one."}), 400

    if datetime.utcnow() > datetime.fromisoformat(user["otp_expires"]):
        conn.close()
        return jsonify({"error": "Code expired. Request a new one."}), 400

    if user["otp_attempts"] >= OTP_MAX_VERIFY_ATTEMPTS:
        conn.close()
        return jsonify({"error": "Too many incorrect attempts. Request a new code."}), 429

    if code != user["otp_code"]:
        conn.execute("UPDATE users SET otp_attempts = otp_attempts + 1 WHERE id=?", (user["id"],))
        conn.commit()
        conn.close()
        return jsonify({"error": "Incorrect code"}), 400

    conn.execute(
        "UPDATE users SET is_verified=1, otp_code=NULL, otp_expires=NULL, otp_attempts=0 WHERE id=?",
        (user["id"],)
    )
    conn.commit()
    audit(user["id"], user["username"], "EMAIL_VERIFIED", f"{em} verified their email")
    conn.close()
    return jsonify({"message": "Email verified. You can now log in."}), 200


@app.route("/auth/resend-otp", methods=["POST"])
def resend_otp():
    d = request.get_json()
    em = (d.get("email","")).strip().lower()
    if not em:
        return jsonify({"error": "Email is required"}), 400

    last_sent = OTP_RESEND_LAST_SENT.get(em)
    if last_sent and (datetime.utcnow() - last_sent).total_seconds() < OTP_RESEND_COOLDOWN_SECONDS:
        wait = int(OTP_RESEND_COOLDOWN_SECONDS - (datetime.utcnow() - last_sent).total_seconds())
        return jsonify({"error": f"Please wait {wait}s before requesting another code."}), 429

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email=?", (em,)).fetchone()

    # Same response whether or not the account exists, so this endpoint can't
    # be used to check which emails are registered.
    if not user or user["is_verified"]:
        conn.close()
        return jsonify({"message": "If that account needs verification, a new code was sent."}), 200

    OTP_RESEND_LAST_SENT[em] = datetime.utcnow()
    _generate_and_send_otp(conn, user)
    conn.close()
    return jsonify({"message": "If that account needs verification, a new code was sent."}), 200


@app.route("/auth/login", methods=["POST"])
def login():
    d  = request.get_json()
    em = (d.get("email","")).strip().lower()
    pw = d.get("password","")

    # ── Brute-force throttling ──────────────────────────────────────────────
    # Without this, a public deployment can be hit with unlimited password
    # guesses against any known email address. This is a simple in-memory
    # per-email lockout — not as robust as a dedicated rate-limiting service,
    # but it stops trivial automated guessing, which is the realistic threat
    # for a project like this.
    now = datetime.utcnow()

    lockout_until = LOGIN_LOCKOUTS.get(em)
    if lockout_until and now < lockout_until:
        remaining = int((lockout_until - now).total_seconds() // 60) + 1
        audit(None, em, "LOGIN_LOCKED", "Attempted login while locked out")
        return jsonify({"error": f"Too many failed login attempts. Try again in about {remaining} minute(s)."}), 429
    elif lockout_until and now >= lockout_until:
        LOGIN_LOCKOUTS.pop(em, None)
        LOGIN_ATTEMPTS.pop(em, None)

    attempts = LOGIN_ATTEMPTS.get(em, [])
    attempts = [t for t in attempts if (now - t).total_seconds() < LOGIN_WINDOW_SECONDS]

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email=? AND is_active=1",
                        (em,)).fetchone()
    conn.close()

    if not user or not check_password_hash(user["password_hash"], pw):
        attempts.append(now)
        LOGIN_ATTEMPTS[em] = attempts
        if len(attempts) >= LOGIN_MAX_ATTEMPTS:
            LOGIN_LOCKOUTS[em] = now + timedelta(seconds=LOGIN_LOCKOUT_SECONDS)
            LOGIN_ATTEMPTS.pop(em, None)
            audit(None, em, "LOGIN_LOCKED", "Too many failed attempts — locked for 1 hour")
            return jsonify({"error": "Too many failed login attempts. Try again in about 60 minutes."}), 429
        audit(None, em, "LOGIN_FAIL", "Invalid credentials")
        return jsonify({"error":"Invalid email or password"}), 401

    if not user["is_verified"]:
        return jsonify({
            "error": "Please verify your email before logging in.",
            "needs_verification": True,
            "email": em
        }), 403

    LOGIN_ATTEMPTS.pop(em, None)
    LOGIN_LOCKOUTS.pop(em, None)

    token = secrets.token_hex(32)
    TOKENS[token] = {
        "id":       user["id"],
        "username": user["username"],
        "role":     user["role"],
        "organization": user["organization"]
    }

    conn = get_db()
    conn.execute("UPDATE users SET last_login=? WHERE id=?",
                 (datetime.utcnow().isoformat(), user["id"]))
    conn.commit(); conn.close()

    audit(user["id"], user["username"], "LOGIN", "Successful login")
    return jsonify({
        "message": "Login successful",
        "token":   token,
        "user":    {"id":user["id"],"username":user["username"],
                    "email":user["email"],"role":user["role"],
                    "organization":user["organization"]}
    })


@app.route("/auth/logout", methods=["POST"])
@login_required
def logout():
    u = current_user()
    token = get_token()
    if token in TOKENS:
        del TOKENS[token]
    audit(u["id"], u["username"], "LOGOUT")
    return jsonify({"message":"Logged out"})


@app.route("/auth/me", methods=["GET"])
def me():
    token = get_token()
    if not token or token not in TOKENS:
        return jsonify({"authenticated":False}), 200
    u = TOKENS[token]
    return jsonify({
        "authenticated": True,
        "user": {"id":u["id"],"username":u["username"],"role":u["role"]}
    })

# ══════════════════════════════════════════════════════════════════════════════
# CORE ANALYSIS ROUTES
# ══════════════════════════════════════════════════════════════════════════════

def perform_scan(body, sender, subject, auth, user_id, source="manual", gmail_message_id=None,
                  provider=None, account_id=None):
    """
    Core scan pipeline: feature engineering -> ML scoring -> risk/verdict ->
    DB insert. Used by both the manual /analyze-email route and every mail
    provider's poller, so all ingestion paths always share identical
    scoring logic. Returns (response_dict, http_status).

    `provider` + `account_id` identify exactly which connected account
    (if any) this scan came from — this is what lets the quarantine
    "delete" action reconstruct the right provider instance later and
    actually remove the message from the real mailbox, not just from
    Snarelytics's own records.
    """
    # Idempotency: don't re-scan the same Gmail message twice (poller may overlap)
    if gmail_message_id:
        conn = get_db()
        existing = conn.execute(
            "SELECT scan_id FROM scans WHERE gmail_message_id=?",
            (gmail_message_id,)).fetchone()
        conn.close()
        if existing:
            return {"message": "Already scanned", "scan_id": existing["scan_id"]}, 200

    susp_urls = [u2 for u2 in extract_urls(body) if is_suspicious_url(u2)]
    features  = engineer_features(body, sender, subject, auth)

    processed = preprocess_text(f"{subject} {sender} {body}")
    X         = VECTORIZER.transform([processed])
    proba     = float(MODEL.predict_proba(X)[0][1])

    # Organization-scoped relational signal — see relational_signal.py.
    # Looked up once here so both scoring and the post-scan observation
    # write below use the exact same sender_domain/organization pair.
    conn = get_db()
    urow_for_org = conn.execute("SELECT organization FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    organization = urow_for_org["organization"] if urow_for_org else "Unassigned"
    sender_domain = relational_signal.extract_domain(sender)

    conn = get_db()
    sender_context = relational_signal.get_sender_context(conn, organization, sender_domain)
    conn.close()
    relational_delta, relational_factor = relational_signal.relational_risk_adjustment(sender_context)

    risk_score          = compute_risk(proba, features, auth)
    risk_score           = max(0, min(100, risk_score + relational_delta))
    verdict, risk_level  = score_to_verdict(risk_score)
    confidence           = round(max(proba, 1-proba)*100, 1)

    phish_kws  = [k for k in PHISHING_KWS if k in f"{subject} {sender} {body}".lower()][:8]
    safe_sigs  = [s for s in SAFE_SIGNALS  if s in body.lower()]
    factors    = get_factors(features, auth)
    if relational_factor:
        factors.append(relational_factor)
        factors.sort(key=lambda x:(0 if x["impact"]=="negative" else 1,-x["weight"]))
        factors = factors[:6]
    explanation= explain(verdict, risk_score, factors, phish_kws, susp_urls, auth)

    is_quarantined = 1 if verdict == "Phishing" else 0

    # Use a globally unique ID instead of a content+timestamp hash — the old
    # approach could produce identical scan_ids for similar content scanned
    # in quick succession (Windows clock resolution isn't always finer than
    # a few ms), and INSERT OR REPLACE would then silently overwrite the
    # earlier scan, making it disappear from reports.
    scan_id = uuid.uuid4().hex

    conn = get_db()
    conn.execute("""INSERT OR REPLACE INTO scans
        (scan_id,user_id,sender,subject,email_hash,verdict,risk_score,risk_level,
         confidence,factors,keywords,safe_signals,urls_found,
         spf_result,dkim_result,dmarc_result,explanation,is_quarantined,created_at,
         source,gmail_message_id,provider,account_id)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (scan_id, user_id, sender, subject,
         hashlib.sha256(body.encode()).hexdigest(),
         verdict, risk_score, risk_level, confidence,
         json.dumps(factors), json.dumps(phish_kws),
         json.dumps(safe_sigs), json.dumps(extract_urls(body)),
         auth["spf"], auth["dkim"], auth["dmarc"],
         explanation, is_quarantined,
         datetime.utcnow().isoformat(),
         source, gmail_message_id, provider, account_id))
    conn.commit(); conn.close()

    conn = get_db()
    relational_signal.record_observation(conn, organization, sender_domain, is_phishing=(verdict == "Phishing"))
    conn.commit(); conn.close()

    conn = get_db()
    urow = conn.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    audit(user_id, urow["username"] if urow else "unknown", "EMAIL_SCAN",
          f"verdict={verdict} score={risk_score} sender={sender} source={source}")

    return {
        "scan_id":           scan_id,
        "verdict":           verdict,
        "risk_score":        risk_score,
        "risk_level":        risk_level,
        "confidence":        confidence,
        "model_probability": round(proba*100,1),
        "factors":           factors,
        "phishing_keywords": phish_kws,
        "safe_signals":      safe_sigs,
        "suspicious_urls":   susp_urls,
        "all_urls_found":    extract_urls(body),
        "spf_result":        auth["spf"],
        "dkim_result":       auth["dkim"],
        "dmarc_result":      auth["dmarc"],
        "feature_vector":    features,
        "explanation":       explanation,
        "is_quarantined":    bool(is_quarantined),
        "is_phishing":       verdict == "Phishing"
    }, 200


@app.route("/analyze-email", methods=["POST"])
@login_required
def analyze_email():
    u = current_user()

    # Support JSON, form data, and .eml upload
    body = sender = subject = raw_headers = ""
    auth = {"spf":"none","dkim":"none","dmarc":"none"}

    if request.files.get("eml_file"):
        parsed = parse_eml(request.files["eml_file"].read())
        if not parsed["ok"]:
            return jsonify({"error":"Could not parse .eml file: "+parsed["error"]}),400
        body        = parsed["body"]
        sender      = parsed["sender"]
        subject     = parsed["subject"]
        raw_headers = parsed["raw_headers"]
        auth        = parse_auth_results(raw_headers)
    elif request.is_json:
        d           = request.get_json()
        body        = d.get("email_content","").strip()
        sender      = d.get("sender","").strip()
        subject     = d.get("subject","").strip()
        raw_headers = d.get("raw_headers","")
        auth        = parse_auth_results(raw_headers) if raw_headers else auth
    else:
        body        = request.form.get("email_content","").strip()
        sender      = request.form.get("sender","").strip()
        subject     = request.form.get("subject","").strip()

    if not body:
        return jsonify({"error":"email_content is required"}), 400

    result, status = perform_scan(body, sender, subject, auth, u["id"], source="manual")
    return jsonify(result), status


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "model_loaded": MODEL is not None,
        "timestamp": datetime.utcnow().isoformat()
    })


@app.route("/stats", methods=["GET"])
@login_required
def stats():
    conn  = get_db()
    total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    threats= conn.execute("SELECT COUNT(*) FROM scans WHERE verdict IN ('Phishing','Suspicious')").fetchone()[0]
    avg   = conn.execute("SELECT AVG(risk_score) FROM scans").fetchone()[0] or 0
    hist  = conn.execute("""SELECT verdict,risk_score,sender,subject,created_at,spf_result,dkim_result,dmarc_result
        FROM scans ORDER BY created_at DESC LIMIT 30""").fetchall()
    conn.close()
    return jsonify({
        "total_scanned":   total,
        "threats_detected":threats,
        "detection_rate":  round(threats/total*100,1) if total else 0,
        "avg_risk_score":  round(avg,1),
        "recent_scans":    [dict(r) for r in hist]
    })


@app.route("/model-info", methods=["GET"])
def model_info():
    conn = get_db()
    row  = conn.execute("SELECT * FROM model_metrics ORDER BY trained_at DESC LIMIT 1").fetchone()
    conn.close()
    return jsonify(dict(row) if row else {"message":"No metrics yet"})


@app.route("/retrain", methods=["POST"])
@admin_required
def retrain():
    global MODEL, VECTORIZER
    MODEL, VECTORIZER, metrics = build_model()
    audit(current_user()["id"], current_user()["username"],
          "MODEL_RETRAIN", f"acc={metrics['accuracy']}")
    return jsonify({"status":"retrained","metrics":metrics})

# ══════════════════════════════════════════════════════════════════════════════
# QUARANTINE MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/quarantine", methods=["GET"])
@login_required
def list_quarantine():
    user = current_user()
    conn = get_db()
    if user.get("role") == "admin":
        # Admins see everything, across every connected account — this is
        # the real-time institutional oversight view. Logged once per
        # listing call, not per row, so the audit trail stays proportional
        # to actual admin activity rather than flooding on every page load.
        rows = conn.execute("""
            SELECT s.*, u.username, u.organization FROM scans s
            LEFT JOIN users u ON s.user_id=u.id
            WHERE s.is_quarantined=1 AND s.released=0
            ORDER BY s.created_at DESC""").fetchall()
        conn.close()
        audit(user["id"], user["username"], "ADMIN_VIEW_ALL_QUARANTINE",
              f"viewed {len(rows)} quarantined item(s) across all accounts")
    else:
        # Analysts only ever see their own connected account's flagged
        # mail — never another analyst's, admin or not.
        rows = conn.execute("""
            SELECT s.*, u.username, u.organization FROM scans s
            LEFT JOIN users u ON s.user_id=u.id
            WHERE s.is_quarantined=1 AND s.released=0 AND s.user_id=?
            ORDER BY s.created_at DESC""", (user["id"],)).fetchall()
        conn.close()
    return jsonify({"quarantined":[dict(r) for r in rows]})


def _can_manage_scan(scan_row, user):
    """
    An admin can manage any quarantined item. An Analyst can only manage
    their own — this is what lets an individual manage their own inbox's
    quarantine without needing admin rights, while still keeping other
    analysts' items off-limits to non-admins in a shared deployment.
    """
    return user.get("role") == "admin" or scan_row["user_id"] == user["id"]


@app.route("/quarantine/<scan_id>/release", methods=["POST"])
@login_required
def release_quarantine(scan_id):
    user = current_user()
    conn = get_db()
    row = conn.execute("SELECT * FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Not found"}), 404
    if not _can_manage_scan(row, user):
        conn.close()
        return jsonify({"error": "You can only manage quarantine items from your own scans"}), 403

    note = (request.get_json() or {}).get("note","")
    conn.execute("UPDATE scans SET released=1,quarantine_note=? WHERE scan_id=?",
                 (note, scan_id))
    conn.commit(); conn.close()
    audit(user["id"], user["username"],
          "QUARANTINE_RELEASE", f"scan_id={scan_id}")
    return jsonify({"message":"Email released from quarantine"})


@app.route("/quarantine/<scan_id>/feedback", methods=["POST"])
@login_required
def submit_feedback(scan_id):
    """
    Lets an analyst mark a flagged email as a false positive (or confirm
    it as a true positive), independent of releasing/deleting it. This is
    the correction signal that would feed a future retraining pass — right
    now it's captured and visible, not yet wired into automatic retraining.
    Kept separate from release/delete so feedback and quarantine actions
    can happen independently (e.g. leave something quarantined but still
    flag it as a wrong call for the record).
    """
    user = current_user()
    verdict = (request.get_json() or {}).get("verdict", "")
    if verdict not in ("false_positive", "true_positive"):
        return jsonify({"error": "verdict must be 'false_positive' or 'true_positive'"}), 400

    conn = get_db()
    row = conn.execute("SELECT * FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Not found"}), 404
    if not _can_manage_scan(row, user):
        conn.close()
        return jsonify({"error": "You can only give feedback on your own scans"}), 403

    conn.execute(
        "UPDATE scans SET analyst_feedback=?, feedback_by=?, feedback_at=? WHERE scan_id=?",
        (verdict, user["username"], datetime.utcnow().isoformat(), scan_id))
    conn.commit(); conn.close()
    audit(user["id"], user["username"], "SCAN_FEEDBACK",
          f"scan_id={scan_id} verdict={verdict}")
    return jsonify({"message": "Feedback recorded"})


@app.route("/quarantine/<scan_id>/delete", methods=["DELETE"])
@login_required
def delete_quarantine(scan_id):
    user = current_user()
    conn = get_db()
    row = conn.execute("SELECT * FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Not found"}), 404
    if not _can_manage_scan(row, user):
        return jsonify({"error": "You can only manage quarantine items from your own scans"}), 403

    mailbox_result = "not applicable (manual scan — no connected account to delete from)"

    # If this scan came from a connected mail account (not a manual paste-in
    # scan), also remove the actual message from that mailbox — otherwise
    # deleting here would only clear Snarelytics's own record while the real
    # email keeps sitting in the account's Quarantine folder/label forever.
    if row["provider"] and row["account_id"] and row["gmail_message_id"]:
        try:
            from providers import REGISTRY
            table_name, provider_class = REGISTRY[row["provider"]]

            conn = get_db()
            account_row = conn.execute(
                f"SELECT * FROM {table_name} WHERE id=?", (row["account_id"],)).fetchone()
            conn.close()

            if not account_row:
                mailbox_result = "skipped — the connected account no longer exists (may have been disconnected)"
            else:
                provider = provider_class(account_row, get_db)
                provider.ensure_fresh_credentials()
                provider.delete_message(row["gmail_message_id"])
                mailbox_result = "deleted from the mailbox"
        except Exception as e:
            # Don't block the local delete on a mailbox-side failure (e.g.
            # revoked credentials) — but be honest in the response that the
            # real email may still be sitting in the account's Quarantine
            # folder, rather than silently claiming full success.
            mailbox_result = f"FAILED to delete from mailbox ({e}) — it may still be in the account's Quarantine folder"
            log.error(f"Mailbox delete failed for scan {scan_id}: {e}")

    conn = get_db()
    conn.execute("DELETE FROM scans WHERE scan_id=?", (scan_id,))
    conn.commit(); conn.close()
    audit(current_user()["id"], current_user()["username"],
          "QUARANTINE_DELETE", f"scan_id={scan_id} mailbox_result={mailbox_result}")
    return jsonify({"message": "Email deleted from Snarelytics", "mailbox_result": mailbox_result})


@app.route("/quarantine/<scan_id>", methods=["GET"])
@login_required
def get_quarantine_item(scan_id):
    user = current_user()
    conn = get_db()
    row  = conn.execute("SELECT * FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
    conn.close()
    if not row: return jsonify({"error":"Not found"}),404
    if not _can_manage_scan(row, user):
        return jsonify({"error": "You can only view scan items from your own connected accounts"}), 403
    # An admin opening a specific item that belongs to someone else is
    # exactly the "admin sees analyst activity" case the audit trail exists
    # for — log it. Viewing your own item (analyst or admin) isn't logged
    # here to keep the trail focused on cross-account visibility.
    if user.get("role") == "admin" and row["user_id"] != user["id"]:
        audit(user["id"], user["username"], "ADMIN_VIEW_ANALYST_ITEM",
              f"scan_id={scan_id} owner_user_id={row['user_id']}")
    return jsonify(dict(row))

# ══════════════════════════════════════════════════════════════════════════════
# USER MANAGEMENT (Admin only)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/users", methods=["GET"])
@admin_required
def list_users():
    conn  = get_db()
    users = conn.execute(
        "SELECT id,username,email,role,organization,created_at,last_login,is_active FROM users").fetchall()
    conn.close()
    return jsonify({"users":[dict(u) for u in users]})


@app.route("/organizations/summary", methods=["GET"])
@admin_required
def organizations_summary():
    """
    Per-institution rollup for the admin dashboard — the actual multi-
    tenant oversight view: how many analysts and connected mail accounts
    each institution has, and how many threats have been caught for them,
    instead of one flat account list with no institutional grouping.
    """
    conn = get_db()
    orgs = conn.execute("""
        SELECT u.organization AS organization,
               COUNT(DISTINCT u.id) AS analyst_count,
               COUNT(DISTINCT g.id) AS gmail_accounts,
               COUNT(DISTINCT o.id) AS outlook_accounts,
               COUNT(DISTINCT i.id) AS imap_accounts,
               COUNT(DISTINCT CASE WHEN s.is_phishing_int=1 THEN s.id END) AS threats_caught
        FROM users u
        LEFT JOIN gmail_accounts   g ON g.user_id=u.id AND g.is_active=1
        LEFT JOIN outlook_accounts o ON o.user_id=u.id AND o.is_active=1
        LEFT JOIN imap_accounts    i ON i.user_id=u.id AND i.is_active=1
        LEFT JOIN (SELECT id, user_id, CASE WHEN verdict='Phishing' THEN 1 ELSE 0 END AS is_phishing_int
                    FROM scans) s ON s.user_id=u.id
        GROUP BY u.organization
        ORDER BY analyst_count DESC
    """).fetchall()
    conn.close()
    return jsonify({"organizations": [dict(r) for r in orgs]})


@app.route("/users/<int:uid>/role", methods=["PUT"])
@admin_required
def update_role(uid):
    role = (request.get_json() or {}).get("role","analyst")
    if role not in ("admin","analyst"):
        return jsonify({"error":"Invalid role"}),400
    conn = get_db()
    conn.execute("UPDATE users SET role=? WHERE id=?", (role,uid))
    conn.commit(); conn.close()
    audit(current_user()["id"], current_user()["username"],
          "USER_ROLE_UPDATE", f"uid={uid} new_role={role}")
    return jsonify({"message":"Role updated"})


@app.route("/users/<int:uid>/deactivate", methods=["PUT"])
@admin_required
def deactivate_user(uid):
    conn = get_db()
    conn.execute("UPDATE users SET is_active=0 WHERE id=?", (uid,))
    conn.commit(); conn.close()
    audit(current_user()["id"], current_user()["username"],
          "USER_DEACTIVATE", f"uid={uid}")
    return jsonify({"message":"User deactivated"})

# ══════════════════════════════════════════════════════════════════════════════
# AUDIT LOG
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/audit-log", methods=["GET"])
@admin_required
def get_audit_log():
    limit  = int(request.args.get("limit", 100))
    offset = int(request.args.get("offset", 0))
    conn   = get_db()
    rows   = conn.execute("""SELECT * FROM audit_log
        ORDER BY created_at DESC LIMIT ? OFFSET ?""", (limit,offset)).fetchall()
    total  = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    conn.close()
    return jsonify({"logs":[dict(r) for r in rows],"total":total})

# ══════════════════════════════════════════════════════════════════════════════
# REPORTS — PDF & EXCEL
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/report/pdf", methods=["GET"])
@login_required
def report_pdf():
    if not PDF_AVAILABLE:
        return jsonify({"error":"reportlab not installed. Run: pip install reportlab"}),503

    conn   = get_db()
    scans  = conn.execute("SELECT * FROM scans ORDER BY created_at DESC").fetchall()
    total  = len(scans)
    phish  = sum(1 for s in scans if s["verdict"]=="Phishing")
    susp   = sum(1 for s in scans if s["verdict"]=="Suspicious")
    safe   = sum(1 for s in scans if s["verdict"]=="Safe")
    avg_rs = round(sum(s["risk_score"] for s in scans)/total,1) if total else 0
    conn.close()

    path = os.path.join(REPORT_DIR, f"phishguard_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf")
    doc  = SimpleDocTemplate(path, pagesize=A4)
    styles = getSampleStyleSheet()
    story  = []

    story.append(Paragraph("Snarelytics — Security Report", styles["Title"]))
    story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]))
    story.append(Spacer(1,12))

    story.append(Paragraph("Summary Statistics", styles["Heading2"]))
    summary = [
        ["Metric","Value"],
        ["Total Emails Scanned", str(total)],
        ["Phishing Detected",    str(phish)],
        ["Suspicious Flagged",   str(susp)],
        ["Safe Emails",          str(safe)],
        ["Average Risk Score",   str(avg_rs)],
        ["Detection Rate",       f"{round(phish/total*100,1) if total else 0}%"],
    ]
    t = Table(summary, colWidths=[200,200])
    t.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#1A3A5C")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("GRID",(0,0),(-1,-1),0.5,colors.grey),
        ("BACKGROUND",(0,1),(-1,-1),colors.HexColor("#f5f5f5")),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f0f4ff")]),
    ]))
    story.append(t)
    story.append(Spacer(1,20))

    story.append(Paragraph("Recent Scan History (Last 20)", styles["Heading2"]))
    data = [["Sender","Subject","Verdict","Score","Date"]]
    for s in list(scans)[:20]:
        data.append([
            (s["sender"] or "")[:30],
            (s["subject"] or "")[:30],
            s["verdict"] or "",
            str(s["risk_score"]),
            (s["created_at"] or "")[:10]
        ])
    t2 = Table(data, colWidths=[120,130,70,45,80])
    t2.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#1A3A5C")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("FONTSIZE",(0,0),(-1,-1),8),
        ("GRID",(0,0),(-1,-1),0.3,colors.grey),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#fff8f0")]),
    ]))
    story.append(t2)

    doc.build(story)
    audit(current_user()["id"], current_user()["username"], "REPORT_PDF")
    return send_file(path, as_attachment=True,
                     download_name="Snarelytics_Report.pdf",
                     mimetype="application/pdf")


@app.route("/report/excel", methods=["GET"])
@login_required
def report_excel():
    if not EXCEL_AVAILABLE:
        return jsonify({"error":"openpyxl not installed. Run: pip install openpyxl"}),503

    conn  = get_db()
    scans = conn.execute("SELECT * FROM scans ORDER BY created_at DESC").fetchall()
    conn.close()

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Scan History"

    from openpyxl.styles import Font, PatternFill, Alignment
    header_fill = PatternFill("solid", fgColor="1A3A5C")
    header_font = Font(color="FFFFFF", bold=True)

    headers = ["Scan ID","Sender","Subject","Verdict","Risk Score",
               "Risk Level","Confidence","SPF","DKIM","DMARC",
               "Quarantined","Date"]
    for col, h in enumerate(headers,1):
        cell = ws.cell(row=1, column=col, value=h)
        cell.fill = header_fill
        cell.font = header_font

    for row_idx, s in enumerate(scans, 2):
        ws.cell(row=row_idx, column=1,  value=(s["scan_id"] or "")[:16])
        ws.cell(row=row_idx, column=2,  value=s["sender"] or "")
        ws.cell(row=row_idx, column=3,  value=s["subject"] or "")
        ws.cell(row=row_idx, column=4,  value=s["verdict"] or "")
        ws.cell(row=row_idx, column=5,  value=s["risk_score"])
        ws.cell(row=row_idx, column=6,  value=s["risk_level"] or "")
        ws.cell(row=row_idx, column=7,  value=s["confidence"])
        ws.cell(row=row_idx, column=8,  value=s["spf_result"] or "")
        ws.cell(row=row_idx, column=9,  value=s["dkim_result"] or "")
        ws.cell(row=row_idx, column=10, value=s["dmarc_result"] or "")
        ws.cell(row=row_idx, column=11, value="Yes" if s["is_quarantined"] else "No")
        ws.cell(row=row_idx, column=12, value=(s["created_at"] or "")[:10])

    path = os.path.join(REPORT_DIR, f"phishguard_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xlsx")
    wb.save(path)
    audit(current_user()["id"], current_user()["username"], "REPORT_EXCEL")
    return send_file(path, as_attachment=True,
                     download_name="Snarelytics_Report.xlsx",
                     mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

# ══════════════════════════════════════════════════════════════════════════════
# STARTUP
# ══════════════════════════════════════════════════════════════════════════════
MODEL, VECTORIZER = None, None

if __name__ == "__main__":
    init_db()
    MODEL, VECTORIZER = load_model()

    # ── Multi-provider email integration (OAuth routes) ────────────────────
    # Each provider's OAuth connect/callback/status/disconnect routes are
    # registered only if that provider's credentials file is present.
    # Polling itself (below) is independent of this — it always runs and
    # simply does nothing for a provider with zero connected accounts.
    any_provider_configured = False

    # --- Gmail ---
    client_secrets_path = os.environ.get("GOOGLE_CLIENT_SECRETS", DEFAULT_GOOGLE_CLIENT_SECRETS)
    if not os.path.exists(client_secrets_path):
        log.warning("client_secret.json not found — Gmail integration disabled. "
                    "See SETUP_GMAIL.md to enable it.")
        _GMAIL_NOT_CONFIGURED_MSG = (
            "Gmail integration is not set up on this server yet. "
            "See SETUP_GMAIL.md — you need a client_secret.json from "
            "Google Cloud Console in the backend/ folder, then restart the app."
        )

        @app.route("/auth/gmail/connect", methods=["GET"])
        def gmail_connect_not_configured():
            return jsonify({"error": _GMAIL_NOT_CONFIGURED_MSG}), 501

        @app.route("/auth/gmail/status", methods=["GET"])
        def gmail_status_not_configured():
            return jsonify({"error": _GMAIL_NOT_CONFIGURED_MSG, "accounts": []}), 501

        @app.route("/auth/gmail/disconnect/<int:account_id>", methods=["DELETE"])
        def gmail_disconnect_not_configured(account_id):
            return jsonify({"error": _GMAIL_NOT_CONFIGURED_MSG}), 501
    else:
        try:
            from gmail_integration import register_gmail_routes
            register_gmail_routes(app, get_token, get_db, audit, TOKENS, perform_scan)
            log.info("Gmail integration enabled")
            any_provider_configured = True
        except ImportError as e:
            log.warning(f"Gmail integration dependencies missing ({e}). "
                        f"Run: pip install -r requirements.txt")

    # --- Outlook / Microsoft 365 ---
    outlook_secrets_path = os.environ.get("OUTLOOK_SECRETS_FILE", DEFAULT_OUTLOOK_SECRETS_FILE)
    if not os.path.exists(outlook_secrets_path):
        log.warning("outlook_secret.json not found — Outlook integration disabled. "
                    "See SETUP_OUTLOOK.md to enable it.")
        _OUTLOOK_NOT_CONFIGURED_MSG = (
            "Outlook integration is not set up on this server yet. "
            "See SETUP_OUTLOOK.md — you need an outlook_secret.json from "
            "the Azure Portal in the backend/ folder, then restart the app."
        )

        @app.route("/auth/outlook/connect", methods=["GET"])
        def outlook_connect_not_configured():
            return jsonify({"error": _OUTLOOK_NOT_CONFIGURED_MSG}), 501

        @app.route("/auth/outlook/status", methods=["GET"])
        def outlook_status_not_configured():
            return jsonify({"error": _OUTLOOK_NOT_CONFIGURED_MSG, "accounts": []}), 501

        @app.route("/auth/outlook/disconnect/<int:account_id>", methods=["DELETE"])
        def outlook_disconnect_not_configured(account_id):
            return jsonify({"error": _OUTLOOK_NOT_CONFIGURED_MSG}), 501
    else:
        try:
            from outlook_integration import register_outlook_routes
            register_outlook_routes(app, get_token, get_db, audit, TOKENS, perform_scan)
            log.info("Outlook integration enabled")
            any_provider_configured = True
        except ImportError as e:
            log.warning(f"Outlook integration dependencies missing ({e}). "
                        f"Run: pip install -r requirements.txt")

    # --- IMAP (Yahoo and other IMAP-only providers) ---
    # No credentials file needed here — unlike Gmail/Outlook, this isn't
    # an OAuth app registration, so it's always available.
    try:
        from imap_integration import register_imap_routes
        register_imap_routes(app, get_token, get_db, audit, TOKENS, perform_scan)
        log.info("IMAP integration enabled (Yahoo and other IMAP providers)")
        any_provider_configured = True
    except ImportError as e:
        log.warning(f"IMAP integration dependencies missing ({e}).")

    # --- One-click "Sign in with Google / Microsoft" ────────────────────────
    # Independent of the mailbox-connect integrations above, but reuses the
    # same credential files — registers Google/Microsoft login only for
    # whichever ones are actually configured on this deployment.
    try:
        from social_login import register_social_login_routes
        register_social_login_routes(app, get_db, audit, TOKENS)
    except ImportError as e:
        log.warning(f"Social login dependencies missing ({e}).")

    # ── One shared poller for every configured provider ─────────────────────
    # Runs regardless of which providers are configured — a provider with
    # no connected accounts is simply a no-op each cycle, so there's no
    # need to conditionally start/skip this based on what's set up above.
    if any_provider_configured:
        import poller
        from apscheduler.schedulers.background import BackgroundScheduler

        def _poll_tick():
            poller.poll_all_accounts(get_db, perform_scan, parse_auth_results)

        POLL_INTERVAL_SECONDS = int(os.environ.get("MAIL_POLL_INTERVAL", "90"))
        scheduler = BackgroundScheduler()
        scheduler.add_job(_poll_tick, "interval", seconds=POLL_INTERVAL_SECONDS, id="mail_poll")
        scheduler.start()
        log.info(f"Mail polling active every {POLL_INTERVAL_SECONDS}s")

        # ── IMAP IDLE (push-based detection, Approach B) ────────────────────
        # Opt-out via IMAP_IDLE_ENABLED=0 if you'd rather run polling-only —
        # e.g. very low free-tier RAM where extra persistent connections per
        # mailbox are a real constraint. Off by default costs nothing: the
        # 90s poller above is unconditional and fully covers every IMAP
        # account on its own either way.
        if os.environ.get("IMAP_IDLE_ENABLED", "1") == "1":
            try:
                import idle_watcher
                idle_watcher.start_all_watchers(get_db, perform_scan, parse_auth_results)
                log.info("IMAP IDLE watchers started (push-based detection for IMAP accounts)")
            except Exception as e:
                log.warning(f"IMAP IDLE watchers failed to start ({e}) — "
                             f"90s polling still covers IMAP accounts normally")

        # ── Gmail Pub/Sub + Microsoft Graph push notifications ──────────────
        # Both need a real, publicly reachable HTTPS URL for the provider to
        # call back into (a webhook), plus provider-side setup only the
        # deploying institution can do (a GCP Pub/Sub topic; an Azure app
        # registration) — see SETUP_PUSH.md. Feature-flagged and entirely
        # optional: unset, both stay silent and the 90s poller alone
        # continues covering Gmail and Outlook accounts, exactly as before.
        if os.environ.get("GMAIL_PUBSUB_TOPIC"):
            try:
                from push_notifications import register_push_routes, renew_gmail_watches_job
                register_push_routes(app, get_db, perform_scan, parse_auth_results, audit)
                scheduler.add_job(renew_gmail_watches_job, "interval", hours=24,
                                   id="gmail_watch_renewal", args=[get_db])
                log.info("Gmail push notifications enabled (Pub/Sub)")
            except Exception as e:
                log.warning(f"Gmail push notifications failed to start ({e}) — "
                             f"falling back to 90s polling only for Gmail")

        if os.environ.get("OUTLOOK_WEBHOOK_ENABLED") == "1":
            try:
                from push_notifications import register_outlook_push_routes, renew_outlook_subscriptions_job
                register_outlook_push_routes(app, get_db, perform_scan, parse_auth_results, audit)
                scheduler.add_job(renew_outlook_subscriptions_job, "interval", hours=12,
                                   id="outlook_subscription_renewal", args=[get_db])
                log.info("Outlook push notifications enabled (Graph change notifications)")
            except Exception as e:
                log.warning(f"Outlook push notifications failed to start ({e}) — "
                             f"falling back to 90s polling only for Outlook")

    # ── Host/port binding ────────────────────────────────────────────────────
    # Local desktop use (the .exe / Electron build) and a hosted deployment
    # (Render, etc.) need different binding:
    #   - Local: bind to 127.0.0.1 only (loopback — unreachable from any other
    #     device, even on the same network). Safe default for a machine
    #     running the app for just its own user.
    #   - Hosted (RENDER=1 or PORT is set by the platform): must bind to
    #     0.0.0.0 so the platform's router can reach it, and to the PORT the
    #     platform assigns rather than a hardcoded 5000.
    IS_HOSTED = bool(os.environ.get("RENDER")) or bool(os.environ.get("PORT"))
    HOST = "0.0.0.0" if IS_HOSTED else "127.0.0.1"
    PORT = int(os.environ.get("PORT", 5000))

    log.info(f"Snarelytics started → http://{HOST}:{PORT}")

    # ── Server hardening ────────────────────────────────────────────────────
    # The previous default here — app.run(debug=True, host="0.0.0.0") — is a
    # real security risk if left running for extended periods: debug mode
    # exposes Werkzeug's interactive debugger, which allows arbitrary code
    # execution to anything that can reach it, and 0.0.0.0 makes the server
    # reachable from anyone who can reach it, not just this machine.
    #
    # Production default: serve via waitress, a proper WSGI server, instead
    # of Flask's development server.
    #
    # Opt-in dev mode (hot reload + debugger) is still available for active
    # local development by setting PHISHGUARD_DEV=1 before running — never
    # leave this on for a hosted deployment.
    if os.environ.get("PHISHGUARD_DEV") == "1":
        log.warning("Running in DEV mode (debugger enabled) — do not leave this running unattended.")
        app.run(debug=True, host=HOST, port=PORT)
    else:
        from waitress import serve
        serve(app, host=HOST, port=PORT)
