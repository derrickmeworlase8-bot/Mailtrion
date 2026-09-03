"""
Mailtrion — social sign-in (Google / Microsoft)

Deliberately separate from gmail_integration.py / outlook_integration.py.
Those handle "an already-logged-in user connects a mailbox for scanning"
(broad Mail.ReadWrite-style scopes, requires an existing Mailtrion
session). This handles "prove who you are to create/access your
Mailtrion account" — only identity scopes (email/profile), and it runs
BEFORE any Mailtrion session exists, since its whole purpose is to
create one.

Reuses the same Google Cloud / Azure app registrations as the mailbox
integrations (same client_secret.json / outlook_secret.json) — but needs
its OWN redirect URIs added in each console, since these are different
callback routes:

    Google Cloud Console → Credentials → your OAuth client → Authorized
    redirect URIs → add:  https://YOUR-DOMAIN/auth/google/login/callback

    Azure Portal → App registrations → your app → Authentication → add:
    https://YOUR-DOMAIN/auth/microsoft/login/callback

A user who signs in this way never sets a Mailtrion password — their
password_hash is a random, never-shown, never-usable value. They always
come back in through the same provider button. If they later try to
register that email manually, the normal "account already exists, sign
in instead" flow handles it — they'd just click the provider button again
rather than a password they never had.
"""

import os
import re
import time
import logging
import secrets as pysecrets
from datetime import datetime

from flask import request, redirect

log = logging.getLogger(__name__)

# google-auth-oauthlib's default behaviour is to raise if the scopes Google
# actually grants don't exactly match what was requested — which happens
# routinely and harmlessly (Google may return scopes in a different order,
# or bundle "openid" slightly differently) and would otherwise surface as
# exactly the generic "Google sign-in failed" symptom with no clue why.
# This is the standard, documented way to relax that check.
os.environ.setdefault("OAUTHLIB_RELAX_TOKEN_SCOPE", "1")

GOOGLE_LOGIN_REDIRECT_URI = os.environ.get(
    "GOOGLE_LOGIN_REDIRECT_URI", "http://localhost:5000/auth/google/login/callback")
MICROSOFT_LOGIN_REDIRECT_URI = os.environ.get(
    "MICROSOFT_LOGIN_REDIRECT_URI", "http://localhost:5000/auth/microsoft/login/callback")

GOOGLE_LOGIN_SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]
MICROSOFT_LOGIN_SCOPES = ["User.Read"]

# state -> expiry timestamp, just to bound how long a pending login attempt
# is considered valid (CSRF protection for the OAuth redirect round-trip).
_PENDING_STATES = {}
_STATE_TTL_SECONDS = 600


def _new_state():
    state = pysecrets.token_urlsafe(24)
    _PENDING_STATES[state] = time.time() + _STATE_TTL_SECONDS
    return state


def _consume_state(state):
    expiry = _PENDING_STATES.pop(state, None)
    return expiry is not None and time.time() < expiry


def _unique_username(conn, base):
    base = re.sub(r"[^a-zA-Z0-9_]", "", base) or "user"
    candidate = base
    n = 1
    while conn.execute("SELECT 1 FROM users WHERE username=?", (candidate,)).fetchone():
        n += 1
        candidate = f"{base}{n}"
    return candidate


def _find_or_create_social_user(conn, get_db, audit, email, display_name):
    email = email.strip().lower()
    user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

    if user:
        if not user["is_verified"]:
            # The provider already proved this person owns the mailbox —
            # that's strictly stronger proof than our own OTP step, so
            # there's no reason to still require it.
            conn.execute("UPDATE users SET is_verified=1 WHERE id=?", (user["id"],))
            conn.commit()
        conn.execute("UPDATE users SET last_login=? WHERE id=?",
                     (datetime.utcnow().isoformat(), user["id"]))
        conn.commit()
        return conn.execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()

    from werkzeug.security import generate_password_hash
    username = _unique_username(conn, display_name or email.split("@")[0])
    unusable_password = generate_password_hash(pysecrets.token_urlsafe(32))
    conn.execute("""INSERT INTO users
        (username,email,password_hash,role,created_at,last_login,is_verified)
        VALUES (?,?,?,?,?,?,1)""",
        (username, email, unusable_password, "analyst",
         datetime.utcnow().isoformat(), datetime.utcnow().isoformat()))
    conn.commit()
    new_user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    audit(new_user["id"], username, "REGISTER_SOCIAL", f"Account created via social sign-in: {email}")
    return new_user


def register_social_login_routes(app, get_db, audit, TOKENS):
    """Call once from app.py. Registers Google and/or Microsoft login
    routes depending on which credential files are available — same
    availability check the mailbox integrations already use, so if Gmail/
    Outlook connect works on this deployment, sign-in-with will too."""

    # ── Google ───────────────────────────────────────────────────────────
    try:
        from providers.gmail_provider import CLIENT_SECRETS_FILE, _load_client_config
        import os as _os
        if _os.path.exists(CLIENT_SECRETS_FILE) or _os.environ.get("GOOGLE_CLIENT_SECRETS_JSON"):
            from google_auth_oauthlib.flow import Flow

            def _google_flow(state=None):
                return Flow.from_client_config(
                    _load_client_config(), scopes=GOOGLE_LOGIN_SCOPES,
                    redirect_uri=GOOGLE_LOGIN_REDIRECT_URI, state=state
                )

            @app.route("/auth/google/login", methods=["GET"])
            def google_login():
                state = _new_state()
                flow = _google_flow()
                auth_url, _ = flow.authorization_url(
                    access_type="online", include_granted_scopes="true",
                    prompt="select_account", state=state
                )
                return redirect(auth_url)

            @app.route("/auth/google/login/callback", methods=["GET"])
            def google_login_callback():
                state = request.args.get("state")
                if not _consume_state(state):
                    return redirect("/?social_login_error=Session+expired,+please+try+again")

                try:
                    flow = _google_flow(state=state)
                    flow.fetch_token(authorization_response=request.url)
                    creds = flow.credentials

                    import requests as _requests
                    resp = _requests.get(
                        "https://www.googleapis.com/oauth2/v3/userinfo",
                        headers={"Authorization": f"Bearer {creds.token}"}, timeout=10
                    )
                    resp.raise_for_status()
                    info = resp.json()
                    email = info.get("email")
                    name = info.get("given_name") or info.get("name") or ""
                    if not email:
                        return redirect("/?social_login_error=Could+not+get+your+email+from+Google")

                    conn = get_db()
                    user = _find_or_create_social_user(conn, get_db, audit, email, name)
                    conn.close()

                    token = pysecrets.token_hex(32)
                    TOKENS[token] = {"id": user["id"], "username": user["username"], "role": user["role"],
                                      "organization": user["organization"]}
                    return redirect(f"/?social_login_token={token}&social_provider=google")
                except Exception as e:
                    log.error(f"[google-login] callback failed: {e!r}", exc_info=True)
                    return redirect(f"/?social_login_error=Google+sign-in+failed")

            app.logger.info("Google one-click sign-in enabled")
    except ImportError:
        pass

    # ── Microsoft ────────────────────────────────────────────────────────
    try:
        from providers.outlook_provider import OUTLOOK_SECRETS_FILE, build_msal_app, GRAPH_BASE
        import os as _os
        if _os.path.exists(OUTLOOK_SECRETS_FILE) or _os.environ.get("OUTLOOK_SECRETS_JSON"):
            import requests as _requests

            @app.route("/auth/microsoft/login", methods=["GET"])
            def microsoft_login():
                state = _new_state()
                msal_app = build_msal_app()
                auth_url = msal_app.get_authorization_request_url(
                    scopes=MICROSOFT_LOGIN_SCOPES, redirect_uri=MICROSOFT_LOGIN_REDIRECT_URI,
                    prompt="select_account", state=state
                )
                return redirect(auth_url)

            @app.route("/auth/microsoft/login/callback", methods=["GET"])
            def microsoft_login_callback():
                state = request.args.get("state")
                code = request.args.get("code")
                if not _consume_state(state):
                    return redirect("/?social_login_error=Session+expired,+please+try+again")
                if not code:
                    return redirect("/?social_login_error=Microsoft+sign-in+was+cancelled")

                try:
                    msal_app = build_msal_app()
                    result = msal_app.acquire_token_by_authorization_code(
                        code, scopes=MICROSOFT_LOGIN_SCOPES, redirect_uri=MICROSOFT_LOGIN_REDIRECT_URI
                    )
                    if "access_token" not in result:
                        return redirect("/?social_login_error=Microsoft+sign-in+failed")

                    me = _requests.get(f"{GRAPH_BASE}/me",
                                       headers={"Authorization": f"Bearer {result['access_token']}"}, timeout=10)
                    me.raise_for_status()
                    me_json = me.json()
                    email = me_json.get("mail") or me_json.get("userPrincipalName")
                    name = me_json.get("givenName") or me_json.get("displayName") or ""
                    if not email:
                        return redirect("/?social_login_error=Could+not+get+your+email+from+Microsoft")

                    conn = get_db()
                    user = _find_or_create_social_user(conn, get_db, audit, email, name)
                    conn.close()

                    token = pysecrets.token_hex(32)
                    TOKENS[token] = {"id": user["id"], "username": user["username"], "role": user["role"],
                                      "organization": user["organization"]}
                    return redirect(f"/?social_login_token={token}&social_provider=microsoft")
                except Exception as e:
                    log.error(f"[microsoft-login] callback failed: {e!r}", exc_info=True)
                    return redirect("/?social_login_error=Microsoft+sign-in+failed")

            app.logger.info("Microsoft one-click sign-in enabled")
    except ImportError:
        pass
