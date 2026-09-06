"""
Mailtrion — social sign-in (Google / Microsoft / Yahoo)

Deliberately separate from gmail_integration.py / outlook_integration.py.
Those handle "an already-logged-in user connects a mailbox for scanning"
(broad Mail.ReadWrite-style scopes, requires an existing Mailtrion
session). This handles "prove who you are to create/access your
Mailtrion account" — only identity scopes (email/profile), and it runs
BEFORE any Mailtrion session exists, since its whole purpose is to
create one.

Google and Microsoft reuse the same Cloud/Azure app registrations as the
mailbox integrations (same client_secret.json / outlook_secret.json) —
but need their OWN redirect URIs added in each console, since these are
different callback routes:

    Google Cloud Console → Credentials → your OAuth client → Authorized
    redirect URIs → add:  https://YOUR-DOMAIN/auth/google/login/callback

    Azure Portal → App registrations → your app → Authentication → add:
    https://YOUR-DOMAIN/auth/microsoft/login/callback

Yahoo has its own, separate app registration (Yahoo Developer Network —
developer.yahoo.com), since it isn't used by the mailbox-connect side at
all (Yahoo mailboxes are connected via IMAP app password instead — see
imap_integration.py — because Yahoo's mail scope requires a separate
restricted-scope approval Yahoo grants case-by-case). Set:

    YAHOO_CLIENT_ID, YAHOO_CLIENT_SECRET  (from a YDN app)
    YAHOO_LOGIN_REDIRECT_URI = https://YOUR-DOMAIN/auth/yahoo/login/callback

    Yahoo Developer Network → your app → Redirect URI(s) → add the same
    https://YOUR-DOMAIN/auth/yahoo/login/callback

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
YAHOO_LOGIN_REDIRECT_URI = os.environ.get(
    "YAHOO_LOGIN_REDIRECT_URI", "http://localhost:5000/auth/yahoo/login/callback")

GOOGLE_LOGIN_SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]
MICROSOFT_LOGIN_SCOPES = ["User.Read"]
YAHOO_LOGIN_SCOPES = "openid email"
# "openid profile email" together triggered Yahoo's invalid_scope error;
# "openid" alone got through consent but didn't return an email claim.
# "profile" specifically is the more likely culprit of the two extra
# scopes (Yahoo's scope names don't necessarily match Google/Microsoft's
# despite looking identical) — this targets just what's actually needed
# (an email address) without the name/profile scope that may be the
# actual invalid one.

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

    # ── Yahoo ────────────────────────────────────────────────────────────
    # Yahoo has no Python SDK equivalent to google-auth-oauthlib/msal, so
    # this talks to its OAuth 2.0 / OpenID Connect endpoints directly with
    # `requests`. Credentials come from Yahoo Developer Network (YDN) —
    # separate from the IMAP app-password flow in imap_integration.py,
    # which remains how Yahoo *mailboxes* get connected for scanning:
    # Yahoo's mail scope is a restricted scope requiring separate approval
    # from Yahoo, so sign-in (identity only) and mailbox access stay on
    # two different paths, same as the Gmail/Outlook split described
    # at the top of this file.
    # .strip() matters here specifically: copy-pasting a credential from a
    # web page into Render's environment variable UI can silently pick up
    # a trailing newline or space along with the visible text. That
    # invisible character changes the value Yahoo receives without
    # changing anything visible in any screenshot of it — exactly the
    # failure mode that produced Yahoo's "invalid client id" error here.
    yahoo_client_id = (os.environ.get("YAHOO_CLIENT_ID") or "").strip()
    yahoo_client_secret = (os.environ.get("YAHOO_CLIENT_SECRET") or "").strip()
    if yahoo_client_id and yahoo_client_secret:
        import requests as _requests
        import base64 as _base64
        import json as _json

        def _decode_id_token_claims(id_token):
            """Decodes the middle (payload) segment of a JWT without
            verifying its signature. Safe here specifically because this
            id_token comes straight from Yahoo's token endpoint over TLS
            in a direct server-to-server call this function itself just
            made — it was never passed through the browser or any
            untrusted party — so there's nothing to forge in transit."""
            payload_b64 = id_token.split(".")[1]
            padded = payload_b64 + "=" * (-len(payload_b64) % 4)
            return _json.loads(_base64.urlsafe_b64decode(padded))

        @app.route("/auth/yahoo/login", methods=["GET"])
        def yahoo_login():
            state = _new_state()
            from urllib.parse import urlencode
            params = {
                "client_id": yahoo_client_id,
                "redirect_uri": YAHOO_LOGIN_REDIRECT_URI,
                "response_type": "code",
                "scope": YAHOO_LOGIN_SCOPES,
                "state": state,
                "nonce": pysecrets.token_urlsafe(16),
            }
            return redirect("https://api.login.yahoo.com/oauth2/request_auth?" + urlencode(params))

        @app.route("/auth/yahoo/login/callback", methods=["GET"])
        def yahoo_login_callback():
            state = request.args.get("state")
            code = request.args.get("code")
            if not _consume_state(state):
                return redirect("/?social_login_error=Session+expired,+please+try+again")
            if not code:
                # Log whatever Yahoo actually sent instead of guessing —
                # "cancelled" was a generic label this route used to apply
                # any time `code` was missing, whether or not the user
                # actually cancelled anything. Yahoo puts a real reason in
                # `error`/`error_description` when it redirects back
                # without a code for its own reasons (misconfigured scope,
                # app in a restricted review state, etc.).
                yahoo_error = request.args.get("error")
                yahoo_error_desc = request.args.get("error_description")
                log.error(f"[yahoo-login] callback missing code — "
                          f"error={yahoo_error!r} error_description={yahoo_error_desc!r} "
                          f"full_args={dict(request.args)!r}")
                if yahoo_error:
                    return redirect(f"/?social_login_error=Yahoo:+{yahoo_error_desc or yahoo_error}")
                return redirect("/?social_login_error=Yahoo+sign-in+was+cancelled")

            try:
                basic = _base64.b64encode(f"{yahoo_client_id}:{yahoo_client_secret}".encode()).decode()
                token_resp = _requests.post(
                    "https://api.login.yahoo.com/oauth2/get_token",
                    headers={"Authorization": f"Basic {basic}",
                             "Content-Type": "application/x-www-form-urlencoded"},
                    data={"grant_type": "authorization_code", "code": code,
                          "redirect_uri": YAHOO_LOGIN_REDIRECT_URI},
                    timeout=10,
                )
                token_resp.raise_for_status()
                token_data = token_resp.json()
                id_token = token_data.get("id_token")
                access_token = token_data.get("access_token")
                if not id_token:
                    return redirect("/?social_login_error=Yahoo+sign-in+failed")

                claims = _decode_id_token_claims(id_token)
                email = claims.get("email")
                name = claims.get("given_name") or claims.get("name") or ""
                log.info(f"[yahoo-login] id_token claims: {claims!r}")

                # With scope=openid alone, the ID token's claims can vary
                # by account type — fall back to Yahoo's userinfo endpoint
                # (using the access_token from the same response) if email
                # wasn't already present, rather than failing outright.
                if not email and access_token:
                    try:
                        userinfo_resp = _requests.get(
                            "https://api.login.yahoo.com/openid/v1/userinfo",
                            headers={"Authorization": f"Bearer {access_token}"},
                            timeout=10,
                        )
                        log.info(f"[yahoo-login] userinfo status={userinfo_resp.status_code} "
                                 f"body={userinfo_resp.text!r}")
                        if userinfo_resp.ok:
                            userinfo = userinfo_resp.json()
                            email = userinfo.get("email") or email
                            name = userinfo.get("given_name") or userinfo.get("name") or name
                    except Exception as e:
                        log.warning(f"[yahoo-login] userinfo fallback failed: {e!r}")

                if not email:
                    log.error(f"[yahoo-login] no email found — claims={claims!r} "
                              f"has_access_token={bool(access_token)}")
                    return redirect("/?social_login_error=Could+not+get+your+email+from+Yahoo")

                conn = get_db()
                user = _find_or_create_social_user(conn, get_db, audit, email, name)
                conn.close()

                token = pysecrets.token_hex(32)
                TOKENS[token] = {"id": user["id"], "username": user["username"], "role": user["role"],
                                  "organization": user["organization"]}
                return redirect(f"/?social_login_token={token}&social_provider=yahoo")
            except Exception as e:
                log.error(f"[yahoo-login] callback failed: {e!r}", exc_info=True)
                return redirect("/?social_login_error=Yahoo+sign-in+failed")

        app.logger.info("Yahoo one-click sign-in enabled")
