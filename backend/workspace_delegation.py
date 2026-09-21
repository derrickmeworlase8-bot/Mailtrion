"""
Mailtrion — Google Workspace domain-wide delegation

Lets an institution's Workspace super admin authorize Mailtrion once
(via domain-wide delegation in their admin console) and then enroll
every mailbox in their domain automatically, instead of each employee
individually clicking "Connect Gmail".

Two distinct identities are involved here, and it's important not to
conflate them:
  - The SERVICE ACCOUNT (this app's own credential, downloaded as a
    JSON key) is what the institution's admin grants domain-wide
    delegation to, once, in their admin console.
  - `admin_subject_email` is a real person in the institution's domain
    who has rights to call the Admin SDK Directory API (list every
    user). The service account impersonates THIS person only for the
    one-time "list every mailbox in the domain" call. Impersonating
    individual employees' own mailboxes (for actual scanning) uses
    each employee's own email as the subject instead — see
    gmail_provider.py.
"""

import json
from google.oauth2 import service_account
from googleapiclient.discovery import build

DIRECTORY_SCOPES = ["https://www.googleapis.com/auth/admin.directory.user.readonly"]
GMAIL_SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
]


def build_delegated_credentials(service_account_json_str, subject_email, scopes):
    """Returns credentials that act as `subject_email`, using the
    institution's authorized service account — no per-user OAuth
    consent screen or stored refresh token needed."""
    info = json.loads(service_account_json_str)
    creds = service_account.Credentials.from_service_account_info(info, scopes=scopes)
    return creds.with_subject(subject_email)


def list_domain_users(service_account_json_str, admin_subject_email):
    """Calls the Admin SDK Directory API, impersonating a real admin
    in the domain, to list every active user account. Returns a list
    of email addresses. Raises on failure (wrong admin email,
    delegation not yet authorized in the admin console, Admin SDK API
    not enabled, etc.) — the caller should surface that error clearly
    rather than silently enrolling nobody."""
    creds = build_delegated_credentials(service_account_json_str, admin_subject_email, DIRECTORY_SCOPES)
    service = build("admin", "directory_v1", credentials=creds)

    users = []
    page_token = None
    while True:
        resp = service.users().list(
            customer="my_customer",
            maxResults=200,
            orderBy="email",
            pageToken=page_token,
        ).execute()
        for u in resp.get("users", []):
            if not u.get("suspended") and u.get("primaryEmail"):
                users.append(u["primaryEmail"])
        page_token = resp.get("nextPageToken")
        if not page_token:
            break
    return users