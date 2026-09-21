"""
Mailtrion — admin routes for Google Workspace domain-wide enrollment.

Design note on mailbox ownership: bulk-enrolled mailboxes don't
necessarily correspond to an existing Mailtrion analyst account, so
each enrolled mailbox is attributed to the admin who ran the
enrollment. Since admins already have full cross-account visibility
(see list_quarantine's admin branch in app.py), this doesn't restrict
anything in practice — it's a placeholder ownership model, not a
security boundary. A future pass could map enrolled mailboxes to
per-employee Mailtrion accounts as those get created.
"""

from datetime import datetime
from flask import request, jsonify

from crypto_utils import encrypt_value, decrypt_value
from workspace_delegation import list_domain_users


def register_workspace_routes(app, get_db, audit, admin_required, current_user):

    @app.route("/admin/workspace/connect", methods=["POST"])
    @admin_required
    def workspace_connect():
        d = request.get_json() or {}
        domain = (d.get("domain") or "").strip().lower()
        service_account_json = (d.get("service_account_json") or "").strip()
        admin_subject_email = (d.get("admin_subject_email") or "").strip()
        organization = (d.get("organization") or "").strip() or "Unassigned"

        if not domain or not service_account_json or not admin_subject_email:
            return jsonify({"error": "domain, service_account_json, and admin_subject_email are all required"}), 400

        user = current_user()
        conn = get_db()
        try:
            conn.execute("""INSERT INTO workspace_domains
                (organization, domain, service_account_json, admin_subject_email, connected_by, connected_at, is_active)
                VALUES (?,?,?,?,?,?,1)
                ON CONFLICT(domain) DO UPDATE SET
                    service_account_json=excluded.service_account_json,
                    admin_subject_email=excluded.admin_subject_email,
                    is_active=1""",
                (organization, domain, encrypt_value(service_account_json), admin_subject_email,
                 user["id"], datetime.utcnow().isoformat()))
            conn.commit()
        except Exception as e:
            conn.close()
            return jsonify({"error": f"Could not save domain configuration: {e}"}), 400
        conn.close()

        audit(user["id"], user["username"], "WORKSPACE_DOMAIN_CONNECTED", f"domain={domain}")
        return jsonify({"message": "Domain configuration saved. Run enrollment next.", "domain": domain})

    @app.route("/admin/workspace", methods=["GET"])
    @admin_required
    def workspace_list():
        conn = get_db()
        rows = conn.execute("""
            SELECT id, organization, domain, admin_subject_email,
                   connected_at, last_enrolled_at, enrolled_user_count, is_active
            FROM workspace_domains ORDER BY connected_at DESC
        """).fetchall()
        conn.close()
        return jsonify({"domains": [dict(r) for r in rows]})

    @app.route("/admin/workspace/<int:domain_id>/enroll", methods=["POST"])
    @admin_required
    def workspace_enroll(domain_id):
        user = current_user()
        conn = get_db()
        domain_row = conn.execute(
            "SELECT * FROM workspace_domains WHERE id=?", (domain_id,)
        ).fetchone()
        if not domain_row:
            conn.close()
            return jsonify({"error": "Domain not found"}), 404

        service_account_json = decrypt_value(domain_row["service_account_json"])

        try:
            emails = list_domain_users(service_account_json, domain_row["admin_subject_email"])
        except Exception as e:
            conn.close()
            return jsonify({
                "error": f"Could not list domain users: {e}. "
                         f"Confirm domain-wide delegation was authorized in the Workspace admin "
                         f"console with the exact scopes required, and that admin_subject_email "
                         f"is a real, active admin in this domain."
            }), 400

        enrolled, skipped = 0, 0
        placeholder = encrypt_value("DELEGATED")
        for email in emails:
            existing = conn.execute(
                "SELECT id FROM gmail_accounts WHERE gmail_address=?", (email,)
            ).fetchone()
            if existing:
                skipped += 1
                continue
            conn.execute("""INSERT INTO gmail_accounts
                (user_id, gmail_address, access_token, refresh_token, connected_at,
                 is_active, is_delegated, workspace_domain_id)
                VALUES (?,?,?,?,?,1,1,?)""",
                (user["id"], email, placeholder, placeholder,
                 datetime.utcnow().isoformat(), domain_id))
            enrolled += 1

        conn.execute("""UPDATE workspace_domains
            SET last_enrolled_at=?, enrolled_user_count=enrolled_user_count+?
            WHERE id=?""",
            (datetime.utcnow().isoformat(), enrolled, domain_id))
        conn.commit()
        conn.close()

        audit(user["id"], user["username"], "WORKSPACE_DOMAIN_ENROLLED",
              f"domain_id={domain_id} enrolled={enrolled} skipped_existing={skipped}")
        return jsonify({
            "message": f"Enrolled {enrolled} mailbox(es); {skipped} already existed.",
            "enrolled": enrolled, "skipped": skipped, "total_found": len(emails)
        })