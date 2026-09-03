"""
Mailtrion — relational sender-reputation signal.

The published PhishGuard graph paper (Ramesh et al., 2026) analyses
sender-receiver relationships with a Neo4j-backed graph model (PageRank,
ArticleRank, Degree Centrality) alongside its content classifier — the
idea being that WHO is emailing WHO, and how often, carries a signal
content analysis alone misses (e.g. a first-ever contact from a domain
impersonating a known vendor).

Standing up and operating a full graph database is real infrastructure
overhead that isn't justified at this project's current pilot scale, and
isn't something we can commit to for free indefinitely (see the earlier
cost/free-tier conversation). This module implements the SAME underlying
idea — sender-receiver relationship history as a risk signal — as a
lightweight aggregation inside the existing SQLite database instead:

  - Has this sender domain ever contacted this organization before?
  - How many times, and has it ever previously been flagged as phishing?

This is deliberately named and scoped as a "v1, lightweight" version of
the relational signal in the proposal/report — full graph analytics
(PageRank/centrality over the sender-receiver graph, as in the cited
paper) is the natural v2 upgrade once there's enough connected-account
volume and infra budget to justify running Neo4j.
"""

import re
from datetime import datetime


def extract_domain(sender: str) -> str:
    """Pulls the domain out of a From header, which may be a raw address
    ('a@b.com') or a display-name form ('Name <a@b.com>')."""
    match = re.search(r'@([\w.-]+)', sender or "")
    return match.group(1).lower() if match else "unknown"


def get_sender_context(conn, organization: str, sender_domain: str) -> dict:
    """Looks up this sender domain's history against this organization —
    the relational context used to adjust risk scoring."""
    row = conn.execute(
        """SELECT total_seen, phishing_count, first_seen, last_seen
           FROM sender_reputation
           WHERE organization=? AND sender_domain=?""",
        (organization, sender_domain)
    ).fetchone()

    if not row:
        return {"is_first_contact": True, "total_seen": 0,
                "phishing_count": 0, "phishing_ratio": 0.0}

    total = row["total_seen"] or 0
    flagged = row["phishing_count"] or 0
    return {
        "is_first_contact": total == 0,
        "total_seen": total,
        "phishing_count": flagged,
        "phishing_ratio": (flagged / total) if total else 0.0,
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
    }


def relational_risk_adjustment(context: dict) -> tuple:
    """
    Returns (score_delta, factor_or_None) based on sender-receiver history.
    Kept modest and additive to the existing content/auth-based scoring —
    this is a supporting signal, not a replacement for it.
    """
    if context["phishing_count"] > 0:
        return 15, {
            "name": f"Sender domain previously flagged {context['phishing_count']}x for this organization",
            "weight": min(100, 40 + context["phishing_count"] * 15),
            "impact": "negative",
        }

    if context["is_first_contact"]:
        return 5, {
            "name": "First contact from this sender domain",
            "weight": 30,
            "impact": "negative",
        }

    if context["total_seen"] >= 5:
        return -5, {
            "name": f"Established sender ({context['total_seen']} prior emails, none flagged)",
            "weight": 25,
            "impact": "positive",
        }

    return 0, None


def record_observation(conn, organization: str, sender_domain: str, is_phishing: bool):
    """Upserts this scan's outcome into the sender-domain history for this
    organization. Called once per scan, after scoring — this is what lets
    the *next* email from the same domain benefit from (or be penalized
    by) this one's outcome."""
    now = datetime.utcnow().isoformat()
    existing = conn.execute(
        "SELECT id FROM sender_reputation WHERE organization=? AND sender_domain=?",
        (organization, sender_domain)
    ).fetchone()

    if existing:
        conn.execute(
            """UPDATE sender_reputation
               SET total_seen = total_seen + 1,
                   phishing_count = phishing_count + ?,
                   last_seen = ?
               WHERE id=?""",
            (1 if is_phishing else 0, now, existing["id"])
        )
    else:
        conn.execute(
            """INSERT INTO sender_reputation
               (organization, sender_domain, total_seen, phishing_count, first_seen, last_seen)
               VALUES (?,?,1,?,?,?)""",
            (organization, sender_domain, 1 if is_phishing else 0, now, now)
        )
