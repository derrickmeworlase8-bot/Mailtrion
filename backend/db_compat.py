"""
db_compat.py — SQLite / Postgres compatibility shim.

Why this exists: the pilot deployment ran on SQLite with a file living on
Render's free-tier disk, which does not persist across every restart —
meaning connected accounts, scan history, and audit logs could vanish on
a redeploy. The fix is a real, persistent Postgres database (e.g. a free
Supabase project). Rewriting all ~80 query call sites across app.py by
hand to use psycopg2's `%s` placeholders and dict-cursor rows would be a
large, error-prone change under deadline pressure for no functional
benefit — so instead, this module provides a drop-in `connect()` that:

  - returns a real sqlite3 connection, unchanged, when DATABASE_URL is
    not set (local development keeps working exactly as before), or
  - returns a lightweight Postgres-backed wrapper, when DATABASE_URL is
    set, that accepts the exact same `?`-style query text and exposes
    the same dict-key row access (row["column"]) that sqlite3.Row does,
    so the existing call sites do not need to change.

Three SQLite-only fragments this codebase actually uses are translated
automatically inside that wrapper: `INTEGER PRIMARY KEY AUTOINCREMENT`
(table creation), `INSERT OR REPLACE INTO scans` (safe to simplify to a
plain INSERT here since scan_id is already a globally unique UUID, so no
real "replace" ever happens in practice), and `PRAGMA table_info(...)`
(replaced by the table_columns() helper below, used at each of its four
call sites instead of the raw PRAGMA string).
"""

import os
import re
import sqlite3

DATABASE_URL = os.environ.get("DATABASE_URL")
IS_POSTGRES = bool(DATABASE_URL)

if IS_POSTGRES:
    import psycopg2
    import psycopg2.extras
    IntegrityError = psycopg2.IntegrityError
else:
    IntegrityError = sqlite3.IntegrityError


_QMARK_RE = re.compile(r"\?")


def _translate_sql(sql: str) -> str:
    sql = sql.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
    sql = sql.replace("INSERT OR REPLACE INTO scans", "INSERT INTO scans")
    sql = _QMARK_RE.sub("%s", sql)
    return sql


class _PGCursorWrapper:
    """Mimics sqlite3.Cursor closely enough for this codebase: .execute()
    returns self (so `.execute(...).fetchall()` and `.execute(...).rowcount`
    both work, matching the two patterns actually used in app.py), and
    rows come back as dict-like objects supporting row["column"] access."""

    def __init__(self, real_cursor):
        self._cursor = real_cursor

    def execute(self, sql, params=()):
        self._cursor.execute(_translate_sql(sql), tuple(params) if params else params)
        return self

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    @property
    def rowcount(self):
        return self._cursor.rowcount


class _PGConnWrapper:
    def __init__(self, real_conn):
        self._conn = real_conn

    def cursor(self):
        return _PGCursorWrapper(self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor))

    def execute(self, sql, params=()):
        return self.cursor().execute(sql, params)

    def commit(self):
        self._conn.commit()

    def close(self):
        self._conn.close()


def connect(db_path=None):
    """Drop-in replacement for sqlite3.connect(DB_PATH). Returns a
    Postgres-backed connection instead whenever DATABASE_URL is set,
    with no other code changes required at the call site."""
    if IS_POSTGRES:
        return _PGConnWrapper(psycopg2.connect(DATABASE_URL))
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def table_columns(c, table_name: str) -> set:
    """Replacement for `PRAGMA table_info(table_name)`, used at every
    migration check site in app.py's init_db(). Works identically on
    both backends from the caller's point of view — pass in a cursor
    (from conn.cursor()), get back a set of column-name strings."""
    if IS_POSTGRES:
        c.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name = %s",
            (table_name,)
        )
        return {row["column_name"] for row in c.fetchall()}
    rows = c.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {row[1] for row in rows}
