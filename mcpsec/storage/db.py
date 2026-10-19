"""storage/db.py — SQLite connection and schema setup."""

from __future__ import annotations

import logging
import os
import sqlite3

logger = logging.getLogger("storage.db")

_DB_PATH = os.path.join(os.path.dirname(__file__), "mcpsec.db")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    conn = get_connection()
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id   TEXT PRIMARY KEY,
                created_at   TEXT NOT NULL,
                ended_at     TEXT,
                state        TEXT NOT NULL DEFAULT 'NORMAL',
                event_count  INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id  TEXT NOT NULL REFERENCES sessions(session_id),
                timestamp   TEXT NOT NULL,
                direction   TEXT NOT NULL,
                tool_name   TEXT NOT NULL,
                flags       TEXT NOT NULL DEFAULT '[]',
                decision    TEXT NOT NULL DEFAULT 'pass',
                content     TEXT NOT NULL DEFAULT '{}'
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_tool    ON events(tool_name)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_decision ON events(decision)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(timestamp)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS routing_table (
                tool_name    TEXT PRIMARY KEY,
                backend_name TEXT NOT NULL,
                updated_at   TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tool_label_overrides (
                tool_name  TEXT PRIMARY KEY,
                labels     TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
    conn.close()
    logger.info("SQLite DB ready: %s", _DB_PATH)
