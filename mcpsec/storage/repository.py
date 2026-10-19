"""storage/repository.py — Persistent read/write for sessions and events."""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any

from .db import get_connection, init_db

logger = logging.getLogger("storage.repository")


def _decorate_session_row(row: dict[str, Any]) -> dict[str, Any]:
    decision = row.pop("max_decision", None)
    display_state = "NORMAL"
    if decision == "block":
        display_state = "BLOCK"
    elif decision == "alert" or row["state"] == "ALERT":
        display_state = "ALERT"
    row["display_state"] = display_state
    return row


class EventRepository:
    """Thread-safe SQLite-backed store for sessions and events."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        init_db()

    # ------------------------------------------------------------------
    # Writes (called from proxy — hot path, keep fast)
    # ------------------------------------------------------------------

    def upsert_session(self, session_id: str, created_at: str, state: str, event_count: int) -> None:
        with self._lock:
            conn = get_connection()
            with conn:
                conn.execute("""
                    INSERT INTO sessions (session_id, created_at, state, event_count)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(session_id) DO UPDATE SET
                        state       = excluded.state,
                        event_count = excluded.event_count
                """, (session_id, created_at, state, event_count))
            conn.close()

    def close_session(self, session_id: str) -> None:
        now = datetime.now(tz=timezone.utc).isoformat()
        with self._lock:
            conn = get_connection()
            with conn:
                conn.execute(
                    "UPDATE sessions SET ended_at = ? WHERE session_id = ?",
                    (now, session_id),
                )
            conn.close()

    def save_event(self, session_id: str, event: dict[str, Any]) -> None:
        with self._lock:
            conn = get_connection()
            with conn:
                conn.execute("""
                    INSERT INTO events (session_id, timestamp, direction, tool_name, flags, decision, content)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    session_id,
                    event["timestamp"],
                    event["direction"],
                    event["tool_name"],
                    json.dumps(event.get("flags", [])),
                    event.get("decision", "pass"),
                    json.dumps(event.get("content", {})),
                ))
                conn.execute("""
                    UPDATE sessions SET event_count = event_count + 1 WHERE session_id = ?
                """, (session_id,))
            conn.close()

    # ------------------------------------------------------------------
    # Reads (called from API — can be slightly slower)
    # ------------------------------------------------------------------

    def get_sessions(
        self,
        include_closed: bool = True,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        conn = get_connection()
        query = """
            SELECT
                sessions.*,
                (
                    SELECT CASE
                        WHEN SUM(CASE WHEN events.decision = 'block' THEN 1 ELSE 0 END) > 0 THEN 'block'
                        WHEN SUM(CASE WHEN events.decision = 'alert' THEN 1 ELSE 0 END) > 0 THEN 'alert'
                        ELSE NULL
                    END
                    FROM events
                    WHERE events.session_id = sessions.session_id
                ) AS max_decision
            FROM sessions
        """
        if not include_closed:
            query += " WHERE ended_at IS NULL"
        query += " ORDER BY created_at DESC LIMIT ?"
        rows = conn.execute(query, (limit,)).fetchall()
        conn.close()
        return [_decorate_session_row(dict(r)) for r in rows]

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        conn = get_connection()
        row = conn.execute(
            """
            SELECT
                sessions.*,
                (
                    SELECT CASE
                        WHEN SUM(CASE WHEN events.decision = 'block' THEN 1 ELSE 0 END) > 0 THEN 'block'
                        WHEN SUM(CASE WHEN events.decision = 'alert' THEN 1 ELSE 0 END) > 0 THEN 'alert'
                        ELSE NULL
                    END
                    FROM events
                    WHERE events.session_id = sessions.session_id
                ) AS max_decision
            FROM sessions
            WHERE session_id = ?
            """,
            (session_id,),
        ).fetchone()
        conn.close()
        return _decorate_session_row(dict(row)) if row is not None else None

    def get_events(
        self,
        session_id: str | None = None,
        tool_name: str | None = None,
        decision: str | None = None,
        flags_contain: str | None = None,
        since: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []

        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        if tool_name:
            clauses.append("tool_name = ?")
            params.append(tool_name)
        if decision:
            clauses.append("decision = ?")
            params.append(decision)
        if flags_contain:
            clauses.append("flags LIKE ?")
            params.append(f"%{flags_contain}%")
        if since:
            clauses.append("timestamp >= ?")
            params.append(since)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        query = f"SELECT * FROM events {where} ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        conn = get_connection()
        rows = conn.execute(query, params).fetchall()
        conn.close()

        results = []
        for r in rows:
            d = dict(r)
            d["flags"] = json.loads(d["flags"])
            d["content"] = json.loads(d["content"])
            results.append(d)
        return results

    def save_routing_table(self, table: dict[str, str]) -> None:
        """Persist tool→backend mapping. Replaces previous snapshot."""
        now = datetime.now(tz=timezone.utc).isoformat()
        with self._lock:
            conn = get_connection()
            with conn:
                conn.execute("DELETE FROM routing_table")
                conn.executemany(
                    "INSERT INTO routing_table (tool_name, backend_name, updated_at) VALUES (?, ?, ?)",
                    [(tool, backend, now) for tool, backend in table.items()],
                )
            conn.close()

    def get_routing_table(self) -> dict[str, Any]:
        conn = get_connection()
        rows = conn.execute(
            "SELECT tool_name, backend_name, updated_at FROM routing_table ORDER BY tool_name"
        ).fetchall()
        conn.close()
        if not rows:
            return {"status": "no data yet", "tool_to_backend": {}, "backend_to_tools": {}}

        tool_to_backend: dict[str, str] = {}
        backend_to_tools: dict[str, list[str]] = {}
        updated_at = None
        for r in rows:
            tool_to_backend[r["tool_name"]] = r["backend_name"]
            backend_to_tools.setdefault(r["backend_name"], []).append(r["tool_name"])
            updated_at = r["updated_at"]

        return {
            "status": "ready",
            "updated_at": updated_at,
            "tool_to_backend": tool_to_backend,
            "backend_to_tools": backend_to_tools,
        }

    def set_label_override(self, tool_name: str, labels: list[str]) -> None:
        """Persist a human-corrected U/S/E label set for a tool. Survives
        toxic-flow re-runs (rescan / add-backend / remove-backend)."""
        now = datetime.now(tz=timezone.utc).isoformat()
        with self._lock:
            conn = get_connection()
            with conn:
                conn.execute("""
                    INSERT INTO tool_label_overrides (tool_name, labels, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(tool_name) DO UPDATE SET
                        labels     = excluded.labels,
                        updated_at = excluded.updated_at
                """, (tool_name, json.dumps(labels), now))
            conn.close()

    def delete_label_override(self, tool_name: str) -> None:
        with self._lock:
            conn = get_connection()
            with conn:
                conn.execute("DELETE FROM tool_label_overrides WHERE tool_name = ?", (tool_name,))
            conn.close()

    def get_label_overrides(self) -> dict[str, list[str]]:
        conn = get_connection()
        rows = conn.execute("SELECT tool_name, labels FROM tool_label_overrides").fetchall()
        conn.close()
        return {r["tool_name"]: json.loads(r["labels"]) for r in rows}

    def get_stats(self) -> dict[str, Any]:
        conn = get_connection()
        sessions_total = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        events_total   = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        flagged        = conn.execute("SELECT COUNT(*) FROM events WHERE flags != '[]'").fetchone()[0]
        blocked        = conn.execute("SELECT COUNT(*) FROM events WHERE decision = 'block'").fetchone()[0]
        alerted        = conn.execute("SELECT COUNT(*) FROM events WHERE decision = 'alert'").fetchone()[0]
        conn.close()
        return {
            "sessions_total": sessions_total,
            "events_total":   events_total,
            "flagged_events": flagged,
            "blocked":        blocked,
            "alerted":        alerted,
        }

    def clear_runtime_state(self) -> dict[str, int]:
        results_dir = os.path.join(os.path.dirname(__file__), "results")
        removed_files = 0

        with self._lock:
            conn = get_connection()
            with conn:
                deleted_events = conn.execute("DELETE FROM events").rowcount
                deleted_sessions = conn.execute("DELETE FROM sessions").rowcount
                conn.execute("DELETE FROM routing_table")
                conn.execute(
                    "DELETE FROM sqlite_sequence WHERE name IN ('events')"
                )
            conn.close()

            for filename in ("discovery_result.json", "toxic_flow_result.json"):
                path = os.path.join(results_dir, filename)
                if os.path.exists(path):
                    os.remove(path)
                    removed_files += 1

        return {
            "deleted_sessions": deleted_sessions,
            "deleted_events": deleted_events,
            "removed_result_files": removed_files,
        }
