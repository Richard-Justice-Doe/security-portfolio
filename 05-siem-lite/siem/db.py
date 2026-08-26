"""SQLite store for normalised events and alerts."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    src_ip TEXT,
    raw_message TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    rule TEXT NOT NULL,
    severity TEXT NOT NULL,
    src_ip TEXT,
    details TEXT NOT NULL
);
"""


def connect(path: str | Path) -> sqlite3.Connection:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def reset(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM events")
    conn.execute("DELETE FROM alerts")
    conn.commit()


def insert_events(conn: sqlite3.Connection, rows: list[dict[str, Any]]) -> int:
    conn.executemany(
        """
        INSERT INTO events (ts, source, event_type, severity, src_ip, raw_message)
        VALUES (:ts, :source, :event_type, :severity, :src_ip, :raw_message)
        """,
        rows,
    )
    conn.commit()
    return len(rows)


def insert_alerts(conn: sqlite3.Connection, rows: list[dict[str, Any]]) -> int:
    conn.executemany(
        """
        INSERT INTO alerts (ts, rule, severity, src_ip, details)
        VALUES (:ts, :rule, :severity, :src_ip, :details)
        """,
        rows,
    )
    conn.commit()
    return len(rows)


def fetch_events(
    conn: sqlite3.Connection,
    source: str | None = None,
    severity: str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    clauses = ["1=1"]
    params: list[Any] = []
    if source:
        clauses.append("source = ?")
        params.append(source)
    if severity:
        clauses.append("severity = ?")
        params.append(severity)
    sql = f"SELECT * FROM events WHERE {' AND '.join(clauses)} ORDER BY ts DESC LIMIT ?"
    params.append(limit)
    return [dict(r) for r in conn.execute(sql, params)]


def fetch_alerts(conn: sqlite3.Connection, limit: int = 100) -> list[dict[str, Any]]:
    return [dict(r) for r in conn.execute("SELECT * FROM alerts ORDER BY ts DESC LIMIT ?", (limit,))]


def volume_by_hour(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT substr(ts, 1, 13) AS hour, source, COUNT(*) AS n
        FROM events
        GROUP BY hour, source
        ORDER BY hour
        """
    )
    return [dict(r) for r in rows]
