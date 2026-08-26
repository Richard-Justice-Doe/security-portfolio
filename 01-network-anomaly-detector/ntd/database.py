"""SQLite persistence for raw packets and the learned baseline."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    length INTEGER,
    tcp_flags TEXT
);

CREATE TABLE IF NOT EXISTS baseline_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS baseline_ports (
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (port, protocol)
);

CREATE TABLE IF NOT EXISTS baseline_destinations (
    dst_ip TEXT NOT NULL,
    dst_port INTEGER NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (dst_ip, dst_port)
);

CREATE TABLE IF NOT EXISTS baseline_hosts (
    host TEXT PRIMARY KEY,
    packets INTEGER NOT NULL,
    avg_size REAL NOT NULL,
    unique_dsts INTEGER NOT NULL,
    connections INTEGER NOT NULL,
    packets_per_sec REAL NOT NULL
);
"""


def connect(path: str | Path) -> sqlite3.Connection:
    """Open (or create) the database and ensure the schema exists."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def insert_packet(conn: sqlite3.Connection, rec: dict[str, Any]) -> None:
    conn.execute(
        """
        INSERT INTO packets (ts, src_ip, dst_ip, src_port, dst_port, protocol, length, tcp_flags)
        VALUES (:ts, :src_ip, :dst_ip, :src_port, :dst_port, :protocol, :length, :tcp_flags)
        """,
        rec,
    )


def insert_packets(conn: sqlite3.Connection, records: Iterable[dict[str, Any]]) -> int:
    rows = list(records)
    for rec in rows:
        insert_packet(conn, rec)
    conn.commit()
    return len(rows)


def load_packets(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    cur = conn.execute(
        "SELECT ts, src_ip, dst_ip, src_port, dst_port, protocol, length, tcp_flags "
        "FROM packets ORDER BY ts"
    )
    return [dict(row) for row in cur.fetchall()]


def replace_baseline(
    conn: sqlite3.Connection,
    *,
    meta: dict[str, str],
    ports: Iterable[tuple[int, str, int]],
    destinations: Iterable[tuple[str, int, int]],
    hosts: Iterable[tuple[str, int, float, int, int, float]],
) -> None:
    """Overwrite baseline tables with a freshly computed snapshot."""
    conn.execute("DELETE FROM baseline_meta")
    conn.execute("DELETE FROM baseline_ports")
    conn.execute("DELETE FROM baseline_destinations")
    conn.execute("DELETE FROM baseline_hosts")

    conn.executemany("INSERT INTO baseline_meta (key, value) VALUES (?, ?)", meta.items())
    conn.executemany(
        "INSERT INTO baseline_ports (port, protocol, count) VALUES (?, ?, ?)",
        ports,
    )
    conn.executemany(
        "INSERT INTO baseline_destinations (dst_ip, dst_port, count) VALUES (?, ?, ?)",
        destinations,
    )
    conn.executemany(
        """
        INSERT INTO baseline_hosts
            (host, packets, avg_size, unique_dsts, connections, packets_per_sec)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        hosts,
    )
    conn.commit()


def load_baseline(conn: sqlite3.Connection) -> dict[str, Any]:
    """Load the stored baseline into memory for detection."""
    meta = {row["key"]: row["value"] for row in conn.execute("SELECT key, value FROM baseline_meta")}
    if not meta:
        raise RuntimeError("No baseline found. Run baseline.py first.")

    ports = {
        (row["port"], row["protocol"]): row["count"]
        for row in conn.execute("SELECT port, protocol, count FROM baseline_ports")
    }
    destinations = {
        (row["dst_ip"], row["dst_port"]): row["count"]
        for row in conn.execute("SELECT dst_ip, dst_port, count FROM baseline_destinations")
    }
    dest_ips = {dst_ip for (dst_ip, _port) in destinations}
    typical_ports = {port for (port, _proto) in ports}
    hosts = {
        row["host"]: dict(row)
        for row in conn.execute("SELECT * FROM baseline_hosts")
    }
    return {
        "meta": meta,
        "ports": ports,
        "destinations": destinations,
        "dest_ips": dest_ips,
        "typical_ports": typical_ports,
        "hosts": hosts,
        "avg_packet_size": float(meta.get("avg_packet_size", 0)),
        "std_packet_size": float(meta.get("std_packet_size", 0)),
    }
