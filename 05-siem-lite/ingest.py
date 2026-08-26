#!/usr/bin/env python3
"""Load sample logs, normalise them, run the rule engine, write SQLite."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from rules import run_rules
from siem.db import connect, insert_alerts, insert_events, reset
from siem.parsers import parse_file

SAMPLES = {
    "auth": "samples/auth.log",
    "firewall": "samples/iptables.log",
    "web": "samples/access.log",
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Ingest lab logs into SIEM-lite SQLite.")
    parser.add_argument("--db", default="data/siem.db")
    parser.add_argument("--reset", action="store_true", help="Wipe events/alerts before ingest")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent
    conn = connect(root / args.db if not Path(args.db).is_absolute() else args.db)
    if args.reset:
        reset(conn)

    total = 0
    for source, rel in SAMPLES.items():
        path = root / rel
        rows = parse_file(source, path)
        insert_events(conn, rows)
        print(f"{source:10} {len(rows):4} events from {rel}")
        total += len(rows)

    alerts = run_rules(conn)
    insert_alerts(conn, alerts)
    print(f"stored {total} events, {len(alerts)} alerts -> {args.db}")
    for alert in alerts:
        print(f"  [{alert['severity']:<6}] {alert['rule']:<20} {alert['details']}")
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
