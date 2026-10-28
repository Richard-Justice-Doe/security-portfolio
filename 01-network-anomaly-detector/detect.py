#!/usr/bin/env python3
"""Compare new traffic against a stored baseline and emit structured alerts.

Detectors:
  PORT_SCAN          — many SYN ports from one host to one target in a short window
  UNUSUAL_OUTBOUND   — destination IP/port never seen during baseline training
  BEACONING          — near-periodic connections to the same remote service

Example:
    python detect.py --pcap samples/anomalous.pcap --db data/traffic.db --log logs/alerts.jsonl
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from ntd.alerts import AlertLogger
from ntd.database import connect, load_baseline
from ntd.detector import run_detectors
from ntd.packets import iter_packets


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect traffic anomalies against a learned baseline.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pcap", help="Offline PCAP to analyse (recommended demo mode)")
    source.add_argument("--interface", help="Live capture interface (networks you own only)")
    parser.add_argument("--db", default=str(HERE / "data/traffic.db"), help="SQLite DB that holds the baseline")
    parser.add_argument("--log", default=str(HERE / "logs/alerts.jsonl"), help="JSONL alert log path")
    parser.add_argument(
        "--append",
        action="store_true",
        help="Add to the existing alert log instead of starting a fresh one for this run",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=30.0,
        help="Live-capture window in seconds (analysis runs after the window closes)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logger = AlertLogger(args.log, append=args.append)

    conn = connect(args.db)
    try:
        baseline = load_baseline(conn)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()

    meta = baseline["meta"]
    logger.emit_info(
        f"Loaded baseline: {meta.get('packet_count')} packets, "
        f"{meta.get('unique_dest_ips')} dest IPs, {meta.get('unique_ports')} ports"
    )

    try:
        packets = iter_packets(
            pcap=args.pcap,
            interface=args.interface,
            duration=None if args.pcap else args.duration,
        )
    except OSError as exc:
        print(f"Capture failed ({exc}). Use --pcap with samples/anomalous.pcap.", file=sys.stderr)
        return 1

    logger.emit_info(f"Analysed {len(packets)} packets from {'PCAP' if args.pcap else args.interface}")
    alerts = run_detectors(packets, baseline)

    if not alerts:
        print("No alerts. Traffic is consistent with the baseline.")
        return 0

    print(f"\n{len(alerts)} alert(s):\n")
    for alert in alerts:
        logger.emit(alert)

    print(f"\nJSONL log written to {args.log}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
