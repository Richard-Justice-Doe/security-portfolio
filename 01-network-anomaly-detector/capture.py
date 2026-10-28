#!/usr/bin/env python3
"""Capture packets from a live interface or an offline PCAP into SQLite.

Ethical use: only sniff networks you own or have explicit permission to
monitor. The bundled sample PCAPs use documentation-range addresses only.

Examples:
    python capture.py --pcap samples/baseline.pcap --db data/traffic.db
    python capture.py --interface Ethernet --duration 60 --db data/traffic.db
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow `python capture.py` from this directory.
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from ntd.database import connect, insert_packets
from ntd.packets import iter_packets


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Capture IP packets into SQLite for baseline training or later analysis."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pcap", help="Read packets from a PCAP file (recommended demo mode)")
    source.add_argument(
        "--interface",
        help="Live capture on this interface (requires admin/Npcap; only on networks you own)",
    )
    parser.add_argument("--db", default=str(HERE / "data/traffic.db"), help="SQLite database path")
    parser.add_argument(
        "--duration",
        type=float,
        default=30.0,
        help="Live-capture timeout in seconds (ignored for --pcap)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    conn = connect(args.db)
    print(f"Writing packets to {args.db} ...", file=sys.stderr)
    try:
        records = iter_packets(
            pcap=args.pcap,
            interface=args.interface,
            duration=None if args.pcap else args.duration,
        )
    except OSError as exc:
        print(
            f"Capture failed ({exc}). On Windows, live sniffing needs Npcap and an elevated shell. "
            "Use --pcap with samples/baseline.pcap for the portable demo.",
            file=sys.stderr,
        )
        return 1

    stored = insert_packets(conn, records)
    conn.close()
    print(f"Stored {stored} IP packets in {args.db}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
