#!/usr/bin/env python3
"""Build a traffic baseline from packets previously stored by capture.py.

The baseline records:
  - typical destination ports and protocols
  - common destination IP:port pairs
  - average / std-dev packet size
  - per-host packet rate and unique destination count

Example:
    python baseline.py --db data/traffic.db
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ntd.builder import build_baseline
from ntd.database import connect


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compute a network baseline from captured packets.")
    parser.add_argument("--db", default="data/traffic.db", help="SQLite database path")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    conn = connect(args.db)
    try:
        meta = build_baseline(conn)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()

    print("Baseline written to", args.db)
    print(f"  outbound packets : {meta['packet_count']}")
    print(f"  sample duration  : {meta['duration_sec']}s")
    print(f"  avg packet size  : {meta['avg_packet_size']} bytes (std {meta['std_packet_size']})")
    print(f"  unique dest IPs  : {meta['unique_dest_ips']}")
    print(f"  unique ports     : {meta['unique_ports']}")
    print(f"  internal hosts   : {meta['host_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
