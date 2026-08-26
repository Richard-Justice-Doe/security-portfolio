"""Aggregate captured packets into a reusable traffic baseline."""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from typing import Any

from ntd.database import load_packets, replace_baseline
from ntd.packets import outbound_only


def build_baseline(conn) -> dict[str, Any]:
    """Compute port, destination, size, and per-host frequency stats.

    Only outbound (LAN-sourced) packets are used so return traffic does not
    pollute "typical destination" and "typical port" sets.
    """
    packets = outbound_only(load_packets(conn))
    if len(packets) < 10:
        raise RuntimeError(
            f"Need at least 10 outbound packets to build a baseline (have {len(packets)})."
        )

    timestamps = [p["ts"] for p in packets]
    duration = max(timestamps) - min(timestamps)
    if duration <= 0:
        duration = 1.0

    sizes = [p["length"] for p in packets]
    avg_size = statistics.mean(sizes)
    std_size = statistics.pstdev(sizes) if len(sizes) > 1 else 0.0

    port_counts: Counter[tuple[int, str]] = Counter()
    dest_counts: Counter[tuple[str, int]] = Counter()
    by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for pkt in packets:
        by_host[pkt["src_ip"]].append(pkt)
        if pkt["dst_port"] is not None:
            port_counts[(int(pkt["dst_port"]), pkt["protocol"])] += 1
            dest_counts[(pkt["dst_ip"], int(pkt["dst_port"]))] += 1

    host_rows = []
    for host, pkts in sorted(by_host.items()):
        unique_dsts = len({p["dst_ip"] for p in pkts})
        connections = len(
            {(p["dst_ip"], p["dst_port"]) for p in pkts if p["dst_port"] is not None}
        )
        host_sizes = [p["length"] for p in pkts]
        host_rows.append(
            (
                host,
                len(pkts),
                statistics.mean(host_sizes),
                unique_dsts,
                connections,
                len(pkts) / duration,
            )
        )

    meta = {
        "packet_count": str(len(packets)),
        "duration_sec": f"{duration:.3f}",
        "avg_packet_size": f"{avg_size:.2f}",
        "std_packet_size": f"{std_size:.2f}",
        "unique_dest_ips": str(len({ip for ip, _port in dest_counts})),
        "unique_ports": str(len(port_counts)),
        "host_count": str(len(by_host)),
    }

    replace_baseline(
        conn,
        meta=meta,
        ports=[(port, proto, count) for (port, proto), count in port_counts.items()],
        destinations=[(ip, port, count) for (ip, port), count in dest_counts.items()],
        hosts=host_rows,
    )
    return meta
