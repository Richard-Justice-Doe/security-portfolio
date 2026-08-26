"""Heuristic detectors: port scans, unusual outbound destinations, beaconing."""

from __future__ import annotations

import statistics
from collections import defaultdict
from typing import Any

from ntd.alerts import Alert
from ntd.config import Thresholds
from ntd.packets import PacketRecord, is_internal, outbound_only


def _is_syn_scan_packet(pkt: PacketRecord) -> bool:
    """True for TCP SYN (not SYN-ACK) which is the usual scan fingerprint."""
    if pkt.get("protocol") != "TCP" or not pkt.get("tcp_flags"):
        return False
    flags = str(pkt["tcp_flags"]).upper()
    return "S" in flags and "A" not in flags


def detect_port_scans(
    packets: list[PacketRecord],
    thresholds: Thresholds,
) -> list[Alert]:
    """Flag one host probing many ports on a single target in a short window."""
    alerts: list[Alert] = []
    grouped: dict[tuple[str, str], list[PacketRecord]] = defaultdict(list)

    for pkt in outbound_only(packets):
        if pkt.get("dst_port") is None:
            continue
        if not _is_syn_scan_packet(pkt):
            continue
        grouped[(pkt["src_ip"], pkt["dst_ip"])].append(pkt)

    window = thresholds.port_scan_window_sec
    min_ports = thresholds.port_scan_min_ports

    for (src, dst), pkts in grouped.items():
        pkts.sort(key=lambda p: p["ts"])
        best_ports = 0
        best_span = 0.0
        best_ts = pkts[-1]["ts"]
        left = 0
        for right in range(len(pkts)):
            while pkts[right]["ts"] - pkts[left]["ts"] > window:
                left += 1
            ports = {p["dst_port"] for p in pkts[left : right + 1]}
            if len(ports) > best_ports:
                best_ports = len(ports)
                best_span = pkts[right]["ts"] - pkts[left]["ts"]
                best_ts = pkts[right]["ts"]
        if best_ports >= min_ports:
            alerts.append(
                Alert.from_event(
                    "PORT_SCAN",
                    src_ip=src,
                    dst_ip=dst,
                    details=(
                        f"{best_ports} distinct destination ports in {best_span:.2f}s "
                        f"(threshold {min_ports} ports / {window:.0f}s)"
                    ),
                    ts=best_ts,
                    extra={"unique_ports": best_ports, "window_sec": round(best_span, 3)},
                )
            )
    return alerts


def detect_unusual_outbound(
    packets: list[PacketRecord],
    baseline: dict[str, Any],
    _thresholds: Thresholds,
) -> list[Alert]:
    """Flag LAN hosts contacting destination IPs/ports never seen in the baseline."""
    known_pairs = baseline["destinations"]
    known_ips = baseline["dest_ips"]
    alerts: list[Alert] = []
    seen: set[tuple[str, str, int]] = set()

    for pkt in outbound_only(packets):
        if pkt.get("dst_port") is None:
            continue
        if is_internal(pkt["dst_ip"]):
            # East-west traffic is handled by the port-scan heuristic.
            continue
        pair = (pkt["dst_ip"], int(pkt["dst_port"]))
        key = (pkt["src_ip"], pkt["dst_ip"], int(pkt["dst_port"]))
        if key in seen:
            continue
        if pair in known_pairs:
            continue
        seen.add(key)

        if pkt["dst_ip"] not in known_ips:
            reason = "destination IP never observed during baseline"
        else:
            reason = "destination IP:port pair never observed during baseline"

        alerts.append(
            Alert.from_event(
                "UNUSUAL_OUTBOUND",
                src_ip=pkt["src_ip"],
                dst_ip=pkt["dst_ip"],
                src_port=pkt.get("src_port"),
                dst_port=int(pkt["dst_port"]),
                details=reason,
                ts=pkt["ts"],
            )
        )
    return alerts


def detect_beaconing(
    packets: list[PacketRecord],
    thresholds: Thresholds,
) -> list[Alert]:
    """Flag near-periodic connections to the same remote service (C2-like)."""
    grouped: dict[tuple[str, str, int], list[float]] = defaultdict(list)

    for pkt in outbound_only(packets):
        if pkt.get("dst_port") is None:
            continue
        grouped[(pkt["src_ip"], pkt["dst_ip"], int(pkt["dst_port"]))].append(pkt["ts"])

    alerts: list[Alert] = []
    for (src, dst, dport), stamps in grouped.items():
        stamps = sorted(set(stamps))
        if len(stamps) < thresholds.beacon_min_events:
            continue
        intervals = [b - a for a, b in zip(stamps, stamps[1:])]
        if not intervals:
            continue
        mean_iv = statistics.mean(intervals)
        if mean_iv < thresholds.beacon_min_interval or mean_iv > thresholds.beacon_max_interval:
            continue
        stdev = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0
        cv = stdev / mean_iv if mean_iv else 1.0
        if cv <= thresholds.beacon_max_cv:
            alerts.append(
                Alert.from_event(
                    "BEACONING",
                    src_ip=src,
                    dst_ip=dst,
                    dst_port=dport,
                    details=(
                        f"{len(stamps)} connections, mean interval {mean_iv:.1f}s, "
                        f"coefficient of variation {cv:.3f} "
                        f"(threshold CV <= {thresholds.beacon_max_cv})"
                    ),
                    ts=stamps[-1],
                    extra={
                        "event_count": len(stamps),
                        "mean_interval_sec": round(mean_iv, 3),
                        "cv": round(cv, 4),
                    },
                )
            )
    return alerts


def run_detectors(
    packets: list[PacketRecord],
    baseline: dict[str, Any],
    thresholds: Thresholds | None = None,
) -> list[Alert]:
    """Run all heuristics and return alerts in timestamp order."""
    thresholds = thresholds or Thresholds()
    alerts = [
        *detect_port_scans(packets, thresholds),
        *detect_unusual_outbound(packets, baseline, thresholds),
        *detect_beaconing(packets, thresholds),
    ]
    alerts.sort(key=lambda a: a.timestamp)
    return alerts
