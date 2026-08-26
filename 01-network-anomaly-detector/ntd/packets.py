"""Packet parsing and capture helpers built on Scapy.

Live sniffing is optional and requires appropriate privileges plus a
packet-capture driver (Npcap on Windows). Offline PCAP mode is the
supported demo path and needs no extra drivers.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterator
from typing import Any

import logging

logging.getLogger("scapy").setLevel(logging.ERROR)

from scapy.all import ICMP, IP, TCP, UDP, sniff  # type: ignore[import-untyped]

from ntd.config import INTERNAL_NETWORKS

PacketRecord = dict[str, Any]


def is_internal(ip: str | None) -> bool:
    """Return True if *ip* belongs to a private (RFC 1918) network."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(net) for net in INTERNAL_NETWORKS)


def parse_packet(pkt: Any) -> PacketRecord | None:
    """Extract a flat record from a Scapy packet. Non-IP frames are ignored."""
    if IP not in pkt:
        return None

    ip = pkt[IP]
    proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(ip.proto, str(ip.proto))
    record: PacketRecord = {
        "ts": float(pkt.time),
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "src_port": None,
        "dst_port": None,
        "protocol": proto_name,
        "length": int(len(pkt)),
        "tcp_flags": None,
    }

    if TCP in pkt:
        tcp = pkt[TCP]
        record["src_port"] = int(tcp.sport)
        record["dst_port"] = int(tcp.dport)
        record["tcp_flags"] = str(tcp.flags)
    elif UDP in pkt:
        udp = pkt[UDP]
        record["src_port"] = int(udp.sport)
        record["dst_port"] = int(udp.dport)
    elif ICMP in pkt:
        record["protocol"] = "ICMP"

    return record


def iter_packets(
    *,
    pcap: str | None = None,
    interface: str | None = None,
    duration: float | None = None,
    on_packet: Callable[[PacketRecord], None] | None = None,
) -> list[PacketRecord]:
    """Sniff from a live interface or read a PCAP, returning parsed records.

    Either *pcap* or *interface* must be provided. When *on_packet* is set,
    it is called for every parsed record (used by capture.py to persist as
    packets arrive).
    """
    if not pcap and not interface:
        raise ValueError("Provide --pcap or --interface")

    records: list[PacketRecord] = []

    def _handle(pkt: Any) -> None:
        rec = parse_packet(pkt)
        if rec is None:
            return
        records.append(rec)
        if on_packet is not None:
            on_packet(rec)

    sniff_kwargs: dict[str, Any] = {"prn": _handle, "store": False}
    if pcap:
        sniff_kwargs["offline"] = pcap
    else:
        sniff_kwargs["iface"] = interface
        if duration:
            sniff_kwargs["timeout"] = duration

    sniff(**sniff_kwargs)
    return records


def outbound_only(records: Iterator[PacketRecord] | list[PacketRecord]) -> list[PacketRecord]:
    """Keep packets sourced from the internal LAN (outbound / east-west)."""
    return [r for r in records if is_internal(r.get("src_ip"))]
