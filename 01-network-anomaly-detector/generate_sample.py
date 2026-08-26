#!/usr/bin/env python3
"""Generate synthetic PCAPs for the portable demo.

Addresses are from RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) plus RFC 1918 lab networks. Nothing here is real user traffic.

Outputs:
  samples/baseline.pcap    — "normal" office-like DNS/HTTPS/HTTP
  samples/anomalous.pcap   — same mix plus a port scan, a new C2 destination,
                             and a fixed-interval beacon
"""

from __future__ import annotations

import random
from pathlib import Path

import logging

logging.getLogger("scapy").setLevel(logging.ERROR)

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Raw, wrpcap  # type: ignore[import-untyped]

SAMPLES = Path(__file__).resolve().parent / "samples"
BASE_TIME = 1_700_000_000.0  # fixed epoch so runs are reproducible

LAN_A = "192.168.1.10"
LAN_B = "192.168.1.20"
LAN_C = "192.168.1.30"
SCANNER = "192.168.1.50"

DNS_SERVER = "8.8.8.8"
CDN = "192.0.2.10"
MAIL = "192.0.2.20"
INTRANET = "10.0.0.5"

C2_HOST = "198.51.100.50"  # TEST-NET-2 — beacon target
SCAN_TARGET = "10.0.0.80"
MYSTERY = "203.0.113.77"  # TEST-NET-3 — unusual outbound


def _tcp(src: str, dst: str, sport: int, dport: int, ts: float, flags: str = "PA", size: int = 120):
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    pad = size - len(pkt)
    if pad > 0:
        pkt = pkt / Raw(b"N" * pad)
    pkt.time = ts
    return pkt


def _udp_dns(src: str, ts: float, qname: str = "example.test"):
    pkt = (
        IP(src=src, dst=DNS_SERVER)
        / UDP(sport=random.randint(40000, 50000), dport=53)
        / DNS(rd=1, qd=DNSQR(qname=qname))
    )
    pkt.time = ts
    return pkt


def build_normal(rng: random.Random, start: float, duration: float) -> list:
    """Office-like mix: DNS, HTTPS to two sites, occasional intranet HTTP."""
    packets = []
    t = start
    end = start + duration
    hosts = (LAN_A, LAN_B, LAN_C)
    https_targets = ((CDN, 443), (MAIL, 443))

    while t < end:
        host = rng.choice(hosts)
        roll = rng.random()
        if roll < 0.20:
            packets.append(_udp_dns(host, t, rng.choice(["example.test", "cdn.test", "mail.test"])))
        elif roll < 0.85:
            dest, port = rng.choice(https_targets)
            packets.append(
                _tcp(
                    host,
                    dest,
                    rng.randint(40000, 60000),
                    port,
                    t,
                    flags="PA",
                    size=rng.randint(80, 900),
                )
            )
        else:
            packets.append(
                _tcp(host, INTRANET, rng.randint(40000, 60000), 80, t, flags="PA", size=rng.randint(70, 400))
            )
        t += rng.uniform(0.15, 0.7)
    return packets


def build_anomalies(rng: random.Random, start: float) -> list:
    packets = []

    # 1) SYN port scan: one internal host, many ports, ~2 seconds.
    scan_t = start + 8.0
    for i, port in enumerate(range(20, 55)):
        packets.append(_tcp(SCANNER, SCAN_TARGET, 50000 + i, port, scan_t + i * 0.04, flags="S", size=40))

    # 2) Unusual outbound: workstation talks to a never-before-seen IP:4444.
    mystery_t = start + 12.0
    for i in range(4):
        packets.append(
            _tcp(LAN_A, MYSTERY, 51000 + i, 4444, mystery_t + i * 0.4, flags="PA", size=200)
        )

    # 3) Beaconing: exact 30s interval to a TEST-NET-2 C2-like service.
    beacon_t = start + 5.0
    for i in range(8):
        packets.append(_tcp(LAN_B, C2_HOST, 52000, 8080, beacon_t + i * 30.0, flags="PA", size=96))

    return packets


def main() -> None:
    rng = random.Random(42)
    SAMPLES.mkdir(exist_ok=True)

    baseline = build_normal(rng, BASE_TIME, duration=90.0)
    # Anomalous file mixes a shorter normal slice with the three attack patterns
    # so the detector sees both "known-good" and "new" destinations.
    anomalous = build_normal(rng, BASE_TIME + 200.0, duration=40.0) + build_anomalies(rng, BASE_TIME + 200.0)
    anomalous.sort(key=lambda p: p.time)

    wrpcap(str(SAMPLES / "baseline.pcap"), baseline)
    wrpcap(str(SAMPLES / "anomalous.pcap"), anomalous)
    print(f"Wrote {len(baseline)} packets -> {SAMPLES / 'baseline.pcap'}")
    print(f"Wrote {len(anomalous)} packets -> {SAMPLES / 'anomalous.pcap'}")


if __name__ == "__main__":
    main()
