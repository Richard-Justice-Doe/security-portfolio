"""Detection thresholds and network-scope defaults.

Tune these if you retrain the baseline on a quieter or noisier network.
They are intentionally conservative so the bundled sample PCAP produces
clear, reviewable alerts rather than a flood of low-confidence noise.
"""

from dataclasses import dataclass

# RFC 1918 ranges treated as "inside the monitored LAN".
INTERNAL_NETWORKS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")


@dataclass(frozen=True)
class Thresholds:
    """Parameters for the three detection heuristics."""

    # Port scan: many distinct destination ports, one source -> one dest, short window.
    port_scan_min_ports: int = 15
    port_scan_window_sec: float = 5.0

    # Beaconing: near-periodic connections to the same service.
    beacon_min_events: int = 5
    beacon_max_cv: float = 0.15  # coefficient of variation of inter-arrival times
    beacon_min_interval: float = 5.0
    beacon_max_interval: float = 600.0

    # Unusual outbound: destination IP (or IP:port) absent from the baseline.
    min_baseline_dest_count: int = 1
