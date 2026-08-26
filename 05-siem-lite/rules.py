"""Rule engine over the normalised event table."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from siem.db import fetch_events

BRUTE_WINDOW = timedelta(minutes=5)
BRUTE_THRESHOLD = 5
ERROR_WINDOW = timedelta(minutes=2)
ERROR_THRESHOLD = 10


def _ts(row: dict[str, Any]) -> datetime:
    return datetime.strptime(row["ts"], "%Y-%m-%d %H:%M:%S")


def rule_brute_force(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Repeated SSH failures from one IP in a short window."""
    fails = [e for e in events if e["event_type"] == "ssh_failed_login" and e.get("src_ip")]
    fails.sort(key=_ts)
    by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in fails:
        by_ip[event["src_ip"]].append(event)

    alerts = []
    for ip, rows in by_ip.items():
        left = 0
        best = 0
        best_event = rows[-1]
        for right, event in enumerate(rows):
            while _ts(rows[right]) - _ts(rows[left]) > BRUTE_WINDOW:
                left += 1
            count = right - left + 1
            if count > best:
                best = count
                best_event = event
        if best >= BRUTE_THRESHOLD:
            alerts.append(
                {
                    "ts": best_event["ts"],
                    "rule": "brute_force",
                    "severity": "high",
                    "src_ip": ip,
                    "details": (
                        f"{best} failed SSH logins from {ip} "
                        f"within {BRUTE_WINDOW.seconds // 60} minutes"
                    ),
                }
            )
    return alerts


def rule_blocked_or_unusual(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Firewall-blocked IPs that also show up on auth or web (and TEST-NET watchlist)."""
    blocked = {e["src_ip"] for e in events if e["event_type"] == "ufw_block" and e.get("src_ip")}
    watchlist_prefixes = ("203.0.113.", "198.51.100.")  # RFC 5737 documentation ranges
    alerts = []
    seen: set[tuple[str, str]] = set()
    for event in sorted(events, key=_ts):
        ip = event.get("src_ip")
        if not ip or event["source"] == "firewall":
            continue
        unusual = ip.startswith(watchlist_prefixes)
        recycled = ip in blocked
        if not (unusual or recycled):
            continue
        key = (ip, "blocked_ip" if recycled else "unusual_ip")
        if key in seen:
            continue
        seen.add(key)
        rule = "blocked_ip_reuse" if recycled else "unusual_ip"
        why = (
            f"{ip} was previously dropped by the host firewall and later appeared in {event['source']} logs"
            if recycled
            else f"{ip} is on the lab watchlist (documentation-range / 'scanner' address) and hit {event['source']}"
        )
        alerts.append(
            {
                "ts": event["ts"],
                "rule": rule,
                "severity": "high" if recycled else "medium",
                "src_ip": ip,
                "details": why,
            }
        )
    return alerts


def rule_error_spike(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Burst of HTTP 5xx in a short window."""
    errors = [e for e in events if e["event_type"] == "http_5xx"]
    errors.sort(key=_ts)
    alerts = []
    left = 0
    best = 0
    best_event = errors[-1] if errors else None
    for right, event in enumerate(errors):
        while _ts(errors[right]) - _ts(errors[left]) > ERROR_WINDOW:
            left += 1
        count = right - left + 1
        if count > best:
            best = count
            best_event = event
    if best >= ERROR_THRESHOLD and best_event:
        alerts.append(
            {
                "ts": best_event["ts"],
                "rule": "http_error_spike",
                "severity": "high",
                "src_ip": best_event.get("src_ip"),
                "details": (
                    f"{best} HTTP 5xx responses in "
                    f"{ERROR_WINDOW.seconds // 60} minutes"
                ),
            }
        )
    return alerts


def run_rules(conn) -> list[dict[str, Any]]:
    events = fetch_events(conn, limit=5000)
    alerts = [
        *rule_brute_force(events),
        *rule_blocked_or_unusual(events),
        *rule_error_spike(events),
    ]
    alerts.sort(key=lambda a: a["ts"])
    return alerts
