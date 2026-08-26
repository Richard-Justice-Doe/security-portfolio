"""Parse three sample log dialects into a common event schema."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any

YEAR = 2026  # sample logs are from the portfolio demo day

AUTH_FAIL = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]: "
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
)
AUTH_OK = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]: "
    r"Accepted password for (?P<user>\S+) from (?P<ip>\S+)"
)
AUTH_SUDO = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sudo:.*"
)

UFW = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2}).*\[UFW (?P<action>BLOCK|ALLOW)\].*SRC=(?P<ip>\S+)"
)

NGINX = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) [^"]+" (?P<status>\d{3})'
)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _syslog_ts(mon: str, day: str, time: str) -> str:
    dt = datetime(YEAR, MONTHS[mon], int(day), *[int(x) for x in time.split(":")])
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def parse_auth(path: Path) -> list[dict[str, Any]]:
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if m := AUTH_FAIL.match(line):
            events.append(
                {
                    "ts": _syslog_ts(m["mon"], m["day"], m["time"]),
                    "source": "auth",
                    "event_type": "ssh_failed_login",
                    "severity": "warning",
                    "src_ip": m["ip"],
                    "raw_message": line,
                }
            )
        elif m := AUTH_OK.match(line):
            events.append(
                {
                    "ts": _syslog_ts(m["mon"], m["day"], m["time"]),
                    "source": "auth",
                    "event_type": "ssh_accepted",
                    "severity": "info",
                    "src_ip": m["ip"],
                    "raw_message": line,
                }
            )
        elif AUTH_SUDO.match(line):
            m2 = re.match(r"^(\w{3})\s+(\d+)\s+(\d{2}:\d{2}:\d{2})", line)
            events.append(
                {
                    "ts": _syslog_ts(m2.group(1), m2.group(2), m2.group(3)) if m2 else f"{YEAR}-08-26 00:00:00",
                    "source": "auth",
                    "event_type": "sudo",
                    "severity": "info",
                    "src_ip": None,
                    "raw_message": line,
                }
            )
    return events


def parse_firewall(path: Path) -> list[dict[str, Any]]:
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = UFW.match(line)
        if not m:
            continue
        action = m["action"].lower()
        events.append(
            {
                "ts": _syslog_ts(m["mon"], m["day"], m["time"]),
                "source": "firewall",
                "event_type": f"ufw_{action}",
                "severity": "warning" if action == "block" else "info",
                "src_ip": m["ip"],
                "raw_message": line,
            }
        )
    return events


def parse_web(path: Path) -> list[dict[str, Any]]:
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = NGINX.match(line)
        if not m:
            continue
        status = int(m["status"])
        ts = datetime.strptime(m["ts"].split()[0], "%d/%b/%Y:%H:%M:%S")
        if status >= 500:
            sev, etype = "error", "http_5xx"
        elif status >= 400:
            sev, etype = "warning", "http_4xx"
        else:
            sev, etype = "info", "http_ok"
        events.append(
            {
                "ts": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "source": "web",
                "event_type": etype,
                "severity": sev,
                "src_ip": m["ip"],
                "raw_message": line,
            }
        )
    return events


PARSERS = {
    "auth": parse_auth,
    "firewall": parse_firewall,
    "web": parse_web,
}


def parse_file(source: str, path: Path) -> list[dict[str, Any]]:
    if source not in PARSERS:
        raise ValueError(f"Unknown source {source}")
    return PARSERS[source](path)
