"""Structured alert records written to the console and a JSONL log file."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _from_ts(ts: float | None) -> str:
    if ts is None:
        return _utc_now()
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Alert:
    alert_type: str
    src_ip: str | None
    dst_ip: str | None
    details: str
    src_port: int | None = None
    dst_port: int | None = None
    timestamp: str = field(default_factory=_utc_now)
    extra: dict = field(default_factory=dict)

    @classmethod
    def from_event(
        cls,
        alert_type: str,
        *,
        src_ip: str | None,
        dst_ip: str | None,
        details: str,
        src_port: int | None = None,
        dst_port: int | None = None,
        ts: float | None = None,
        extra: dict | None = None,
    ) -> Alert:
        return cls(
            alert_type=alert_type,
            src_ip=src_ip,
            dst_ip=dst_ip,
            details=details,
            src_port=src_port,
            dst_port=dst_port,
            timestamp=_from_ts(ts),
            extra=extra or {},
        )

    def to_dict(self) -> dict:
        payload = asdict(self)
        extra = payload.pop("extra") or {}
        payload.update(extra)
        return payload

    def format_console(self) -> str:
        sport = f":{self.src_port}" if self.src_port is not None else ""
        dport = f":{self.dst_port}" if self.dst_port is not None else ""
        return (
            f"[{self.timestamp}] {self.alert_type:<22} "
            f"src={self.src_ip or '-'}{sport}  "
            f"dst={self.dst_ip or '-'}{dport}  "
            f"{self.details}"
        )


class AlertLogger:
    """Fan-out alerts to stdout and a JSONL log.

    By default the log is truncated so it holds only this run's alerts (what
    report.py expects); pass append=True to keep earlier runs' alerts.
    """

    def __init__(self, log_path: str | Path | None = None, append: bool = False) -> None:
        self.log_path = Path(log_path) if log_path else None
        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            if not append:
                self.log_path.write_text("", encoding="utf-8")

    def emit(self, alert: Alert) -> None:
        line = alert.format_console()
        print(line)
        if self.log_path:
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(alert.to_dict(), ensure_ascii=True) + "\n")

    def emit_info(self, message: str) -> None:
        print(message, file=sys.stderr)
