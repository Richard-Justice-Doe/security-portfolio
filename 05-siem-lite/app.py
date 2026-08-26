"""Flask dashboard for SIEM-lite alerts and event volume."""

from __future__ import annotations

from pathlib import Path

from flask import Flask, render_template, request

from siem.db import connect, fetch_alerts, fetch_events, volume_by_hour

ROOT = Path(__file__).resolve().parent
DB = ROOT / "data" / "siem.db"

app = Flask(__name__)


def _db():
    if not DB.exists():
        raise RuntimeError("No database yet. Run: python ingest.py --reset")
    return connect(DB)


@app.route("/")
def dashboard():
    source = request.args.get("source") or None
    severity = request.args.get("severity") or None
    conn = _db()
    try:
        alerts = fetch_alerts(conn, limit=50)
        events = fetch_events(conn, source=source, severity=severity, limit=200)
        volume = volume_by_hour(conn)
    finally:
        conn.close()
    hours = sorted({row["hour"] for row in volume})
    sources = sorted({row["source"] for row in volume})
    series = {src: [0] * len(hours) for src in sources}
    index = {h: i for i, h in enumerate(hours)}
    for row in volume:
        series[row["source"]][index[row["hour"]]] = row["n"]
    return render_template(
        "dashboard.html",
        alerts=alerts,
        events=events,
        hours=hours,
        series=series,
        source_filter=source or "",
        severity_filter=severity or "",
    )


@app.route("/health")
def health():
    conn = _db()
    try:
        n_alerts = conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"]
        n_events = conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"]
    finally:
        conn.close()
    return {"ok": True, "events": n_events, "alerts": n_alerts}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5005, debug=False)
