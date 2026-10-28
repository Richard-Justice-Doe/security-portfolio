#!/usr/bin/env python3
"""Render a PDF incident report from a detector run.

Reads the JSONL alert log written by detect.py and the baseline stored in
SQLite, then lays out a one-or-more page PDF: a summary, the baseline the run
was compared against, and one detail block per alert.

Example:
    python detect.py --pcap samples/anomalous.pcap --db data/traffic.db --log logs/alerts.jsonl
    python report.py --log logs/alerts.jsonl --db data/traffic.db --out reports/report.pdf

The report is written to a local file. It is never transmitted anywhere; mail
or share it yourself, and only for networks you own or are authorised to assess.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from ntd.database import connect, load_baseline

try:
    from fpdf import FPDF
except ModuleNotFoundError:  # pragma: no cover - dependency hint
    print(
        "report.py needs fpdf2. Install it with:\n    pip install -r requirements.txt",
        file=sys.stderr,
    )
    raise SystemExit(1)


# Alert types the detector can raise, with a human-readable heading.
ALERT_TITLES = {
    "PORT_SCAN": "Port scan",
    "UNUSUAL_OUTBOUND": "Unusual outbound destination",
    "BEACONING": "Beaconing / periodic callback",
}

# Fields rendered verbatim in the per-alert detail block, in order.
DETAIL_FIELDS = [
    ("timestamp", "Time"),
    ("src_ip", "Source IP"),
    ("src_port", "Source port"),
    ("dst_ip", "Destination IP"),
    ("dst_port", "Destination port"),
    ("details", "Finding"),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Render a PDF report from a detector run.")
    parser.add_argument("--log", default=str(HERE / "logs/alerts.jsonl"), help="JSONL alert log from detect.py")
    parser.add_argument("--db", default=str(HERE / "data/traffic.db"), help="SQLite DB holding the baseline")
    parser.add_argument("--out", default=str(HERE / "reports/report.pdf"), help="Output PDF path")
    parser.add_argument("--title", default="Network Anomaly Report", help="Report title")
    return parser.parse_args()


def load_alerts(path: Path) -> list[dict]:
    """Read every JSON object from a JSONL file, skipping blank lines."""
    if not path.exists():
        raise FileNotFoundError(f"alert log not found: {path} (run detect.py first)")
    alerts: list[dict] = []
    with path.open(encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                alerts.append(json.loads(raw))
            except json.JSONDecodeError as exc:
                print(f"Warning: skipping malformed line {lineno} in {path}: {exc}", file=sys.stderr)
    return alerts


def load_baseline_meta(db_path: str) -> dict:
    """Return baseline meta, or an empty dict if no baseline is stored yet."""
    conn = connect(db_path)
    try:
        return load_baseline(conn).get("meta", {})
    except RuntimeError:
        return {}
    finally:
        conn.close()


class ReportPDF(FPDF):
    """FPDF subclass with a consistent header and footer."""

    report_title = "Network Anomaly Report"

    def header(self) -> None:
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(120)
        self.cell(0, 8, self.report_title, align="L")
        self.cell(0, 8, "CONFIDENTIAL", align="R")
        self.ln(10)
        self.set_text_color(0)

    def footer(self) -> None:
        self.set_y(-15)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(150)
        self.cell(0, 10, f"Page {self.page_no()} / {{nb}}", align="C")
        self.set_text_color(0)


def _severity(alert_type: str) -> str:
    return {"PORT_SCAN": "High", "UNUSUAL_OUTBOUND": "Medium", "BEACONING": "High"}.get(
        alert_type, "Info"
    )


def _kv_row(pdf: ReportPDF, label: str, value: str, label_w: float = 46) -> None:
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(label_w, 7, f"{label}:", new_x="RIGHT", new_y="TOP")
    pdf.set_font("Helvetica", "", 10)
    # Wrap the value in the remaining width and advance to the next line.
    value_w = pdf.w - pdf.r_margin - pdf.get_x()
    pdf.multi_cell(value_w, 7, value, new_x="LMARGIN", new_y="NEXT")


def build_pdf(alerts: list[dict], meta: dict, out_path: Path, title: str) -> None:
    ReportPDF.report_title = title
    pdf = ReportPDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.alias_nb_pages()
    pdf.add_page()

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # --- Title block ---
    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(0, 12, title, new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(90)
    pdf.cell(0, 6, f"Generated {generated}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0)
    pdf.ln(4)

    # --- Summary ---
    counts = Counter(a.get("alert_type", "UNKNOWN") for a in alerts)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 9, "Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(210)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.ln(3)

    if alerts:
        _kv_row(pdf, "Total alerts", str(len(alerts)))
        for atype, n in counts.most_common():
            name = ALERT_TITLES.get(atype, atype)
            _kv_row(pdf, name, f"{n}  (severity: {_severity(atype)})", label_w=66)
    else:
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 7, "No alerts were raised. Traffic was consistent with the baseline.")
    pdf.ln(4)

    # --- Baseline the run was compared against ---
    if meta:
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 9, "Baseline compared against", new_x="LMARGIN", new_y="NEXT")
        pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
        pdf.ln(3)
        _kv_row(pdf, "Baseline packets", str(meta.get("packet_count", "-")))
        _kv_row(pdf, "Sample duration", f"{meta.get('duration_sec', '-')} s")
        _kv_row(
            pdf,
            "Avg packet size",
            f"{meta.get('avg_packet_size', '-')} bytes (std {meta.get('std_packet_size', '-')})",
        )
        _kv_row(pdf, "Unique dest IPs", str(meta.get("unique_dest_ips", "-")))
        _kv_row(pdf, "Unique ports", str(meta.get("unique_ports", "-")))
        _kv_row(pdf, "Internal hosts", str(meta.get("host_count", "-")))
        pdf.ln(4)

    # --- Alert detail ---
    if alerts:
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 9, "Findings", new_x="LMARGIN", new_y="NEXT")
        pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
        pdf.ln(4)

        for i, alert in enumerate(alerts, 1):
            atype = alert.get("alert_type", "UNKNOWN")
            heading = ALERT_TITLES.get(atype, atype)
            # Keep a finding block from splitting awkwardly across a page break.
            if pdf.get_y() > pdf.h - 60:
                pdf.add_page()
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_fill_color(242, 244, 248)
            pdf.cell(
                0,
                8,
                f"{i}. {heading}  [{atype}]  -  severity {_severity(atype)}",
                new_x="LMARGIN",
                new_y="NEXT",
                fill=True,
            )
            pdf.ln(1)
            for key, label in DETAIL_FIELDS:
                if alert.get(key) in (None, ""):
                    continue
                _kv_row(pdf, label, str(alert[key]))
            pdf.ln(3)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(out_path))


def main() -> int:
    args = parse_args()
    try:
        alerts = load_alerts(Path(args.log))
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    meta = load_baseline_meta(args.db)
    out_path = Path(args.out)
    build_pdf(alerts, meta, out_path, args.title)

    print(f"PDF report written to {out_path}  ({len(alerts)} alert(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
