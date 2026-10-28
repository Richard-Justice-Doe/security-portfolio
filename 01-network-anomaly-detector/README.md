# Network Traffic Anomaly Detector

Offline (and optional live) detector that learns a **baseline of normal LAN behaviour** and flags three classes of deviation: **port scans**, **unusual outbound destinations**, and **beaconing**. Built as a self-contained portfolio project — synthetic PCAPs only, no real user traffic.

## Problem it solves

A small office or homelab often has no SIEM. This tool answers: *after I have watched the network for a quiet period, what new destinations, scan-like bursts, or metronomic callbacks showed up?* It stores the quiet period in SQLite and compares a later capture against that snapshot.

## Layout

| Path | Role |
| --- | --- |
| `capture.py` | Sniff an interface or read a `.pcap` into SQLite |
| `baseline.py` | Aggregate typical ports, destinations, packet size, per-host rates |
| `detect.py` | Compare new traffic to the baseline; log alerts |
| `report.py` | Render a PDF incident report from the alert log |
| `generate_sample.py` | Rebuild the bundled synthetic PCAPs |
| `samples/` | `baseline.pcap` (normal) and `anomalous.pcap` (scan + C2 + beacon) |
| `ntd/` | Parsing, SQLite, heuristics, structured logging |

## Setup

Python 3.10+ (tested on 3.14). From this directory:

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS / Linux
pip install -r requirements.txt
```

**Live sniffing** (optional) needs administrator rights and [Npcap](https://npcap.com/) on Windows. You do **not** need Npcap to run the PCAP demo.

## How to run against the sample capture

```bash
python generate_sample.py
python capture.py --pcap samples/baseline.pcap --db data/traffic.db
python baseline.py --db data/traffic.db
python detect.py --pcap samples/anomalous.pcap --db data/traffic.db --log logs/alerts.jsonl
python report.py --log logs/alerts.jsonl --db data/traffic.db --out reports/report.pdf
```

Each `detect.py` run starts a fresh alert log; add `--append` to keep alerts from earlier runs.

Live capture on a network you own (not required for the demo):

```bash
python capture.py --interface Ethernet --duration 60 --db data/traffic.db
python baseline.py --db data/traffic.db
python detect.py --interface Ethernet --duration 60 --db data/traffic.db
```

## What the baseline records

For outbound packets sourced from RFC 1918 addresses:

- typical destination **ports** (and protocol)
- common destination **IP:port** pairs
- **average packet size** (and standard deviation)
- per-host **packet rate**, unique destinations, and connection count

## Detectors

| Alert | Heuristic |
| --- | --- |
| `PORT_SCAN` | TCP SYN to ≥15 distinct ports on one target within 5 seconds |
| `UNUSUAL_OUTBOUND` | External destination IP (or IP:port) absent from the baseline |
| `BEACONING` | ≥5 connections to the same service whose inter-arrival CV ≤ 0.15 |

## Example alert output

```
Loaded baseline: 198 packets, 4 dest IPs, 3 ports
Analysed 135 packets from PCAP

4 alert(s):

[2023-11-14T22:16:45Z] UNUSUAL_OUTBOUND       src=192.168.1.20:52000  dst=198.51.100.50:8080  destination IP never observed during baseline
[2023-11-14T22:16:49Z] PORT_SCAN              src=192.168.1.50  dst=10.0.0.80  35 distinct destination ports in 1.36s (threshold 15 ports / 5s)
[2023-11-14T22:16:52Z] UNUSUAL_OUTBOUND       src=192.168.1.10:51000  dst=203.0.113.77:4444  destination IP never observed during baseline
[2023-11-14T22:20:15Z] BEACONING              src=192.168.1.20  dst=198.51.100.50:8080  8 connections, mean interval 30.0s, coefficient of variation 0.000 (threshold CV <= 0.15)

JSONL log written to logs/alerts.jsonl
```

Each log line is one JSON object (`timestamp`, `alert_type`, `src_ip`, `dst_ip`, `details`, plus detector-specific fields).

## Sample data

`generate_sample.py` writes two PCAPs using RFC 5737 documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and a private lab net. The anomalous file injects:

1. A SYN sweep from `192.168.1.50` across ports 20–54 on `10.0.0.80`
2. Four sessions from `192.168.1.10` to `203.0.113.77:4444` (never in the baseline)
3. Eight callbacks from `192.168.1.20` to `198.51.100.50:8080` at a fixed 30-second interval

## Ethical use

- Only capture traffic on networks you **own** or have **written permission** to monitor.
- Do not point `--interface` at campus, café, or employer networks without authorisation.
- The bundled PCAPs are fully synthetic. They contain no personal data.

## Limitations (honest)

This is a teaching detector, not a product NIDS. It has no encrypted-payload inspection, no community threat intel, and a single static baseline (concept drift is out of scope). Thresholds live in `ntd/config.py` if you retrain on your own lab capture.

## Contributors

- [Richard Justice Doe](https://github.com/Richard-Justice-Doe) — author
