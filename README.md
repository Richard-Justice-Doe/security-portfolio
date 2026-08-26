# Security Portfolio

Five self-contained security labs in one repo. Each folder has its own `requirements.txt` and README. **All sample data is synthetic.** Do not point any of these tools at a network, inbox, or host you do not own.

| # | Project | What it shows |
| --- | --- | --- |
| 1 | [Network Traffic Anomaly Detector](01-network-anomaly-detector/) | Baseline LAN behaviour, then port-scan / unusual-outbound / beaconing alerts from a PCAP |
| 2 | [Phishing / Email Header Analyzer](02-phishing-header-analyzer/) | Flask UI that scores SPF/DKIM/DMARC, Reply-To mismatch, display-name spoofing, Received-chain jumps |
| 3 | [Vulnerable Web App + Patch Walkthrough](03-vuln-webapp-walkthrough/) | Intentionally weak campus portal vs a patched copy (SQL + session fixes). Lab only |
| 4 | [Mobile Money Fraud Detection Simulator](04-momo-fraud-detection-sim/) | Synthetic Ghana MoMo/GhIPSS-style traffic: velocity, geo-impossible, amount-spike rules + Isolation Forest |
| 5 | [SIEM-lite](05-siem-lite/) | Ingest auth/firewall/web logs, normalise to SQLite, rule alerts, Chart.js dashboard |

## Quick start (per project)

```bash
cd 01-network-anomaly-detector   # then 02, 03, 04, 05
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Follow that folder's README for the exact demo commands.

## Ethical use

These projects are **portfolio / teaching labs**. They use documentation-range IPs, fake wallets, and made-up email. Project 3 is labelled **VULNERABLE BY DESIGN — LAB USE ONLY, DO NOT DEPLOY PUBLICLY** and ships a patched twin; it is not a target for public scanning.
